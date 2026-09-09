/**
 * @fileoverview Per-session cookie revocation (#143).
 *
 * Two levels. End-to-end through the middleware with a real in-memory KV store:
 * a session destroyed by logout, whose pre-logout cookie is REPLAYED, is refused
 * (SC-006) — the "logout does not revoke" hole closed. And driver-level with a
 * fake store: the revocation check must fail CLOSED — a store whose read throws
 * refuses the cookie (never authenticates it), and a revoke that throws
 * propagates from destroy() (SC-010).
 *
 * @module @lockness/session/tests/cookie_revocation
 */

import { assertEquals, assertRejects } from '@std/assert'
import { Hono } from 'hono'
import type { Context } from 'hono'
import { drainDisposables } from '@lockness/contract/lifecycle/internal'
import {
    configureSession,
    generateAppKey,
    getSession,
    sessionMiddleware,
} from '../mod.ts'
import { CookieSessionDriver } from '../drivers/cookie.ts'
import { seal } from '../drivers/cookie_seal.ts'
import type { RevocationStore } from '../drivers/revocation_store.ts'
import type { SessionConfig } from '../types.ts'
import { resetDriverRegistry } from '../drivers/registry.ts'

const KEY = generateAppKey()

function reset(): void {
    resetDriverRegistry()
    drainDisposables()
}

Deno.test('cookie revocation - a replayed pre-logout cookie is refused end-to-end (SC-006)', async () => {
    reset()
    configureSession({
        driver: 'cookie',
        secret: KEY,
        cookieName: 'rev_session',
        lifetime: 7200,
        absoluteLifetime: 3600, // required for revocation (bounds retention)
        revocation: true,
        kvPath: ':memory:', // an in-memory revocation store, per process
    })
    const app = new Hono()
    app.use('*', sessionMiddleware())
    app.get('/set', (c) => {
        getSession(c).set('user', 'alice')
        return c.text('set')
    })
    app.get('/read', (c) => c.text(getSession(c).get<string>('user') ?? 'NONE'))
    app.get('/logout', async (c) => {
        await getSession(c).destroy()
        return c.text('out')
    })

    try {
        // Issue a session; capture the cookie an attacker would steal.
        const r1 = await app.request('/set')
        const captured = r1.headers.get('set-cookie')!.split(';')[0]

        // It authenticates before logout.
        const before = await app.request('/read', {
            headers: { cookie: captured },
        })
        assertEquals(await before.text(), 'alice', 'valid before logout')

        // Log out — revokes the session's jti in the shared store.
        await app.request('/logout', { headers: { cookie: captured } })

        // Replay the CAPTURED pre-logout cookie: it is cryptographically valid and
        // within the cap, but its jti is revoked → refused → empty session.
        const after = await app.request('/read', {
            headers: { cookie: captured },
        })
        assertEquals(
            await after.text(),
            'NONE',
            'the captured cookie is refused after logout — revocation works',
        )
    } finally {
        reset()
    }
})

/** A real Hono context carrying an optional cookie header, for driver-level tests. */
async function contextWith(cookieHeader?: string): Promise<Context> {
    const app = new Hono()
    let captured!: Context
    app.all('*', (c) => {
        captured = c
        return c.body(null)
    })
    await app.request(
        '/',
        cookieHeader ? { headers: { cookie: cookieHeader } } : undefined,
    )
    return captured
}

const REV_CONFIG: SessionConfig = {
    driver: 'cookie',
    cookieName: 'rev_session',
    secret: KEY,
    lifetime: 7200,
    absoluteLifetime: 3600,
    revocation: true,
    path: '/',
    secure: false,
    httpOnly: true,
    sameSite: 'Lax',
}

Deno.test('cookie revocation - a store read error fails CLOSED (SC-010 read path)', async () => {
    const throwingStore: RevocationStore = {
        isRevoked: () => Promise.reject(new Error('kv down')),
        revoke: () => Promise.resolve(),
        revokeUser: () => Promise.resolve(),
        userRevokedSince: () => Promise.resolve(null),
        close: () => Promise.resolve(),
    }
    // A valid cookie carrying a known jti.
    const sealed = await seal(KEY, { user: 'bob' }, 3600, {
        iat: Math.floor(Date.now() / 1000),
        jti: 'a'.repeat(32),
    })
    const ctx = await contextWith(`rev_session=${encodeURIComponent(sealed)}`)
    const driver = new CookieSessionDriver(ctx, REV_CONFIG, throwingStore)

    assertEquals(
        await driver.read('x'),
        null,
        'a store outage refuses the cookie — never authenticates a possibly-revoked one',
    )
})

Deno.test('cookie revocation - a revoke error propagates from destroy (SC-010 write path)', async () => {
    const throwingStore: RevocationStore = {
        isRevoked: () => Promise.resolve(false),
        revoke: () => Promise.reject(new Error('kv down')),
        revokeUser: () => Promise.resolve(),
        userRevokedSince: () => Promise.resolve(null),
        close: () => Promise.resolve(),
    }
    const sealed = await seal(KEY, { user: 'bob' }, 3600, {
        iat: Math.floor(Date.now() / 1000),
        jti: 'b'.repeat(32),
    })
    const ctx = await contextWith(`rev_session=${encodeURIComponent(sealed)}`)
    const driver = new CookieSessionDriver(ctx, REV_CONFIG, throwingStore)

    // read() stashes the jti; destroy() then revokes it — the failing write must
    // propagate, not be swallowed (a silent logout failure is worse).
    await driver.read('x')
    await assertRejects(
        () => driver.destroy('x'),
        Error,
        'kv down',
    )
})

Deno.test('cookie revocation - a revoked jti stays revoked through a re-seal (SC-007)', async () => {
    const revoked = new Set<string>()
    const store: RevocationStore = {
        isRevoked: (jti) => Promise.resolve(revoked.has(jti)),
        revoke: (jti) => {
            revoked.add(jti)
            return Promise.resolve()
        },
        revokeUser: () => Promise.resolve(),
        userRevokedSince: () => Promise.resolve(null),
        close: () => Promise.resolve(),
    }
    const jti = 'c'.repeat(32)
    const iat = Math.floor(Date.now() / 1000)

    // A cookie, then a RE-SEAL of the same session (preserved identity) — both
    // carry the same jti, so revoking once refuses both.
    const first = await seal(KEY, { user: 'carol' }, 3600, { iat, jti })
    const resealed = await seal(KEY, { user: 'carol', extra: 1 }, 3600, {
        iat,
        jti,
    })

    // Revoke via the first cookie's driver.
    const ctx1 = await contextWith(`rev_session=${encodeURIComponent(first)}`)
    const d1 = new CookieSessionDriver(ctx1, REV_CONFIG, store)
    await d1.read('x')
    await d1.destroy('x')

    // The RE-SEALED cookie (same jti) is now refused too — revocation cannot be
    // shed by triggering a re-seal.
    const ctx2 = await contextWith(
        `rev_session=${encodeURIComponent(resealed)}`,
    )
    const d2 = new CookieSessionDriver(ctx2, REV_CONFIG, store)
    assertEquals(
        await d2.read('x'),
        null,
        'the re-sealed cookie shares the revoked jti and is refused',
    )
})

Deno.test('cookie revocation - regenerate() revokes the old jti then resets the identity', async () => {
    const revoked = new Set<string>()
    const store: RevocationStore = {
        isRevoked: (jti) => Promise.resolve(revoked.has(jti)),
        revoke: (jti) => {
            revoked.add(jti)
            return Promise.resolve()
        },
        revokeUser: () => Promise.resolve(),
        userRevokedSince: () => Promise.resolve(null),
        close: () => Promise.resolve(),
    }
    const oldJti = 'd'.repeat(32)
    const iat = Math.floor(Date.now() / 1000)
    const sealed = await seal(KEY, { user: 'dave' }, 3600, { iat, jti: oldJti })
    const ctx = await contextWith(`rev_session=${encodeURIComponent(sealed)}`)
    const driver = new CookieSessionDriver(ctx, REV_CONFIG, store)

    await driver.read('x') // stashes the old identity
    await driver.regenerate('x', 'y', 3600)
    assertEquals(revoked.has(oldJti), true, 'regenerate revoked the old jti')

    // The reset means the next write mints a FRESH identity, not the revoked one.
    await driver.write('y', { user: 'dave' }, 3600)
    const reissued =
        ctx.res.headers.get('set-cookie')!.split(';')[0].split('=')[1]
    const opened = await import('../drivers/cookie_seal.ts').then((m) =>
        m.openSealed(KEY, decodeURIComponent(reissued))
    )
    assertEquals(
        typeof opened !== 'string' && opened.jti !== oldJti,
        true,
        'the re-issued cookie carries a fresh, non-revoked jti',
    )
})

Deno.test('cookie revocation - destroy() suppresses the trailing re-seal (no logout re-issue)', async () => {
    const store: RevocationStore = {
        isRevoked: () => Promise.resolve(false),
        revoke: () => Promise.resolve(),
        revokeUser: () => Promise.resolve(),
        userRevokedSince: () => Promise.resolve(null),
        close: () => Promise.resolve(),
    }
    const sealed = await seal(KEY, { user: 'erin' }, 3600, {
        iat: Math.floor(Date.now() / 1000),
        jti: 'e'.repeat(32),
    })
    const ctx = await contextWith(`rev_session=${encodeURIComponent(sealed)}`)
    const driver = new CookieSessionDriver(ctx, REV_CONFIG, store)
    await driver.read('x')
    await driver.destroy('x') // deletes the cookie, marks destroyed

    // The middleware's trailing save() would call write() — it must be a no-op,
    // so the deletion stands and the revoked session is not re-issued.
    await driver.write('x', { user: 'erin' }, 3600)
    const setCookies = ctx.res.headers.getSetCookie()
    // Only the deletion (maxAge=0 / expires in the past) — never a fresh session.
    const reIssued = setCookies.find((c) =>
        !/(max-age=0|expires=thu, 01 jan 1970)/i.test(c)
    )
    assertEquals(
        reIssued,
        undefined,
        'no fresh session cookie was written after destroy',
    )
})
