/**
 * @fileoverview Per-user session eviction at the driver's `read()` (#147).
 *
 * The cookie driver refuses a session whose first-issuance `iat` is STRICTLY
 * before its subject's eviction epoch — one `revokeUser` write evicts every
 * prior session of that subject. Fail-closed: a store read that throws refuses.
 * A subject-less cookie (pre-`#147`) has no epoch and is untouched. Every
 * assertion is negative-tested: the pre-fix `read()` (no per-user branch) would
 * authenticate the evicted cookie.
 *
 * @module @lockness/session/tests/user_revocation
 */

import { assertEquals } from '@std/assert'
import { FakeTime } from '@std/testing/time'
import { Hono } from 'hono'
import type { Context } from 'hono'
import { generateAppKey } from '../mod.ts'
import { CookieSessionDriver } from '../drivers/cookie.ts'
import { seal } from '../drivers/cookie_seal.ts'
import type { RevocationStore } from '../drivers/revocation_store.ts'
import type { SessionConfig } from '../types.ts'

const KEY = generateAppKey()

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

/** An in-memory {@link RevocationStore} recording per-subject eviction epochs. */
function memoryStore(): RevocationStore & { epochs: Map<string, number> } {
    const epochs = new Map<string, number>()
    return {
        epochs,
        isRevoked: () => Promise.resolve(false),
        revoke: () => Promise.resolve(),
        revokeUser: (sub, _ttl) => {
            epochs.set(sub, Math.floor(Date.now() / 1000))
            return Promise.resolve()
        },
        userRevokedSince: (sub) => Promise.resolve(epochs.get(sub) ?? null),
        close: () => Promise.resolve(),
    }
}

/** A real Hono context carrying an optional cookie header. */
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

Deno.test('user revocation - a session issued before the subject epoch is refused (SC-001)', async () => {
    using time = new FakeTime(1_000_000_000_000)
    const store = memoryStore()

    // A session issued now, carrying sub='7'.
    const iat = Math.floor(Date.now() / 1000)
    const sealed = await seal(KEY, { user: 'ivan' }, 3600, {
        iat,
        jti: 'a'.repeat(32),
    }, '7')

    // The subject is evicted one second later.
    time.tick(1000)
    await store.revokeUser('7', 3600)

    const ctx = await contextWith(`rev_session=${encodeURIComponent(sealed)}`)
    const driver = new CookieSessionDriver(ctx, REV_CONFIG, store)
    assertEquals(
        await driver.read('x'),
        null,
        'iat strictly before the eviction epoch is refused',
    )
})

Deno.test('user revocation - iat == epoch survives (strict <, SC-003 boundary)', async () => {
    using _time = new FakeTime(1_000_000_000_000)
    const store = memoryStore()

    const iat = Math.floor(Date.now() / 1000)
    // Evict in the SAME second the session was issued.
    await store.revokeUser('7', 3600)
    const sealed = await seal(KEY, { user: 'ivan' }, 3600, {
        iat,
        jti: 'b'.repeat(32),
    }, '7')

    const ctx = await contextWith(`rev_session=${encodeURIComponent(sealed)}`)
    const driver = new CookieSessionDriver(ctx, REV_CONFIG, store)
    const data = await driver.read('x')
    assertEquals(
        data?.user,
        'ivan',
        'iat == epoch survives the strict-< epoch check',
    )
})

Deno.test('user revocation - a subject-less cookie is unaffected (SC-005)', async () => {
    using time = new FakeTime(1_000_000_000_000)
    const store = memoryStore()

    // A pre-`#147` cookie: no sub embedded.
    const iat = Math.floor(Date.now() / 1000)
    const sealed = await seal(KEY, { user: 'ivan' }, 3600, {
        iat,
        jti: 'c'.repeat(32),
    })

    // Evict subject '7' — irrelevant, this cookie carries no subject.
    time.tick(1000)
    await store.revokeUser('7', 3600)

    const ctx = await contextWith(`rev_session=${encodeURIComponent(sealed)}`)
    const driver = new CookieSessionDriver(ctx, REV_CONFIG, store)
    const data = await driver.read('x')
    assertEquals(
        data?.user,
        'ivan',
        'a subject-less cookie has no eviction epoch and authenticates',
    )
})

Deno.test('user revocation - a store read error fails CLOSED (SC-004)', async () => {
    const throwingStore: RevocationStore = {
        isRevoked: () => Promise.resolve(false),
        revoke: () => Promise.resolve(),
        revokeUser: () => Promise.resolve(),
        userRevokedSince: () => Promise.reject(new Error('kv down')),
        close: () => Promise.resolve(),
    }
    const sealed = await seal(KEY, { user: 'ivan' }, 3600, {
        iat: Math.floor(Date.now() / 1000),
        jti: 'd'.repeat(32),
    }, '7')

    const ctx = await contextWith(`rev_session=${encodeURIComponent(sealed)}`)
    const driver = new CookieSessionDriver(ctx, REV_CONFIG, throwingStore)
    assertEquals(
        await driver.read('x'),
        null,
        'a store outage on the per-user check refuses — never authenticates',
    )
})
