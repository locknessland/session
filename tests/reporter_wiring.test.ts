/**
 * The driver → reporter seam (#236).
 *
 * `RejectionReporter` is unit-tested in `reporting.test.ts`, and `openSealed`'s
 * classification in `wire_format.test.ts` — but nothing asserted the glue on the
 * real request path: that a cookie `CookieSessionDriver.read()` refuses is
 * actually handed to the injected reporter. This is exactly the wiring the #236
 * refactor moved out of the (now pure) `openSealed` and into `read()`, and it
 * rides on the new injectable `reporter` constructor parameter. Deleting the
 * `this.#reporter.report(...)` call would otherwise leave the whole suite green.
 *
 * @module @lockness/session/tests/reporter_wiring
 */

import { assertEquals } from '@std/assert'
import { Hono } from 'hono'
import type { Context } from 'hono'
import { generateAppKey } from '../secret.ts'
import { CookieSessionDriver, RejectionReporter } from '../drivers/cookie.ts'
import { seal } from '../drivers/cookie_seal.ts'
import type { RevocationStore } from '../drivers/revocation_store.ts'
import type { SessionConfig } from '../types.ts'

const KEY = generateAppKey()

const CONFIG: SessionConfig = {
    driver: 'cookie',
    cookieName: 'wiring_session',
    secret: KEY,
    lifetime: 7200,
    path: '/',
    secure: false,
    httpOnly: true,
    sameSite: 'Lax',
}

const REV_CONFIG: SessionConfig = {
    ...CONFIG,
    absoluteLifetime: 3600,
    revocation: true,
}

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

/** Run `fn` with `console.warn` silenced (the reporter warns on first refusal). */
async function silencingWarn(fn: () => Promise<void>): Promise<void> {
    const warn = console.warn
    console.warn = () => {}
    try {
        await fn()
    } finally {
        console.warn = warn
    }
}

Deno.test('read() feeds a crypto-refused cookie to the injected reporter (#236 seam)', async () => {
    const reporter = new RejectionReporter()
    const ctx = await contextWith('wiring_session=not-a-lockness-cookie')
    const driver = new CookieSessionDriver(ctx, CONFIG, undefined, reporter)

    let result: unknown
    await silencingWarn(async () => {
        result = await driver.read('sid')
    })

    // The cookie is refused …
    assertEquals(result, null)
    // … and the refusal reached the reporter through the driver — the wiring
    // this test exists to pin. Removing `this.#reporter.report(opened)` from
    // read() makes this assertion fail.
    assertEquals(reporter.lastRejection(), 'bad-prefix')
})

Deno.test('read() feeds a revoked cookie to the injected reporter (#236 seam, revoked path)', async () => {
    const revokingStore: RevocationStore = {
        isRevoked: () => Promise.resolve(true),
        revoke: () => Promise.resolve(),
        revokeUser: () => Promise.resolve(),
        userRevokedSince: () => Promise.resolve(null),
        close: () => Promise.resolve(),
    }
    // A cryptographically valid cookie whose jti the store reports as revoked.
    const sealed = await seal(KEY, { user: 'bob' }, 3600, {
        iat: Math.floor(Date.now() / 1000),
        jti: 'a'.repeat(32),
    })
    const reporter = new RejectionReporter()
    const ctx = await contextWith(
        `wiring_session=${encodeURIComponent(sealed)}`,
    )
    const driver = new CookieSessionDriver(
        ctx,
        REV_CONFIG,
        revokingStore,
        reporter,
    )

    let result: unknown
    await silencingWarn(async () => {
        result = await driver.read('sid')
    })

    // A revoked cookie is refused and the 'revoked' class reached the reporter.
    assertEquals(result, null)
    assertEquals(reporter.lastRejection(), 'revoked')
})
