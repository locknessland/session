/**
 * @fileoverview The cookie absolute-lifetime cap (#143).
 *
 * The cap must be measured from FIRST issuance (`iat`), preserved across
 * re-seals — not from the last write. A session refreshed on every request must
 * still age out. The decisive test re-seals across the boundary (drives real
 * requests that mutate the session, so each response re-seals the cookie) and
 * asserts it is refused once `now - iat` passes the cap: a version that re-minted
 * `iat` on every write (the inert mechanism the security audit caught) would keep
 * the session alive forever and fail this.
 *
 * @module @lockness/session/tests/cookie_absolute_lifetime
 */

import { assertEquals } from '@std/assert'
import { FakeTime } from '@std/testing/time'
import { Hono } from 'hono'
import { drainDisposables } from '@lockness/contract/lifecycle/internal'
import {
    configureSession,
    generateAppKey,
    getSession,
    sessionMiddleware,
} from '../mod.ts'
import { open, seal, sealArbitrary } from '../drivers/cookie_seal.ts'
import { resetDriverRegistry } from '../drivers/registry.ts'

const KEY = generateAppKey()

function reset(): void {
    resetDriverRegistry()
    drainDisposables()
}

/** An app whose one route mutates the session every request (forces a re-seal). */
function bumpApp(): Hono {
    const app = new Hono()
    app.use('*', sessionMiddleware())
    app.get('/bump', (c) => {
        const s = getSession(c)
        s.set('n', (s.get<number>('n') ?? 0) + 1)
        return c.text(String(s.get<number>('n')))
    })
    return app
}

Deno.test('cookie cap - a session re-sealed every request ages out at the cap, not at the last write (SC-001)', async () => {
    reset()
    const time = new FakeTime(1_000_000)
    try {
        configureSession({
            driver: 'cookie',
            secret: KEY,
            cookieName: 'cap_session',
            lifetime: 7200, // idle window comfortably longer than the cap
            absoluteLifetime: 100, // hard ceiling: 100s from first issuance
        })
        const app = bumpApp()

        // Request 1 — first issuance at t0. Carry the cookie forward.
        const r1 = await app.request('/bump')
        assertEquals(await r1.text(), '1')
        let cookie = r1.headers.get('set-cookie')!.split(';')[0]

        // Request 2 at t0+60 — WITHIN the cap. The session re-seals (n→2); the
        // preserved iat means it is still accepted.
        time.tick(60_000)
        const r2 = await app.request('/bump', { headers: { cookie } })
        assertEquals(
            await r2.text(),
            '2',
            'within the cap the re-sealed session persists',
        )
        cookie = r2.headers.get('set-cookie')!.split(';')[0]

        // Request 3 at t0+150 — PAST the 100s cap. Even though request 2 re-sealed
        // the cookie only 90s ago, the cap is measured from first issuance (t0),
        // so 150 > 100 → refused → a fresh empty session (n resets to 1). An
        // iat-re-minting build would report '3' here.
        time.tick(90_000)
        const r3 = await app.request('/bump', { headers: { cookie } })
        assertEquals(
            await r3.text(),
            '1',
            'past the absolute cap the session is refused despite recent re-seals',
        )
    } finally {
        time.restore()
        reset()
    }
})

Deno.test('cookie cap - within the cap a session is accepted (SC-002)', async () => {
    reset()
    const time = new FakeTime(2_000_000)
    try {
        configureSession({
            driver: 'cookie',
            secret: KEY,
            cookieName: 'cap_session2',
            lifetime: 7200,
            absoluteLifetime: 3600,
        })
        const app = bumpApp()
        const r1 = await app.request('/bump')
        const cookie = r1.headers.get('set-cookie')!.split(';')[0]
        time.tick(1000_000) // 1000s < 3600s cap
        const r2 = await app.request('/bump', { headers: { cookie } })
        assertEquals(await r2.text(), '2', 'accepted within the cap')
    } finally {
        time.restore()
        reset()
    }
})

Deno.test('cookie cap - absoluteLifetime 0 is enforced, not treated as off (off-sentinel)', async () => {
    // The gate is `typeof === 'number'`, not truthiness: 0 means "expire the
    // instant the issuance second passes", it does NOT disable the cap.
    const time = new FakeTime(3_000_000)
    try {
        const sealed = await seal(KEY, { a: 1 }, 7200) // iat = now
        assertEquals(
            await open(KEY, sealed, 0),
            { a: 1 },
            'at the issuance second, age 0 is not > 0 — accepted',
        )
        time.tick(1000) // 1s later
        assertEquals(
            await open(KEY, sealed, 0),
            null,
            'one second on, a cap of 0 refuses — 0 did not disable the cap',
        )
        // And with the cap UNSET (undefined), the same cookie is accepted forever.
        assertEquals(
            await open(KEY, sealed, undefined),
            { a: 1 },
            'undefined disables the cap (the only off-state)',
        )
    } finally {
        time.restore()
    }
})

Deno.test('cookie cap - a payload with no/non-numeric iat is refused when the cap is on (SC-003/FR-002)', async () => {
    const future = Math.floor(Date.now() / 1000) + 7200
    // GCM-valid cookies that a real seal() never produces: iat absent, and iat
    // as a string. Both must be refused under a positive cap — a future seal()
    // change cannot let a session skip the ceiling by omission.
    const noIat = await sealArbitrary(KEY, { d: { a: 1 }, exp: future })
    const stringIat = await sealArbitrary(KEY, {
        d: { a: 1 },
        exp: future,
        iat: 'nope',
    })
    assertEquals(
        await open(KEY, noIat, 100),
        null,
        'missing iat is refused under a cap',
    )
    assertEquals(
        await open(KEY, stringIat, 100),
        null,
        'non-numeric iat is refused under a cap',
    )
    // With the cap OFF, the same iat-less cookie opens (the gate is cap-scoped).
    assertEquals(
        await open(KEY, noIat, undefined),
        { a: 1 },
        'with no cap, iat is not required',
    )
})
