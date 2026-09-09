/**
 * The driver memo — one instance per process per resolved config, with cookie
 * and redis held per-request. See #138.
 *
 * These pin the four guarantees that were prose in the plan: memory persists a
 * login across requests (the P0 #142 named but never tested), memory/deno-kv are
 * identical across requests while cookie/redis are not (the redis assertion is
 * the gate that fails the instant redis slips into the memo), the deno-kv handle
 * acquisition is single-flighted against a concurrent burst, and a memoized
 * handle is released through the disposables drain.
 */

import {
    assertEquals,
    assertNotStrictEquals,
    assertStrictEquals,
} from '@std/assert'
import { crypto } from '@std/crypto'
import { credentialFingerprint } from '@lockness/redis'
import { Hono } from 'hono'
import type { Context } from 'hono'
import { drainDisposables } from '@lockness/contract/lifecycle/internal'
import {
    configureSession,
    generateAppKey,
    getSession,
    sessionMiddleware,
} from '../mod.ts'
import {
    driverKey,
    getOrCreateDriver,
    resetDriverRegistry,
} from '../drivers/registry.ts'
import { DenoKvSessionDriver } from '../drivers/deno_kv.ts'
import type { SessionConfig } from '../types.ts'

/** A resolved config for one backend, with a usable cookie secret. */
function config(over: Partial<SessionConfig>): SessionConfig {
    return {
        driver: 'memory',
        cookieName: 'lockness_session',
        lifetime: 7200,
        path: '/',
        secure: false,
        httpOnly: true,
        sameSite: 'Lax',
        secret: generateAppKey(),
        ...over,
    }
}

/** The registry is process-wide; every test starts from empty. */
function reset(): void {
    resetDriverRegistry()
    drainDisposables()
}

const fakeCtx = {} as Context

Deno.test('driver memo - a memory login persists across requests (FR-008, the real #142)', async () => {
    reset()
    configureSession({
        driver: 'memory',
        secret: generateAppKey(),
        cookieName: 'memo_session',
    })

    const app = new Hono()
    app.use('*', sessionMiddleware({ driver: 'memory' }))
    app.get('/set', (c) => {
        getSession(c).set('counter', 41)
        return c.text('set')
    })
    app.get('/get', (c) => {
        return c.text(String(getSession(c).get<number>('counter') ?? 'MISSING'))
    })

    const res1 = await app.request('/set')
    assertEquals(res1.status, 200)
    // The middleware wrote the id into a cookie; carry it to the next request.
    const cookie = res1.headers.get('set-cookie')?.split(';')[0]
    assertEquals(typeof cookie, 'string', 'the id was issued as a cookie')

    const res2 = await app.request('/get', { headers: { cookie: cookie! } })
    assertEquals(
        await res2.text(),
        '41',
        'the value written on request 1 was read on request 2 — the memory store persisted',
    )
    reset()
})

Deno.test('driver memo - memory, deno-kv and redis are identical across requests; cookie is not (FR-007)', () => {
    reset()

    // memory: same instance across two lookups.
    const mem = config({ driver: 'memory' })
    assertStrictEquals(
        getOrCreateDriver(fakeCtx, mem),
        getOrCreateDriver(fakeCtx, mem),
        'the memory store is shared across requests',
    )

    // deno-kv: same instance (no handle opened — construction is lazy).
    const kv = config({ driver: 'deno-kv', kvPath: ':memory:' })
    assertStrictEquals(
        getOrCreateDriver(fakeCtx, kv),
        getOrCreateDriver(fakeCtx, kv),
        'one deno-kv instance per process per config',
    )

    // cookie: a fresh instance per request — it closes over the Context.
    const cookie = config({ driver: 'cookie' })
    assertNotStrictEquals(
        getOrCreateDriver(fakeCtx, cookie),
        getOrCreateDriver(fakeCtx, cookie),
        'cookie is per-request',
    )

    // redis: the #145 INVERSE of #138's gate. Once its socket became safe to
    // share (drained reply reader #139 + per-connection command serialization
    // #145), redis joined the memo — so two requests get the SAME instance. This
    // assertion flipping from not-strict to strict IS the #145 landing. No live
    // server: construction is lazy.
    const redis = config({
        driver: 'redis',
        redis: { hostname: '127.0.0.1', port: 6379 },
    })
    assertStrictEquals(
        getOrCreateDriver(fakeCtx, redis),
        getOrCreateDriver(fakeCtx, redis),
        'redis is memoized per process per config (#145 inverse of the #138 gate)',
    )
    reset()
})

Deno.test('driver memo - driverKey keys memoized drivers and refuses only cookie', () => {
    reset()
    assertEquals(driverKey(config({ driver: 'memory' })), 'memory')
    assertEquals(
        driverKey(config({ driver: 'deno-kv', kvPath: './s.db' })),
        'deno-kv:./s.db',
    )

    // redis: keyed on host/port/db + a per-process-keyed HMAC of the password
    // (#248); the cleartext password never appears in the key. Pin the EXACT
    // fingerprint via the shared `credentialFingerprint`, not merely a 64-hex
    // shape — a length check passes for any hash, so it would not catch the
    // primitive being swapped out (review M3). Also assert it is NOT the bare
    // SHA-256: a keyed HMAC must not collapse to an offline-brute-forceable
    // unsalted digest.
    const redisKey = driverKey(config({
        driver: 'redis',
        redis: { hostname: 'h', port: 6379, db: 0, password: 's3cret' },
    }))
    const bareSha256 = Array.from(
        new Uint8Array(
            crypto.subtle.digestSync(
                'SHA-256',
                new TextEncoder().encode('s3cret'),
            ),
        ),
        (b) => b.toString(16).padStart(2, '0'),
    ).join('')
    assertEquals(
        redisKey,
        `redis:h:6379:0:${credentialFingerprint('s3cret')}`,
        'redis key is host:port:db then the keyed HMAC of the password',
    )
    assertEquals(
        redisKey.includes(bareSha256),
        false,
        'the key is not a bare SHA-256 of the password (not brute-forceable)',
    )
    assertEquals(
        redisKey.includes('s3cret'),
        false,
        'the cleartext password never enters the key',
    )

    // SC-003: same host, DIFFERENT password ⇒ different key ⇒ different socket.
    const keyA = driverKey(config({
        driver: 'redis',
        redis: { hostname: 'h', port: 6379, db: 0, password: 'alpha' },
    }))
    const keyB = driverKey(config({
        driver: 'redis',
        redis: { hostname: 'h', port: 6379, db: 0, password: 'bravo' },
    }))
    const keyA2 = driverKey(config({
        driver: 'redis',
        redis: { hostname: 'h', port: 6379, db: 0, password: 'alpha' },
    }))
    assertEquals(
        keyA === keyB,
        false,
        'different passwords never collapse to one authenticated socket',
    )
    assertEquals(
        keyA === keyA2,
        true,
        'identical configs resolve to the same key (stable)',
    )

    // cookie is the ONLY driver driverKey refuses to key.
    let threw = false
    try {
        driverKey(config({ driver: 'cookie' }))
    } catch {
        threw = true
    }
    assertEquals(threw, true, "driverKey('cookie') must throw — never memoized")
    reset()
})

Deno.test('driver memo - deno-kv acquisition is single-flighted under a concurrent burst (FR-012)', async () => {
    reset()
    // Deno.openKv is a getter-only property; defineProperty is the supported
    // way to stub a Deno API for a test. Count how many handles get opened.
    const realOpenKv = Deno.openKv
    let opens = 0
    const stub = (path?: string) => {
        opens++
        return realOpenKv(path)
    }
    Object.defineProperty(Deno, 'openKv', { configurable: true, value: stub })

    const driver = new DenoKvSessionDriver(':memory:')
    try {
        // Two concurrent first-reads: the check-then-act race would open twice.
        await Promise.all([
            driver.read('a'.repeat(64)),
            driver.read('b'.repeat(64)),
        ])
        assertEquals(
            opens,
            1,
            'a concurrent burst opened exactly one Deno.Kv handle',
        )
    } finally {
        Object.defineProperty(Deno, 'openKv', {
            configurable: true,
            value: realOpenKv,
        })
        await driver.close()
    }
    reset()
})

Deno.test('driver memo - a memoized deno-kv handle is released through the disposables drain (FR-006/US4)', async () => {
    reset()
    const driver = new DenoKvSessionDriver(':memory:')
    // Acquire the handle (registers the disposable) via a read.
    await driver.read('c'.repeat(64))

    let closed = 0
    const orig = driver.close.bind(driver)
    driver.close = () => {
        closed++
        return orig()
    }
    // Re-register so the spy is what the drain calls: acquire again is a no-op,
    // so instead drain what is registered and run each dispose.
    for (const d of drainDisposables()) await d.dispose()

    assertEquals(closed >= 1, true, 'the drain closed the driver')
    // Idempotent: draining again closes nothing (already drained + closed).
    for (const d of drainDisposables()) await d.dispose()
    await driver.close() // explicit double-close must not throw
    reset()
})

Deno.test('driver memo - a deno-kv session persists across requests through the middleware (SC-002)', async () => {
    reset()
    configureSession({
        driver: 'deno-kv',
        kvPath: ':memory:',
        secret: generateAppKey(),
        cookieName: 'kv_session',
    })
    const app = new Hono()
    app.use('*', sessionMiddleware({ driver: 'deno-kv', kvPath: ':memory:' }))
    app.get('/set', (c) => {
        getSession(c).set('v', 7)
        return c.text('set')
    })
    app.get('/get', (c) => {
        return c.text(String(getSession(c).get<number>('v') ?? 'MISSING'))
    })

    const r1 = await app.request('/set')
    const cookie = r1.headers.get('set-cookie')?.split(';')[0]
    const r2 = await app.request('/get', { headers: { cookie: cookie! } })
    assertEquals(
        await r2.text(),
        '7',
        'the deno-kv session survived the write→read cycle through one memoized handle',
    )
    reset() // closes the memoized kv handle
})

Deno.test('driver memo - the registry disposable clears the memo at shutdown (FR-010)', async () => {
    reset()
    const cfg = config({ driver: 'memory' })
    const a = getOrCreateDriver(fakeCtx, cfg)
    assertStrictEquals(
        getOrCreateDriver(fakeCtx, cfg),
        a,
        'memoized before shutdown',
    )

    // Draining runs the registry's own disposable → resetDriverRegistry → the
    // memo is cleared, so a later lookup builds a fresh instance.
    for (const d of drainDisposables()) await d.dispose()
    assertNotStrictEquals(
        getOrCreateDriver(fakeCtx, cfg),
        a,
        'the memo was cleared on the shutdown drain',
    )
    reset()
})

Deno.test('driver memo - resetDriverRegistry empties a memoized memory store (clear branch)', async () => {
    reset()
    const cfg = config({ driver: 'memory' })
    const mem = getOrCreateDriver(fakeCtx, cfg)
    await mem.write('f'.repeat(64), { x: 1 }, 3600)
    assertEquals((await mem.read('f'.repeat(64)))?.x, 1, 'written before reset')

    resetDriverRegistry() // exercises the clear() capability branch on memory
    assertEquals(
        await mem.read('f'.repeat(64)),
        null,
        'the memory store was emptied, not just dereferenced',
    )
    reset()
})

Deno.test('driver memo - a transient Deno.openKv failure self-heals on the next read (FR-012 resilience)', async () => {
    reset()
    const realOpenKv = Deno.openKv
    let calls = 0
    Object.defineProperty(Deno, 'openKv', {
        configurable: true,
        value: (path?: string) => {
            calls++
            if (calls === 1) return Promise.reject(new Error('transient'))
            return realOpenKv(path)
        },
    })

    const driver = new DenoKvSessionDriver(':memory:')
    try {
        let firstThrew = false
        try {
            await driver.read('a'.repeat(64))
        } catch {
            firstThrew = true
        }
        assertEquals(firstThrew, true, 'the first open rejected')

        // The cached promise self-healed: the second read retries openKv rather
        // than re-awaiting the cached rejection, and succeeds.
        assertEquals(
            await driver.read('a'.repeat(64)),
            null,
            'the retry opened a fresh handle and read (empty)',
        )
        assertEquals(calls, 2, 'openKv was retried, not permanently poisoned')
    } finally {
        Object.defineProperty(Deno, 'openKv', {
            configurable: true,
            value: realOpenKv,
        })
        await driver.close()
    }
    reset()
})
