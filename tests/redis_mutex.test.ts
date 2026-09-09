/**
 * @fileoverview Per-connection command serialization on the shared Redis socket.
 *
 * These pin the Security-S5 invariant #145 exists for: once the redis driver is
 * memoized and its socket shared, two overlapping commands must NEVER interleave
 * their frames — the second's write begins only after the first's reply is fully
 * drained (`readReply`, #139). A missing or write-only mutex turns the drained
 * reply reader into a cross-user disclosure primitive (CWE-362): user B reads
 * user A's reply off a desynced socket. The overlap test (not back-to-back) is
 * the one that actually exercises the control — a sequential test passes with no
 * mutex at all (Security audit F4).
 *
 * @module @lockness/session/tests/redis_mutex
 */

import { assertEquals } from '@std/assert'
import { RedisSessionDriver } from '../drivers/redis.ts'
import { startFakeRedis } from './fake_redis.ts'

const id = (n: number): string => String(n).padStart(64, '0')

Deno.test('redis mutex - overlapping GETs each receive their OWN reply (SC-004, Security-S5)', async () => {
    const redis = await startFakeRedis()
    // Distinct keys, sizable distinct values — an interleave or a mis-drained
    // reply hands one caller another caller's bytes, which this asserts against.
    const N = 12
    for (let i = 0; i < N; i++) {
        redis.store.set(
            `session:${id(i)}`,
            JSON.stringify({ who: i, pad: 'x'.repeat(500) }),
        )
    }
    const driver = new RedisSessionDriver({
        hostname: '127.0.0.1',
        port: redis.port,
    })
    try {
        // Fire all reads WITHOUT awaiting between them — every sendCommand is in
        // flight before any completes. Serialization is the only thing that keeps
        // each reply matched to its caller on the one shared socket.
        const results = await Promise.all(
            Array.from({ length: N }, (_, i) => driver.read(id(i))),
        )
        for (let i = 0; i < N; i++) {
            assertEquals(
                (results[i] as { who: number }).who,
                i,
                `overlapping read ${i} got its own reply, not another caller's`,
            )
        }
    } finally {
        await driver.close()
        redis.stop()
    }
})

Deno.test('redis mutex - a write and a read in flight together do not corrupt each other', async () => {
    const redis = await startFakeRedis()
    const driver = new RedisSessionDriver({
        hostname: '127.0.0.1',
        port: redis.port,
    })
    const other = id(99)
    redis.store.set(`session:${other}`, JSON.stringify({ v: 'kept' }))
    try {
        // A large SETEX and a GET of a DIFFERENT key, both in flight at once.
        const [, read] = await Promise.all([
            driver.write(id(1), { big: 'y'.repeat(4096) }, 3600),
            driver.read(other),
        ])
        assertEquals(
            (read as { v: string }).v,
            'kept',
            'the concurrent GET returned its own value, not a fragment of the SETEX',
        )
        assertEquals(
            JSON.parse(redis.store.get(`session:${id(1)}`)!).big.length,
            4096,
            'the concurrent SETEX wrote its full value',
        )
    } finally {
        await driver.close()
        redis.stop()
    }
})

Deno.test('redis mutex - connect() AUTH/SELECT do not deadlock against the command queue (R2)', async () => {
    // A password + non-zero db means connect() issues AUTH then SELECT. Those go
    // through #exchange DIRECTLY, never sendCommand — if they instead re-entered
    // the command queue that awaits connect(), this read would hang forever.
    const redis = await startFakeRedis()
    redis.store.set(`session:${id(7)}`, JSON.stringify({ ok: true }))
    const driver = new RedisSessionDriver({
        hostname: '127.0.0.1',
        port: redis.port,
        password: 's3cret',
        db: 3,
    })
    try {
        const data = await driver.read(id(7))
        assertEquals(
            (data as { ok: boolean }).ok,
            true,
            'authenticated read completed — no re-entrancy deadlock',
        )
    } finally {
        await driver.close()
        redis.stop()
    }
})
