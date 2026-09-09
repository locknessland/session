/**
 * Regenerate is atomic — a mid-rotation fault leaves both-or-neither (US2).
 *
 * SC-007 / FR-011 / Security S3: the danger is a state where the new id resolves
 * to the authenticated data WHILE the attacker-known old id also still resolves.
 * These inject a fault at the rotation and assert that never happens — the store
 * is left with only the old id (nothing applied), never both.
 *
 * On Redis the fault is an `EVAL` error (the fake replies `-ERR`); on Deno KV it
 * is a forced `kv.atomic()` commit failure. Both must reject and leave the old
 * key intact and the new key absent.
 */

import { assertEquals, assertRejects } from '@std/assert'
import type { SessionData } from '../types.ts'
import { DenoKvSessionDriver, RedisSessionDriver } from '../drivers/mod.ts'
import { FakeKv } from './fake_kv.ts'
import { startFakeRedis } from './fake_redis.ts'

const OLD_ID = 'a'.repeat(64)
const NEW_ID = 'b'.repeat(64)
const DATA: SessionData = { userId: 7 }

Deno.test('atomicity - redis: an EVAL fault leaves the old id, never both (SC-007)', async () => {
    const redis = await startFakeRedis()
    try {
        const driver = new RedisSessionDriver({
            hostname: '127.0.0.1',
            port: redis.port,
        })
        await driver.write(OLD_ID, DATA, 3600)
        redis.setFailEval(true)

        await assertRejects(
            () => driver.regenerate(OLD_ID, NEW_ID, 7200),
            Error,
            'forced eval failure',
        )

        assertEquals(await driver.read(OLD_ID), DATA, 'old id still resolves')
        assertEquals(
            await driver.read(NEW_ID),
            null,
            'new id never resolved — not the both-resolve state',
        )
        await driver.close()
    } finally {
        redis.stop()
    }
})

Deno.test('atomicity - deno-kv: a forced commit failure leaves the old id, never both (SC-007)', async () => {
    const fake = new FakeKv()
    const realOpenKv = Deno.openKv
    Object.defineProperty(Deno, 'openKv', {
        configurable: true,
        value: () => Promise.resolve(fake as unknown as Deno.Kv),
    })
    try {
        const driver = new DenoKvSessionDriver()
        await driver.write(OLD_ID, DATA, 3600)
        fake.failNextCommit = true

        await assertRejects(
            () => driver.regenerate(OLD_ID, NEW_ID, 7200),
            Error,
            'atomic set+delete was rejected',
        )

        assertEquals(await driver.read(OLD_ID), DATA, 'old id still resolves')
        assertEquals(
            await driver.read(NEW_ID),
            null,
            'new id never resolved — not the both-resolve state',
        )
        await driver.close()
    } finally {
        Object.defineProperty(Deno, 'openKv', {
            configurable: true,
            value: realOpenKv,
        })
    }
})
