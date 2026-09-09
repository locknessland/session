/**
 * A full Redis login round-trip succeeds (US2, FR-009).
 *
 * The pre-#139 regenerate wrote the new key with `config.db` as the TTL, so a
 * default `db=0` issued `SETEX <key> 0`, which Redis rejects — the login 500'd
 * and the old id was never destroyed (fixation protection entirely off). This
 * drives write → regenerate → read against a stateful fake and asserts the
 * cycle completes: the new id carries the data, the old id is gone.
 */

import { assertEquals } from '@std/assert'
import type { SessionConfig, SessionData } from '../types.ts'
import { RedisSessionDriver } from '../drivers/redis.ts'
import { SessionStore } from '../store.ts'
import { generateAppKey } from '../secret.ts'
import { startFakeRedis } from './fake_redis.ts'

const OLD_ID = 'c'.repeat(64)
const DATA: SessionData = { userId: 123, name: 'Renée' }

Deno.test('redis login e2e - write → regenerate → read completes without a 500 (FR-009)', async () => {
    const redis = await startFakeRedis()
    try {
        const config: SessionConfig = {
            driver: 'redis',
            cookieName: 'lockness_session',
            lifetime: 7200,
            secret: generateAppKey(),
            path: '/',
            secure: false,
            httpOnly: true,
            sameSite: 'Lax',
        }
        const driver = new RedisSessionDriver({
            hostname: '127.0.0.1',
            port: redis.port,
        })

        // Pre-login: the anonymous session is written under the old id.
        await driver.write(OLD_ID, DATA, config.lifetime)

        // Login rotates the id through the store — the path that 500'd before.
        const store = new SessionStore(OLD_ID, driver, DATA, config)
        await store.regenerate()
        const newId = store.getId()

        assertEquals(
            await driver.read(newId),
            DATA,
            'the new id carries the data',
        )
        assertEquals(await driver.read(OLD_ID), null, 'the old id is gone')

        await driver.close()
    } finally {
        redis.stop()
    }
})
