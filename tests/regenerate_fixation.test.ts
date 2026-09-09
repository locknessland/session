/**
 * Session-fixation protection after a login-regenerate, on every driver (US2).
 *
 * FR-008 / Security S2: because `SessionStore` rotates the id
 * **unconditionally** (`store.ts` assigns `newId` after the driver resolves),
 * "the id changed" alone stays true even if the driver's move did nothing. So on
 * the stateful drivers this asserts the stronger pair — the new id reads back
 * the carried data AND the old id no longer resolves server-side — which fails
 * if `destroy`/`DEL` is a no-op (SC-005).
 *
 * The driver set is enumerated by the `SessionConfig['driver']` **union type**,
 * not a hand-written array: the `Record` below fails to typecheck if a new
 * driver joins the union without a fixation runner (Architecture A-L3).
 */

import { assertEquals, assertNotEquals } from '@std/assert'
import type { Context } from 'hono'
import type { SessionConfig, SessionData, SessionDriver } from '../types.ts'
import { SessionStore } from '../store.ts'
import { generateAppKey } from '../secret.ts'
import {
    CookieSessionDriver,
    DenoKvSessionDriver,
    MemorySessionDriver,
    RedisSessionDriver,
} from '../drivers/mod.ts'
import { FakeKv } from './fake_kv.ts'
import { startFakeRedis } from './fake_redis.ts'

const OLD_ID = 'a'.repeat(64)
const DATA: SessionData = { userId: 7, role: 'admin' }

function makeConfig(driver: SessionConfig['driver']): SessionConfig {
    return {
        driver,
        cookieName: 'lockness_session',
        lifetime: 7200,
        secret: generateAppKey(),
        path: '/',
        secure: false,
        httpOnly: true,
        sameSite: 'Lax',
    }
}

/** A minimal Hono `Context` sufficient for the cookie driver's set/read path. */
function mockContext(): Context {
    const cookies: Record<string, string> = {}
    const headers: Record<string, string[]> = {}
    return {
        req: { header: () => undefined, raw: { headers: new Headers() } },
        header: (name: string, value: string, opts?: { append?: boolean }) => {
            if (opts?.append) (headers[name] ??= []).push(value)
            else headers[name] = [value]
        },
        get: (key: string) => (key === 'cookie' ? cookies : undefined),
        set: (key: string, value: unknown) => {
            if (key === 'cookie') Object.assign(cookies, value)
        },
        var: {},
    } as unknown as Context
}

/**
 * The invariant every stateful driver must satisfy after a login-regenerate:
 * the store rotated the id, the new id carries the data, the old id is gone.
 */
async function assertServerSideRotation(
    driver: SessionDriver,
    config: SessionConfig,
): Promise<void> {
    await driver.write(OLD_ID, DATA, config.lifetime)
    const store = new SessionStore(OLD_ID, driver, DATA, config)

    const oldId = store.getId()
    await store.regenerate()
    const newId = store.getId()

    assertNotEquals(oldId, newId, 'the id rotated')
    assertEquals(
        await driver.read(newId),
        DATA,
        'the new id reads back the data',
    )
    assertEquals(
        await driver.read(oldId),
        null,
        'the old id no longer resolves server-side',
    )
}

const runners: Record<SessionConfig['driver'], () => Promise<void>> = {
    cookie: async () => {
        // Stateless: the only guarantee is that regenerate does not throw and
        // the store rotates the id. There is no server-side record to probe.
        const config = makeConfig('cookie')
        const driver = new CookieSessionDriver(mockContext(), config)
        const store = new SessionStore(OLD_ID, driver, DATA, config)
        const oldId = store.getId()
        await store.regenerate()
        assertNotEquals(oldId, store.getId(), 'the id rotated')
    },
    memory: async () => {
        await assertServerSideRotation(
            new MemorySessionDriver(),
            makeConfig('memory'),
        )
    },
    'deno-kv': async () => {
        const fake = new FakeKv()
        const realOpenKv = Deno.openKv
        Object.defineProperty(Deno, 'openKv', {
            configurable: true,
            value: () => Promise.resolve(fake as unknown as Deno.Kv),
        })
        try {
            const driver = new DenoKvSessionDriver()
            await assertServerSideRotation(driver, makeConfig('deno-kv'))
            await driver.close()
        } finally {
            Object.defineProperty(Deno, 'openKv', {
                configurable: true,
                value: realOpenKv,
            })
        }
    },
    redis: async () => {
        const redis = await startFakeRedis()
        try {
            const driver = new RedisSessionDriver({
                hostname: '127.0.0.1',
                port: redis.port,
            })
            await assertServerSideRotation(driver, makeConfig('redis'))
            await driver.close()
        } finally {
            redis.stop()
        }
    },
}

for (const name of Object.keys(runners) as Array<SessionConfig['driver']>) {
    Deno.test(
        `fixation - ${name} rotates the id on login (FR-008)`,
        runners[name],
    )
}
