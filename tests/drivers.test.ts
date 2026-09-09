// deno-lint-ignore-file no-explicit-any
/**
 * Tests for @lockness/session - Drivers
 */

import { assertEquals, assertExists, assertThrows } from '@std/assert'
import { FakeTime } from '@std/testing/time'
import type { Context } from 'hono'
import { generateAppKey } from '../secret.ts'
import { createDriver } from '../drivers/mod.ts'
import type { SessionConfig } from '../types.ts'

const BASE_CONFIG: SessionConfig = {
    driver: 'cookie',
    cookieName: 'lockness_session',
    lifetime: 7200,
    path: '/',
    secure: false,
    httpOnly: true,
    sameSite: 'Lax',
}
import {
    CookieSessionDriver,
    DenoKvSessionDriver,
    MemorySessionDriver,
    RedisSessionDriver,
} from '../mod.ts'

// =============================================================================
// Mock Context for Cookie Driver Tests
// =============================================================================

function createMockContext(): Context {
    const cookies: Record<string, string> = {}
    const headers: Record<string, string[]> = {}

    return {
        req: {
            header: (name: string) => headers[name]?.[0],
            raw: {
                headers: new Headers(),
            },
        },
        header: (
            name: string,
            value: string,
            options?: { append?: boolean },
        ) => {
            if (options?.append) {
                if (!headers[name]) headers[name] = []
                headers[name].push(value)
            } else {
                headers[name] = [value]
            }
        },
        get: (key: string) => {
            if (key === 'cookie') return cookies
            return undefined
        },
        set: (key: string, value: unknown) => {
            if (key === 'cookie') Object.assign(cookies, value)
        },
        var: {},
        // Mock cookie methods
        _cookies: cookies,
        _headers: headers,
    } as unknown as Context
}

// =============================================================================
// Cookie Session Driver Tests
// =============================================================================

Deno.test('CookieSessionDriver - write and read session', async () => {
    const ctx = createMockContext()
    const config = {
        driver: 'cookie' as const,
        cookieName: 'test_session',
        lifetime: 3600,
        secret: generateAppKey(),
        path: '/',
        secure: false,
        httpOnly: true,
        sameSite: 'Lax' as const,
    }

    const driver = new CookieSessionDriver(ctx, config)

    const sessionData = { userId: 123, username: 'test' }
    await driver.write('session-id-1', sessionData, 3600)

    // Simulate cookie being set by extracting from headers
    const setCookieHeader = (ctx as any)._headers['Set-Cookie']?.[0]
    if (setCookieHeader) {
        const cookieValue = setCookieHeader.split(';')[0].split('=')[1]
        // Simulate browser sending cookie back
        const headers = new Headers()
        headers.set('Cookie', `${config.cookieName}=${cookieValue}`)
        ;(ctx.req as any).raw.headers = headers
    }

    const retrieved = await driver.read('session-id-1')
    assertEquals(retrieved, sessionData)
})

Deno.test('CookieSessionDriver - destroy session', async () => {
    const ctx = createMockContext()
    const config = {
        driver: 'cookie' as const,
        cookieName: 'test_session',
        lifetime: 3600,
        secret: generateAppKey(),
        path: '/',
        secure: false,
        httpOnly: true,
        sameSite: 'Lax' as const,
    }

    const driver = new CookieSessionDriver(ctx, config)

    await driver.write('session-id-1', { userId: 123 }, 3600)
    await driver.destroy('session-id-1')

    const retrieved = await driver.read('session-id-1')
    assertEquals(retrieved, null)
})

// =============================================================================
// Memory Session Driver Tests
// =============================================================================

Deno.test('MemorySessionDriver - write and read session', async () => {
    const driver = new MemorySessionDriver()

    const sessionData = { userId: 456, username: 'alice' }
    await driver.write('mem-session-1', sessionData, 3600)

    const retrieved = await driver.read('mem-session-1')
    assertEquals(retrieved, sessionData)
})

Deno.test('MemorySessionDriver - session expiration', async () => {
    using time = new FakeTime()
    const driver = new MemorySessionDriver()

    await driver.write('expire-session', { userId: 789 }, 1) // 1 second
    time.tick(1100) // Advance 1.1 seconds

    const retrieved = await driver.read('expire-session')
    assertEquals(retrieved, null)
})

Deno.test('MemorySessionDriver - regenerate session', async () => {
    const driver = new MemorySessionDriver()

    const sessionData = { userId: 999 }
    await driver.write('old-session', sessionData, 3600)
    await driver.regenerate('old-session', 'new-session', 3600)

    const oldRetrieved = await driver.read('old-session')
    const newRetrieved = await driver.read('new-session')

    assertEquals(oldRetrieved, null)
    assertEquals(newRetrieved, sessionData)
})

Deno.test('MemorySessionDriver - garbage collection', async () => {
    using time = new FakeTime()
    const driver = new MemorySessionDriver()

    await driver.write('session-1', { userId: 1 }, 1) // 1 second
    await driver.write('session-2', { userId: 2 }, 3600) // 1 hour

    time.tick(1100) // Advance 1.1 seconds
    await driver.gc()

    const expired = await driver.read('session-1')
    const active = await driver.read('session-2')

    assertEquals(expired, null)
    assertExists(active)
})

// =============================================================================
// Deno KV Session Driver Tests
// =============================================================================

Deno.test('DenoKvSessionDriver - write and read session', async () => {
    const driver = new DenoKvSessionDriver()

    const sessionData = { userId: 111, role: 'admin' }
    await driver.write('kv-session-1', sessionData, 3600)

    const retrieved = await driver.read('kv-session-1')
    assertEquals(retrieved, sessionData)

    await driver.destroy('kv-session-1')
    await driver.close()
})

Deno.test('DenoKvSessionDriver - destroy session', async () => {
    const driver = new DenoKvSessionDriver()

    await driver.write('kv-session-2', { userId: 222 }, 3600)
    await driver.destroy('kv-session-2')

    const retrieved = await driver.read('kv-session-2')
    assertEquals(retrieved, null)

    await driver.close()
})

Deno.test('DenoKvSessionDriver - regenerate session', async () => {
    const driver = new DenoKvSessionDriver()

    const sessionData = { userId: 333 }
    await driver.write('kv-old', sessionData, 3600)
    await driver.regenerate('kv-old', 'kv-new', 3600)

    const oldRetrieved = await driver.read('kv-old')
    const newRetrieved = await driver.read('kv-new')

    assertEquals(oldRetrieved, null)
    assertEquals(newRetrieved, sessionData)

    await driver.destroy('kv-new')
    await driver.close()
})

// =============================================================================
// Redis Session Driver Tests (Mock)
// =============================================================================

Deno.test('RedisSessionDriver - can be instantiated', () => {
    const driver = new RedisSessionDriver({
        hostname: 'localhost',
        port: 6379,
    })

    assertExists(driver)
})

Deno.test('createDriver - an unrecognised driver name throws, naming it', () => {
    // It used to fall through to the cookie driver, which made "which drivers
    // need a secret" a second predicate over the same decision. The throw had no
    // test: `grep createDriver packages/session/tests/` found nothing.
    const context = createMockContext()

    const error = assertThrows(
        () =>
            createDriver(context, {
                ...BASE_CONFIG,
                // deno-lint-ignore no-explicit-any
                driver: 'postgres' as any,
            }),
        Error,
    )

    assertEquals(error.message.includes('postgres'), true)
    assertEquals(error.message.includes('cookie'), true)
})

Deno.test('createDriver - each known driver builds without a secret except cookie', () => {
    const context = createMockContext()

    assertEquals(
        typeof createDriver(context, { ...BASE_CONFIG, driver: 'memory' }).read,
        'function',
    )
    assertThrows(() =>
        createDriver(context, { ...BASE_CONFIG, driver: 'cookie' })
    )
})
