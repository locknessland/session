/**
 * @fileoverview Session driver exports and factory.
 *
 * @module @lockness/session/drivers
 */

import type { Context } from 'hono'
import type { SessionConfig, SessionDriver } from '../types.ts'
import { CookieSessionDriver } from './cookie.ts'
import { MemorySessionDriver } from './memory.ts'
import { DenoKvSessionDriver } from './deno_kv.ts'
import { RedisSessionDriver } from './redis.ts'

// Re-export all drivers
export { CookieSessionDriver } from './cookie.ts'
export { MemorySessionDriver } from './memory.ts'
export { DenoKvSessionDriver } from './deno_kv.ts'
export { RedisSessionDriver } from './redis.ts'

/**
 * Create a session driver based on configuration.
 *
 * Factory function that instantiates the appropriate driver based on the
 * session configuration. This follows the Dependency Inversion Principle
 * by centralizing driver instantiation logic.
 *
 * @param c - Hono context object
 * @param config - Session configuration
 * @returns Configured session driver instance
 * @throws {Error} If redis driver is selected without redis configuration
 *
 * @example
 * ```typescript
 * const driver = createDriver(c, sessionConfig)
 * const data = await driver.read('session-id')
 * ```
 */
export function createDriver(c: Context, config: SessionConfig): SessionDriver {
    switch (config.driver) {
        case 'cookie':
            return new CookieSessionDriver(c, config)
        case 'memory':
            return new MemorySessionDriver()
        case 'deno-kv':
            return new DenoKvSessionDriver(config.kvPath)
        case 'redis':
            if (!config.redis) {
                throw new Error('Redis configuration required for redis driver')
            }
            return new RedisSessionDriver(config.redis)
        default:
            return new CookieSessionDriver(c, config)
    }
}
