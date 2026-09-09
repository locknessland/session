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
import type { RevocationStore } from './revocation_store.ts'

// Re-export all drivers
export { CookieSessionDriver } from './cookie.ts'
export { MemorySessionDriver } from './memory.ts'
export { DenoKvSessionDriver } from './deno_kv.ts'
export { RedisSessionDriver } from './redis.ts'
export { KvRevocationStore, type RevocationStore } from './revocation_store.ts'

/**
 * Create a session driver based on configuration.
 *
 * Factory function that instantiates the appropriate driver based on the
 * session configuration. This follows the Dependency Inversion Principle
 * by centralizing driver instantiation logic.
 *
 * @param c - Hono context object
 * @param config - Session configuration
 * @param revocationStore - The process-shared revocation store, passed only to
 *   the cookie driver and only when revocation is enabled (the registry owns its
 *   lifecycle).
 * @returns Configured session driver instance
 * @throws {Error} If the driver name is unrecognised, or the redis driver is
 *   selected without redis configuration
 *
 * @example
 * ```typescript
 * const driver = createDriver(c, sessionConfig)
 * const data = await driver.read('session-id')
 * ```
 */
export function createDriver(
    c: Context,
    config: SessionConfig,
    revocationStore?: RevocationStore,
): SessionDriver {
    switch (config.driver) {
        case 'cookie':
            return new CookieSessionDriver(c, config, revocationStore)
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
            // Deliberately a throw, not a fallback. Returning the cookie driver
            // for an unrecognised name made "which drivers require a secret" a
            // second predicate — "not one of the other three" — over a decision
            // the switch already owns. A typo'd or env-supplied driver name is a
            // configuration error and says so.
            throw new Error(
                `Unknown session driver: ${
                    JSON.stringify(config.driver)
                }. Expected one of: cookie, memory, deno-kv, redis.`,
            )
    }
}
