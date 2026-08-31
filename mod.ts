/**
 * @fileoverview Session Management System for Lockness.
 *
 * Multi-driver session handling with Cookie, Memory, DenoKV, and Redis support.
 * Provides encrypted sessions, flash data, and automatic garbage collection.
 *
 * @example
 * ```typescript
 * import { sessionMiddleware, getSession, configureSession } from '@lockness/session'
 *
 * // Configure globally
 * configureSession({
 *   driver: 'deno-kv',
 *   secret: Deno.env.get('SESSION_SECRET')!,
 *   lifetime: 3600,
 * })
 *
 * // Use middleware
 * app.useMiddleware(sessionMiddleware())
 *
 * // Access in controller
 * const session = getSession(c)
 * session.set('userId', 123)
 * const userId = session.get<number>('userId')
 * ```
 *
 * @module @lockness/session
 */

// Re-export types
export type {
    RedisConfig,
    Session,
    SessionConfig,
    SessionData,
    SessionDriver,
} from './types.ts'

// Re-export configuration
export { configureSession, getSessionConfig } from './config.ts'

// Re-export utilities
export { getSession } from './utils.ts'

// Re-export drivers
export {
    CookieSessionDriver,
    DenoKvSessionDriver,
    MemorySessionDriver,
    RedisSessionDriver,
} from './drivers/mod.ts'

// Re-export store
export { SessionStore } from './store.ts'

// Re-export middleware
export { sessionMiddleware } from './middleware.ts'
