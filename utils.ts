/**
 * @fileoverview Session utility functions.
 *
 * @module @lockness/session/utils
 */

import type { Context } from 'hono'
import type { Session } from './types.ts'

/**
 * Generate a cryptographically secure session ID.
 *
 * Uses Web Crypto API for random bytes generation.
 *
 * @returns A 64-character hexadecimal session ID
 * @internal
 */
export function generateSessionId(): string {
    const array = new Uint8Array(32)
    crypto.getRandomValues(array)
    return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join(
        '',
    )
}

/**
 * Get session from Hono context.
 *
 * Retrieves the session instance attached by the session middleware.
 * Throws if called before the middleware has run.
 *
 * @param c - Hono context object
 * @returns The session instance
 * @throws {Error} If session middleware is not configured
 *
 * @example
 * ```typescript
 * import { getSession } from '@lockness/session'
 *
 * @Controller('/user')
 * class UserController {
 *   @Get('/profile')
 *   profile(c: Context) {
 *     const session = getSession(c)
 *     const userId = session.get<number>('userId')
 *     // ...
 *   }
 * }
 * ```
 */
export function getSession(c: Context): Session {
    const session = c.get('session') as Session | undefined
    if (!session) {
        throw new Error('Session not initialized. Use sessionMiddleware.')
    }
    return session
}
