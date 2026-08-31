/**
 * @fileoverview Session middleware factory.
 *
 * @module @lockness/session/middleware
 */

import type { Context } from 'hono'
import { getCookie, setCookie } from '@lockness/hono'
import type { SessionConfig } from './types.ts'
import { getSessionConfig } from './config.ts'
import { generateSessionId } from './utils.ts'
import { createDriver } from './drivers/mod.ts'
import { SessionStore } from './store.ts'

/**
 * Session middleware factory.
 *
 * Creates a Hono middleware that initializes session handling for each request.
 * Automatically loads, saves, and manages session lifecycle.
 *
 * @param config - Optional configuration overrides
 * @returns Hono middleware function
 *
 * @example
 * ```typescript
 * import { sessionMiddleware } from '@lockness/session'
 *
 * // Use with global config
 * app.useMiddleware(sessionMiddleware())
 *
 * // Or with inline config
 * app.useMiddleware(sessionMiddleware({
 *   driver: 'deno-kv',
 *   lifetime: 86400,
 * }))
 * ```
 */
export function sessionMiddleware(
    config?: Partial<SessionConfig>,
): (c: Context, next: () => Promise<void>) => Promise<void> {
    const sessionConfig = { ...getSessionConfig(), ...config }

    return async (c: Context, next: () => Promise<void>) => {
        // Create driver based on config using factory
        const driver = createDriver(c, sessionConfig)

        // Get or create session ID
        let sessionId = getCookie(c, sessionConfig.cookieName)
        if (!sessionId) {
            sessionId = generateSessionId()
        }

        // Load session data
        const data = (await driver.read(sessionId)) || {}

        // Create session store
        const session = new SessionStore(sessionId, driver, data, sessionConfig)

        // Attach to context
        c.set('session', session)

        // Process request
        await next()

        // Save session if modified
        await session.save()

        // Set session cookie (for non-cookie drivers)
        if (sessionConfig.driver !== 'cookie') {
            setCookie(c, sessionConfig.cookieName, session.getId(), {
                path: sessionConfig.path,
                domain: sessionConfig.domain,
                secure: sessionConfig.secure,
                httpOnly: sessionConfig.httpOnly,
                sameSite: sessionConfig.sameSite,
                maxAge: sessionConfig.lifetime,
            })
        }
    }
}
