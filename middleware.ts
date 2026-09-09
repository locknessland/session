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
import { getOrCreateDriver } from './drivers/registry.ts'
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
/**
 * The only shape a session id may take.
 *
 * Exactly what {@link generateSessionId} emits — 32 CSPRNG bytes as lowercase
 * hex. The id reaches a storage backend as a key (`session:${id}` on Redis, a
 * Deno KV key part), and it arrives from a cookie that Hono has already
 * URL-decoded, so `%0D%0A` in the header is raw CR/LF by the time it is read.
 * Anything not matching this is discarded and a fresh id is generated.
 */
const SESSION_ID = /^[0-9a-f]{64}$/

export function sessionMiddleware(
    config?: Partial<SessionConfig>,
): (c: Context, next: () => Promise<void>) => Promise<void> {
    return async (c: Context, next: () => Promise<void>) => {
        // Resolved HERE, per request — NOT at factory-call time.
        //
        // The kernel calls this factory from a field initialiser, which runs at
        // `new KernelClass()` (core's `loader.ts:136`); `configureSession` runs
        // later, in bootstrap step 110 (`loader.ts:162`). A snapshot taken in
        // the factory therefore captured the package defaults — an empty secret
        // — and no key an operator set ever reached the driver. That is what
        // made #137 reachable on every kernel application, with APP_KEY set
        // correctly. Do not memoise this for performance: the memo is the bug.
        const sessionConfig = { ...getSessionConfig(), ...config }

        // The config is resolved per request (above); only the driver is
        // memoized, keyed on that resolved config — so the process holds one
        // handle, not one per request, while #137's per-request resolution
        // stays intact. Cookie and redis are per-request inside the registry.
        const driver = getOrCreateDriver(c, sessionConfig)

        const presented = getCookie(c, sessionConfig.cookieName)
        const sessionId = presented && SESSION_ID.test(presented)
            ? presented
            : generateSessionId()

        const data = (await driver.read(sessionId)) || {}
        const session = new SessionStore(sessionId, driver, data, sessionConfig)

        c.set('session', session)

        await next()

        await session.save()

        // The cookie driver writes the whole session into the cookie itself;
        // for every other driver the cookie carries only the id.
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
