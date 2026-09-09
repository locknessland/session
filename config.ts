/**
 * @fileoverview Session configuration management.
 *
 * @module @lockness/session/config
 */

import { isExplicitlyDevelopment } from '@lockness/contract'
import type { SessionConfig } from './types.ts'

/**
 * The fail-closed default for the cookie `secure` flag.
 *
 * The sealed cookie *is* the stateless session, so one transmitted over
 * plaintext HTTP and captured can be replayed to hijack the session even though
 * its contents are authenticated-encrypted. `secure` must therefore be on
 * unless we are *explicitly* in development — `isExplicitlyDevelopment()` fails
 * closed, so an unset or ambiguous environment (fresh deploy, compiled binary
 * without `--allow-env`) yields `true`, and only a positive
 * `DENO_ENV`/`APP_ENV=development` signal allows the plaintext-localhost `false`
 * (M1, #167). A consumer may always override it explicitly.
 *
 * @returns `true` unless the environment is explicitly development.
 */
export function secureCookieDefault(): boolean {
    return !isExplicitlyDevelopment()
}

/**
 * Package defaults.
 *
 * **No `secret` here, deliberately.** It used to default to `''`, which the
 * cookie driver read as "encryption off" — so the documented
 * `sessionMiddleware()` call shipped an attacker-writable cookie. A required
 * field whose shipped default is, by its own definition, unusable invites
 * exactly one fix: putting a generated key back into this file, process-wide and
 * invisible. The key comes from the application, or the cookie driver refuses to
 * start.
 *
 * `secure` is derived (see {@link secureCookieDefault}) rather than hardcoded:
 * it defaults on outside an explicit development environment and is re-derived
 * on every {@link configureSession} call, so it tracks the environment in force
 * at configuration time. An explicit `secure` passed to `configureSession`
 * always wins.
 */
export const defaultConfig: SessionConfig = {
    driver: 'cookie',
    cookieName: 'lockness_session',
    lifetime: 7200, // 2 hours
    path: '/',
    secure: secureCookieDefault(),
    httpOnly: true,
    sameSite: 'Lax',
}

let globalConfig: SessionConfig = {
    ...defaultConfig,
    secure: secureCookieDefault(),
}

/**
 * Configure global session settings.
 *
 * Call this once at application startup to set default session options.
 * These can be overridden per-middleware instance.
 *
 * @param config - Partial configuration to merge with defaults
 *
 * @example
 * ```typescript
 * configureSession({
 *   driver: 'deno-kv',
 *   secret: Deno.env.get('SESSION_SECRET')!,
 *   secure: true,
 *   lifetime: 86400, // 24 hours
 * })
 * ```
 */
export function configureSession(config: Partial<SessionConfig>): void {
    // `secure` is re-derived here so it reflects the environment at configuration
    // time; an explicit `config.secure` overrides it (spread order).
    globalConfig = {
        ...defaultConfig,
        secure: secureCookieDefault(),
        ...config,
    }
}

/**
 * Get the current session configuration.
 *
 * @returns The merged global session configuration
 */
export function getSessionConfig(): SessionConfig {
    return globalConfig
}
