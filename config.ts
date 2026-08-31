/**
 * @fileoverview Session configuration management.
 *
 * @module @lockness/session/config
 */

import type { SessionConfig } from './types.ts'

export const defaultConfig: SessionConfig = {
    driver: 'cookie',
    cookieName: 'lockness_session',
    lifetime: 7200, // 2 hours
    secret: '', // Must be set by user
    path: '/',
    secure: false,
    httpOnly: true,
    sameSite: 'Lax',
}

let globalConfig: SessionConfig = { ...defaultConfig }

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
    globalConfig = { ...defaultConfig, ...config }
}

/**
 * Get the current session configuration.
 *
 * @returns The merged global session configuration
 */
export function getSessionConfig(): SessionConfig {
    return globalConfig
}
