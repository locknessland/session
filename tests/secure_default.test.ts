/**
 * The session cookie `secure` flag must default fail-closed: on everywhere
 * except an explicitly-development environment, while an explicit consumer
 * value always wins (M1, #167).
 *
 * @module @lockness/session/tests/secure_default
 */

import { assertEquals } from '@std/assert'
import { configureSession, getSessionConfig } from '../mod.ts'

/** Snapshot both env names, run `fn` under a chosen combo, then restore. */
function withEnv(
    combo: { DENO_ENV?: string; APP_ENV?: string },
    fn: () => void,
): void {
    const prevDeno = Deno.env.get('DENO_ENV')
    const prevApp = Deno.env.get('APP_ENV')
    const set = (k: string, v?: string) =>
        v === undefined ? Deno.env.delete(k) : Deno.env.set(k, v)
    set('DENO_ENV', combo.DENO_ENV)
    set('APP_ENV', combo.APP_ENV)
    try {
        fn()
    } finally {
        set('DENO_ENV', prevDeno)
        set('APP_ENV', prevApp)
    }
}

Deno.test('secure defaults to true when the environment is not explicitly development (#167)', () => {
    withEnv({}, () => {
        configureSession({ driver: 'cookie' })
        assertEquals(getSessionConfig().secure, true)
    })
})

Deno.test('secure defaults to false only under an explicit development signal (#167)', () => {
    withEnv({ APP_ENV: 'development' }, () => {
        configureSession({ driver: 'cookie' })
        assertEquals(getSessionConfig().secure, false)
    })
    withEnv({ DENO_ENV: 'development' }, () => {
        configureSession({ driver: 'cookie' })
        assertEquals(getSessionConfig().secure, false)
    })
})

Deno.test('secure defaults to true in production (#167)', () => {
    withEnv({ DENO_ENV: 'production' }, () => {
        configureSession({ driver: 'cookie' })
        assertEquals(getSessionConfig().secure, true)
    })
})

Deno.test('an explicit secure value always wins over the derived default (#167)', () => {
    // Explicit false in production must be honoured...
    withEnv({ DENO_ENV: 'production' }, () => {
        configureSession({ driver: 'cookie', secure: false })
        assertEquals(getSessionConfig().secure, false)
    })
    // ...and explicit true in development too.
    withEnv({ APP_ENV: 'development' }, () => {
        configureSession({ driver: 'cookie', secure: true })
        assertEquals(getSessionConfig().secure, true)
    })
})
