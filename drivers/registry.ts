/**
 * @fileoverview Process-wide memo for session drivers.
 *
 * A session driver used to be constructed on every request
 * (`middleware.ts` → `createDriver`), so `deno-kv` and `redis` leaked an OS
 * handle per request and `memory` never persisted a session past one request
 * (its store is instance state). This module memoizes the driver **per process,
 * keyed on the resolved config**, so one handle serves the process and the
 * memory store survives across requests. See #138.
 *
 * `memory`, `deno-kv` **and `redis`** are memoized. `redis` joined the memo once
 * its socket became safe to share: its reply reader drains a full frame (#139)
 * and its commands are serialized per connection (#145). It is keyed on
 * host/port/db **and a per-process-keyed HMAC of the password**
 * ({@link driverKey}), so two configs with different credentials never share one
 * authenticated socket, and the key stays safe to log — the credential is folded
 * through a keyed HMAC, not an offline-brute-forceable bare SHA-256 (#248).
 *
 * **`cookie` is the one driver NOT memoized**, a first-class branch here: it
 * closes over the request `Context` and holds no OS resource, so it is built
 * fresh per request. Memoization is an allowlist ({@link MEMOIZED}), not an
 * "everything not cookie" else-branch — a driver must be added explicitly, so
 * nothing slips into the memo unnoticed.
 *
 * The per-request/per-process split has **one** home: this file. `middleware.ts`
 * calls {@link getOrCreateDriver} and never re-decides it.
 *
 * @module @lockness/session/drivers/registry
 */

import type { Context } from 'hono'
import { credentialFingerprint } from '@lockness/redis'
import {
    deregisterDisposable,
    type DisposableHandle,
    registerDisposable,
} from '@lockness/contract/lifecycle/internal'
import type { SessionConfig, SessionDriver } from '../types.ts'
import { createDriver } from './mod.ts'
import { KvRevocationStore, type RevocationStore } from './revocation_store.ts'

/** One driver instance per resolved-config key, for the life of the process. */
const memo = new Map<string, SessionDriver>()

/**
 * One revocation store per KV path, for the life of the process.
 *
 * The cookie driver is per-request, but a revocation store holds a process-shared
 * KV handle — so the store is memoized HERE and injected by reference into each
 * per-request cookie driver. Without this the cookie driver would open a KV
 * handle per request (the #138 leak, one context over).
 */
const revocationStores = new Map<string, KvRevocationStore>()

/** The registry's own shutdown hook, registered once, lazily. */
let registryHandle: DisposableHandle | undefined

/**
 * The process-shared revocation store for a cookie config that enables
 * revocation, memoized per KV path. Returns `undefined` for any config that does
 * not use cookie revocation, so the driver holds no store reference.
 */
function getRevocationStore(
    config: SessionConfig,
): RevocationStore | undefined {
    if (config.driver !== 'cookie' || !config.revocation) return undefined
    const key = config.kvPath ?? ''
    let store = revocationStores.get(key)
    if (!store) {
        store = new KvRevocationStore(config.kvPath)
        revocationStores.set(key, store)
        registryHandle ??= registerDisposable({
            name: 'session:driver-registry',
            dispose: () => resetDriverRegistry(),
        })
    }
    return store
}

/** The driver names that are memoized (per process). Only `cookie` is not. */
const MEMOIZED = new Set<SessionConfig['driver']>([
    'memory',
    'deno-kv',
    'redis',
])

/**
 * Get the session driver for a resolved config, constructing it once per
 * process for the memoized backends and per request for the others.
 *
 * The `config` MUST be the per-request **resolved** config
 * (`{ ...getSessionConfig(), ...override }`) — memoizing the *unresolved* config
 * is the #137 defect. The `Context` is used only to build the per-request
 * `cookie` driver; the memoized branches ignore it.
 *
 * @param c - The request context (used only by the per-request cookie branch).
 * @param config - The resolved session configuration.
 * @returns The driver serving this config — memoized for `memory` / `deno-kv` /
 *   `redis`, fresh for `cookie`.
 * @example
 * ```typescript
 * const driver = getOrCreateDriver(c, { ...getSessionConfig(), ...override })
 * ```
 */
export function getOrCreateDriver(
    c: Context,
    config: SessionConfig,
): SessionDriver {
    // Memoization is an allowlist, not an else-branch: only the drivers in
    // MEMOIZED are ever cached, so `cookie` is per-request by NOT being on the
    // list. A driver cannot slip into the memo by failing to match a `cookie`
    // check; it has to be added to MEMOIZED explicitly, and `driverKey` throws
    // for anything else.
    if (!MEMOIZED.has(config.driver)) {
        // Cookie is per-request, but its revocation store (when enabled) is
        // process-shared — memoized here and injected by reference.
        return createDriver(c, config, getRevocationStore(config))
    }

    const key = driverKey(config)
    let driver = memo.get(key)
    if (!driver) {
        driver = createDriver(c, config)
        memo.set(key, driver)
        // Register the registry's own teardown the first time it holds anything,
        // so a process that never uses sessions registers nothing.
        registryHandle ??= registerDisposable({
            name: 'session:driver-registry',
            dispose: () => resetDriverRegistry(),
        })
    }
    return driver
}

/**
 * The canonical memo key for a resolved config: what makes two configs the same
 * resource. Over the resource-determining fields only — the driver name, the KV
 * path, and (for redis) host/port/db plus a **per-process-keyed HMAC of the
 * password**. **Never the cleartext password**: the key must stay safe to log,
 * so the credential is folded through the shared `credentialFingerprint` from
 * `@lockness/redis` (a keyed HMAC, not an offline-brute-forceable bare SHA-256;
 * the client authenticates with the raw password and needs none). Two redis
 * configs differing only in password therefore resolve to different keys and
 * never share one authenticated socket.
 *
 * @param config - A resolved config whose driver is memoized.
 * @returns A stable key string.
 * @throws {Error} If called for the per-request `cookie` driver — a key for it
 *   would be the artefact that lets it into the memo by mistake.
 * @throws {Error} If called for a `redis` config with no `redis` block — an
 *   unconfigured redis driver has no resource to key.
 * @example
 * ```typescript
 * driverKey({ driver: 'deno-kv', kvPath: './s.db', ... }) // "deno-kv:./s.db"
 * driverKey({ driver: 'redis', redis: { hostname: 'h', port: 6379, db: 0 } })
 * // "redis:h:6379:0:<hmac(password)>"
 * ```
 */
export function driverKey(config: SessionConfig): string {
    switch (config.driver) {
        case 'memory':
            return 'memory'
        case 'deno-kv':
            return `deno-kv:${config.kvPath ?? ''}`
        case 'redis': {
            const r = config.redis
            if (!r) {
                throw new Error(
                    'driverKey called for a redis config with no redis block: ' +
                        'nothing to key.',
                )
            }
            // host:port:db identify the resource; the keyed-HMAC fingerprint of
            // the password keeps two different-credential configs on the same
            // host from collapsing onto one authenticated socket, without the
            // cleartext — or a brute-forceable bare hash — ever entering the
            // (loggable) key.
            return `redis:${r.hostname}:${r.port ?? 6379}:${r.db ?? 0}:${
                credentialFingerprint(r.password ?? '')
            }`
        }
        default:
            throw new Error(
                `driverKey called for the per-request driver '${config.driver}': ` +
                    'cookie is never memoized.',
            )
    }
}

/**
 * Close every memoized driver and clear the memo.
 *
 * Branches on capability: a driver exposing `close()` (deno-kv) is closed to
 * release its handle; one exposing `clear()` (memory) is cleared so no session
 * survives into the next app. `close()` is idempotent, so this overlapping with
 * core's own disposables drain at shutdown frees each handle at most once.
 *
 * `@internal` — for the test lifecycle (call between session tests) and for the
 * registry's own shutdown hook. Not re-exported from `mod.ts`.
 *
 * @example
 * ```typescript
 * // In a test afterEach:
 * resetDriverRegistry()
 * ```
 */
export function resetDriverRegistry(): void {
    for (const driver of memo.values()) {
        if (typeof driver.close === 'function') {
            // kv.close() runs synchronously inside close(); the promise is only
            // the wrapper. A rejection must not throw mid-teardown (it would
            // strand the drivers behind it), but it is not swallowed silently:
            // it is logged, so a failed teardown is visible.
            void Promise.resolve(driver.close()).catch((error) => {
                console.warn(
                    'session: a driver close() failed during registry reset',
                    error,
                )
            })
        } else {
            const withClear = driver as { clear?: () => void }
            withClear.clear?.()
        }
    }
    memo.clear()
    // Close the process-shared revocation stores too — they hold KV handles.
    for (const store of revocationStores.values()) {
        void Promise.resolve(store.close()).catch((error) => {
            console.warn(
                'session: a revocation store close() failed during registry reset',
                error,
            )
        })
    }
    revocationStores.clear()
    // Drop the shutdown hook too, so the next memoization re-arms one. Without
    // this, a reset (test teardown, or the shutdown drain itself) would leave
    // `registryHandle` truthy and the `??=` below would never register again.
    if (registryHandle) {
        deregisterDisposable(registryHandle)
        registryHandle = undefined
    }
}
