/**
 * @fileoverview Session type definitions.
 *
 * Contains all interfaces and types for the session package.
 *
 * @module @lockness/session/types
 */

/**
 * Session data container type.
 *
 * A flexible record type allowing any string keys with unknown values.
 * Use type assertions or generics when retrieving values.
 *
 * @example
 * ```typescript
 * const data: SessionData = {
 *   userId: 123,
 *   preferences: { theme: 'dark' },
 * }
 * ```
 */
export interface SessionData {
    /** Session data key-value pairs */
    [key: string]: unknown
}

/**
 * Redis connection configuration.
 */
export interface RedisConfig {
    /** Redis server hostname */
    hostname: string
    /**
     * Redis server port.
     * @default 6379
     */
    port?: number
    /** Redis password for authentication */
    password?: string
    /**
     * Redis database index.
     * @default 0
     */
    db?: number
}

/**
 * Session configuration options.
 *
 * Controls session behavior, storage driver, cookie settings, and encryption.
 *
 * @example
 * ```typescript
 * const config: SessionConfig = {
 *   driver: 'deno-kv',
 *   cookieName: 'app_session',
 *   lifetime: 3600,
 *   secret: Deno.env.get('APP_KEY'),
 *   path: '/',
 *   secure: true,
 *   httpOnly: true,
 *   sameSite: 'Strict',
 * }
 * ```
 */
export interface SessionConfig {
    /**
     * Session storage driver.
     * - `cookie`: Stores encrypted data directly in cookie (stateless)
     * - `memory`: In-memory storage (development/testing only)
     * - `deno-kv`: Deno KV persistent storage
     * - `redis`: Redis server storage
     * @default 'cookie'
     */
    driver: 'cookie' | 'deno-kv' | 'memory' | 'redis'
    /**
     * Cookie name for session ID or data.
     * @default 'lockness_session'
     */
    cookieName: string
    /**
     * Idle session lifetime in seconds — the window of inactivity after which a
     * session expires. Refreshed on every write.
     * @default 7200 (2 hours)
     */
    lifetime: number
    /**
     * Absolute session lifetime in seconds — the hard ceiling measured from first
     * issuance, **never** refreshed by activity. When set (a positive number),
     * the cookie driver refuses a session once `now - iat` exceeds it, no matter
     * how often it was re-sealed. Leave **undefined** to disable the cap
     * (`0`/negative is a configuration error, not "off"). Recommended when
     * enabled: `604800` (7 days). Only the cookie driver enforces it today.
     * @default undefined (no absolute cap)
     */
    absoluteLifetime?: number
    /**
     * Enable per-session revocation on the cookie driver: logout and id rotation
     * add the session's nonce to a Deno-KV revocation set, so a captured copy of
     * a revoked cookie can no longer authenticate. **Requires
     * {@link SessionConfig.absoluteLifetime}** (it bounds each revocation entry's
     * retention); enabling it without the cap is refused at boot. With it off the
     * cookie driver holds no server-side state.
     * @default false
     */
    revocation?: boolean
    /**
     * The application key, as `base64:` followed by 32 random bytes in base64 —
     * the shape {@link generateAppKey} emits and the only one accepted.
     *
     * Optional here because the memory, Deno KV and Redis drivers never encrypt
     * anything; the cookie they set carries only a session id. The **cookie**
     * driver requires it and refuses to construct without one. There is no
     * unencrypted mode: a missing key is a configuration error, never a silent
     * downgrade to base64.
     *
     * Never a literal in source. See `secret.ts`.
     */
    secret?: string
    /**
     * Cookie path attribute.
     * @default '/'
     */
    path: string
    /**
     * Cookie domain attribute.
     * Leave undefined to use the current domain.
     */
    domain?: string
    /**
     * Secure cookie flag (HTTPS only).
     * Should be `true` in production.
     * @default false
     */
    secure: boolean
    /**
     * HTTP-only cookie flag.
     * Prevents JavaScript access to the cookie.
     * @default true
     */
    httpOnly: boolean
    /**
     * SameSite cookie attribute.
     * Controls cross-origin cookie behavior.
     * @default 'Lax'
     */
    sameSite: 'Strict' | 'Lax' | 'None'
    /**
     * Deno KV database path.
     * Only used when `driver` is `'deno-kv'`.
     * Leave undefined to use the default KV store.
     */
    kvPath?: string
    /**
     * Redis connection configuration.
     * Required when `driver` is `'redis'`.
     */
    redis?: RedisConfig
}

/**
 * Session storage driver interface.
 *
 * Implement this interface to create custom session storage backends.
 * All methods are async for consistency across different storage types.
 *
 * @example
 * ```typescript
 * class CustomDriver implements SessionDriver {
 *   async read(sessionId: string): Promise<SessionData | null> {
 *     // Fetch from your storage
 *     return myStorage.get(sessionId)
 *   }
 *   // ... implement other methods
 * }
 * ```
 */
export interface SessionDriver {
    /**
     * Read session data by ID.
     * @param sessionId - The unique session identifier
     * @returns Session data or null if not found/expired
     */
    read(sessionId: string): Promise<SessionData | null>
    /**
     * Write session data to storage.
     * @param sessionId - The unique session identifier
     * @param data - Session data to persist
     * @param lifetime - Session lifetime in seconds
     */
    write(sessionId: string, data: SessionData, lifetime: number): Promise<void>
    /**
     * Destroy/delete a session.
     * @param sessionId - The session identifier to destroy
     */
    destroy(sessionId: string): Promise<void>
    /**
     * Regenerate session ID (transfer data to new ID).
     *
     * Used for session-fixation protection after authentication: the data is
     * carried to `newId` and the record at `oldId` is destroyed. On the
     * server-side drivers the move is atomic — the new key is written and the
     * old one deleted as one indivisible operation.
     *
     * @param oldId - The current session identifier
     * @param newId - The new session identifier
     * @param lifetime - Session lifetime in seconds. The regenerated session is
     *   given a **fresh** lifetime — the same value a `write()` for this session
     *   would receive — never the remaining lifetime of the old record and never
     *   a per-driver default. The single source is `SessionConfig.lifetime`,
     *   threaded here by {@link Session.regenerate}'s store implementation.
     */
    regenerate(oldId: string, newId: string, lifetime: number): Promise<void>
    /**
     * Garbage collection - remove expired sessions.
     * Optional: only implement for drivers that need manual cleanup.
     */
    gc?(): Promise<void>
    /**
     * Close any open connections.
     * Optional: only implement for drivers with persistent connections.
     */
    close?(): Promise<void>
    /**
     * Stash the opaque subject token to embed on the next write (#147).
     *
     * **Optional and cookie-only** — mirroring `gc?`/`close?`. Only the cookie
     * driver carries a subject inside its sealed payload; the server-side drivers
     * hold no subject and do not implement this. The session layer never
     * interprets `sub`.
     *
     * @param sub - The opaque subject token (the authenticated principal's id).
     */
    setSubject?(sub: string): void
    /**
     * Evict every session of a subject by recording its eviction epoch (#147).
     *
     * **Optional and cookie-only.** The stateless cookie driver cannot enumerate
     * a subject's sessions, so it uses an eviction epoch; the server-side drivers
     * delete their records instead and do not implement this (plan §9 R3).
     *
     * @param sub - The opaque subject token to evict.
     * @throws When the backing store write fails (fail-closed).
     */
    revokeUser?(sub: string): Promise<void>
}

/**
 * Session instance interface.
 *
 * Provides methods to read, write, and manage session data.
 * Supports flash messages for one-time data transfer between requests.
 *
 * @example
 * ```typescript
 * const session = getSession(c)
 *
 * // Store data
 * session.set('cart', [{ id: 1, qty: 2 }])
 *
 * // Retrieve with type
 * const cart = session.get<CartItem[]>('cart', [])
 *
 * // Flash message (available only on next request)
 * session.flash('success', 'Item added to cart')
 *
 * // On next request
 * const message = session.getFlash<string>('success')
 * ```
 */
export interface Session {
    /**
     * Get the current session ID.
     * @returns The unique session identifier
     */
    getId(): string
    /**
     * Get a value from the session.
     * @typeParam T - Expected return type
     * @param key - The key to retrieve
     * @param defaultValue - Default value if key doesn't exist
     * @returns The stored value or default
     */
    get<T = unknown>(key: string, defaultValue?: T): T | undefined
    /**
     * Set a value in the session.
     * @param key - The key to store under
     * @param value - The value to store (must be JSON-serializable)
     */
    set(key: string, value: unknown): void
    /**
     * Check if a key exists in the session.
     * @param key - The key to check
     * @returns True if the key exists
     */
    has(key: string): boolean
    /**
     * Remove a key from the session.
     * @param key - The key to remove
     */
    forget(key: string): void
    /**
     * Get all session data.
     * @returns A copy of all session data
     */
    all(): SessionData
    /**
     * Clear all session data.
     * Keeps the session ID but removes all stored values.
     */
    flush(): void
    /**
     * Regenerate the session ID.
     * Use after authentication to prevent session fixation attacks.
     */
    regenerate(): Promise<void>
    /**
     * Destroy the session completely.
     * Removes all data and invalidates the session.
     */
    destroy(): Promise<void>
    /**
     * Set flash data (available only for the next request).
     * @param key - The flash key
     * @param value - The flash value (must be JSON-serializable)
     */
    flash(key: string, value: unknown): void
    /**
     * Get flash data from the previous request.
     * @typeParam T - Expected return type
     * @param key - The flash key to retrieve
     * @returns The flash value or undefined
     */
    getFlash<T = unknown>(key: string): T | undefined
    /**
     * Check if the session has been modified.
     * @returns True if any data has been changed
     */
    isDirty(): boolean
    /**
     * Set the opaque subject the session belongs to (#147).
     *
     * **Optional** — honoured only by the cookie driver (the sole driver whose
     * sealed payload carries a subject); a no-op on the server-side drivers. The
     * auth guard calls it after every `regenerate()` so the per-user eviction
     * check keys on the same identity authentication does (`sub ===
     * d[sessionKeyName]`). The id is stringified for the opaque token.
     *
     * @param id - The authenticated principal's id.
     */
    setSubject?(id: string | number): void
    /**
     * Evict every session of a subject (#147) — "log out everywhere / others".
     *
     * **Optional** — honoured only by the cookie driver; a no-op on the
     * server-side drivers (they delete their records instead, plan §9 R3). Records
     * the subject's eviction epoch so every session issued before now is refused.
     * Reached only through the auth guard, scoped to the authenticated subject.
     *
     * @param id - The authenticated principal's id to evict.
     * @throws When the backing store write fails (fail-closed).
     */
    revokeUser?(id: string | number): Promise<void>
}
