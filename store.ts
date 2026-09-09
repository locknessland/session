/**
 * @fileoverview Session store implementation.
 *
 * @module @lockness/session/store
 */

import type {
    Session,
    SessionConfig,
    SessionData,
    SessionDriver,
} from './types.ts'
import { generateSessionId } from './utils.ts'

/**
 * Session store implementation.
 *
 * Manages session data, flash messages, and persistence.
 * Created automatically by the session middleware.
 *
 * @internal Use `getSession(c)` to access the session in controllers.
 */
export class SessionStore implements Session {
    private sessionId: string
    private readonly driver: SessionDriver
    private data: SessionData
    private flashData: SessionData = {}
    private dirty = false
    private readonly config: SessionConfig

    constructor(
        sessionId: string,
        driver: SessionDriver,
        data: SessionData,
        config: SessionConfig,
    ) {
        this.sessionId = sessionId
        this.driver = driver
        this.data = { ...data }
        this.config = config

        // Extract flash data from previous request
        if (this.data._flash) {
            this.flashData = this.data._flash as SessionData
            delete this.data._flash
        }
    }

    getId(): string {
        return this.sessionId
    }

    get<T = unknown>(key: string, defaultValue?: T): T | undefined {
        const value = this.data[key] as T
        return value !== undefined ? value : defaultValue
    }

    set(key: string, value: unknown): void {
        this.data[key] = value
        this.dirty = true
    }

    has(key: string): boolean {
        return key in this.data
    }

    forget(key: string): void {
        delete this.data[key]
        this.dirty = true
    }

    all(): SessionData {
        return { ...this.data }
    }

    flush(): void {
        this.data = {}
        this.dirty = true
    }

    async regenerate(): Promise<void> {
        const newId = generateSessionId()
        // `config.lifetime` is the single source of "how long a session lives"
        // (plan §5 row 1) — the same value `write()` receives — so a regenerated
        // session is given a fresh lifetime rather than inheriting the old
        // record's remaining TTL or a per-driver default.
        await this.driver.regenerate(
            this.sessionId,
            newId,
            this.config.lifetime,
        )
        this.sessionId = newId
        this.dirty = true
    }

    async destroy(): Promise<void> {
        await this.driver.destroy(this.sessionId)
        this.data = {}
        this.dirty = true
    }

    flash(key: string, value: unknown): void {
        if (!this.data._flash) {
            this.data._flash = {}
        }
        ;(this.data._flash as SessionData)[key] = value
        this.dirty = true
    }

    getFlash<T = unknown>(key: string): T | undefined {
        return this.flashData[key] as T
    }

    isDirty(): boolean {
        return this.dirty
    }

    /**
     * Set the opaque subject the session belongs to (#147).
     *
     * Delegates to the optional `driver.setSubject?` — only the cookie driver
     * embeds a subject; on the other drivers this is a no-op. Stringified so the
     * opaque token matches the eviction key. See {@link Session.setSubject}.
     *
     * @param id - The authenticated principal's id.
     */
    setSubject(id: string | number): void {
        this.driver.setSubject?.(String(id))
    }

    /**
     * Evict every session of a subject (#147).
     *
     * Delegates to the optional `driver.revokeUser?` — only the cookie driver
     * records an eviction epoch; on the other drivers this is a no-op. Stringified
     * so the eviction key matches the embedded subject. See
     * {@link Session.revokeUser}.
     *
     * @param id - The authenticated principal's id to evict.
     * @throws When the backing store write fails (fail-closed).
     */
    async revokeUser(id: string | number): Promise<void> {
        // Fail LOUD when the active driver cannot evict per-user (only the cookie
        // driver records an eviction epoch). A silent no-op here would let a
        // caller believe "log out everywhere" happened when it did nothing on a
        // memory/deno-kv/redis driver (#147 review). Server-side per-user eviction
        // on those drivers is a separate mechanism (delete the record) — not this.
        if (!this.driver.revokeUser) {
            throw new Error(
                'per-user session eviction requires the cookie driver with revocation enabled',
            )
        }
        await this.driver.revokeUser(String(id))
    }

    /**
     * Save session data to storage.
     * @internal Called automatically by middleware.
     */
    async save(): Promise<void> {
        if (this.dirty) {
            await this.driver.write(
                this.sessionId,
                this.data,
                this.config.lifetime,
            )
            this.dirty = false
        }
    }
}
