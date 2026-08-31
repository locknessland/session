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
        await this.driver.regenerate(this.sessionId, newId)
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
