/**
 * @fileoverview In-memory session driver.
 *
 * @module @lockness/session/drivers/memory
 */

// deno-lint-ignore-file require-await

import type { SessionData, SessionDriver } from '../types.ts'

/**
 * In-memory session driver.
 *
 * Stores sessions in a Map. Data is lost on server restart.
 * **Use only for development and testing.**
 *
 * @example
 * ```typescript
 * const driver = new MemorySessionDriver()
 * await driver.write('session-id', { userId: 123 }, 3600)
 *
 * // For testing: clear all sessions
 * driver.clear()
 * ```
 */
export class MemorySessionDriver implements SessionDriver {
    private readonly sessions = new Map<
        string,
        { data: SessionData; expires: number }
    >()

    async read(sessionId: string): Promise<SessionData | null> {
        const session = this.sessions.get(sessionId)
        if (!session) return null

        // Check expiration
        if (Date.now() > session.expires) {
            this.sessions.delete(sessionId)
            return null
        }

        return session.data
    }

    async write(
        sessionId: string,
        data: SessionData,
        lifetime: number,
    ): Promise<void> {
        this.sessions.set(sessionId, {
            data,
            expires: Date.now() + lifetime * 1000,
        })
    }

    async destroy(sessionId: string): Promise<void> {
        this.sessions.delete(sessionId)
    }

    async regenerate(oldId: string, newId: string): Promise<void> {
        const session = this.sessions.get(oldId)
        if (session) {
            this.sessions.set(newId, session)
            this.sessions.delete(oldId)
        }
    }

    async gc(): Promise<void> {
        const now = Date.now()
        for (const [id, session] of this.sessions.entries()) {
            if (now > session.expires) {
                this.sessions.delete(id)
            }
        }
    }

    /**
     * Clear all sessions.
     * Testing helper method.
     */
    clear(): void {
        this.sessions.clear()
    }
}
