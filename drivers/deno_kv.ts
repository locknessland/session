/**
 * @fileoverview Deno KV session driver.
 *
 * @module @lockness/session/drivers/deno-kv
 */

import type { SessionData, SessionDriver } from '../types.ts'

/**
 * Deno KV session driver.
 *
 * Persistent session storage using Deno's built-in KV store.
 * Supports automatic expiration via KV's `expireIn` option.
 *
 * @example
 * ```typescript
 * // Use default KV store
 * const driver = new DenoKvSessionDriver()
 *
 * // Or specify a custom path
 * const driver = new DenoKvSessionDriver('./sessions.db')
 * ```
 */
export class DenoKvSessionDriver implements SessionDriver {
    private kv: Deno.Kv | null = null
    private readonly kvPath?: string

    constructor(kvPath?: string) {
        this.kvPath = kvPath
    }

    private async getKv(): Promise<Deno.Kv> {
        if (!this.kv) {
            this.kv = await Deno.openKv(this.kvPath)
        }
        return this.kv
    }

    async read(sessionId: string): Promise<SessionData | null> {
        const kv = await this.getKv()
        const result = await kv.get<SessionData>(['sessions', sessionId])
        return result.value
    }

    async write(
        sessionId: string,
        data: SessionData,
        lifetime: number,
    ): Promise<void> {
        const kv = await this.getKv()
        await kv.set(['sessions', sessionId], data, {
            expireIn: lifetime * 1000, // Convert to milliseconds
        })
    }

    async destroy(sessionId: string): Promise<void> {
        const kv = await this.getKv()
        await kv.delete(['sessions', sessionId])
    }

    async regenerate(oldId: string, newId: string): Promise<void> {
        const kv = await this.getKv()
        const result = await kv.get<SessionData>(['sessions', oldId])
        if (result.value) {
            await kv.set(['sessions', newId], result.value)
            await kv.delete(['sessions', oldId])
        }
    }

    close(): Promise<void> {
        if (this.kv) {
            this.kv.close()
            this.kv = null
        }
        return Promise.resolve()
    }
}
