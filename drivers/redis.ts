/**
 * @fileoverview Redis session driver.
 *
 * @module @lockness/session/drivers/redis
 */

import type { SessionData, SessionDriver } from '../types.ts'

/**
 * Redis session driver.
 *
 * Persistent session storage using Redis server.
 * Implements RESP protocol directly without external dependencies.
 *
 * @example
 * ```typescript
 * const driver = new RedisSessionDriver({
 *   hostname: 'localhost',
 *   port: 6379,
 *   password: 'secret',
 *   db: 1,
 * })
 * ```
 */
export class RedisSessionDriver implements SessionDriver {
    private connection: Deno.Conn | null = null
    private readonly config: {
        hostname: string
        port: number
        password?: string
        db?: number
    }

    constructor(config: {
        hostname: string
        port?: number
        password?: string
        db?: number
    }) {
        this.config = {
            hostname: config.hostname,
            port: config.port ?? 6379,
            password: config.password,
            db: config.db ?? 0,
        }
    }

    private async connect(): Promise<Deno.Conn> {
        if (!this.connection) {
            this.connection = await Deno.connect({
                hostname: this.config.hostname,
                port: this.config.port,
            })

            // Authenticate if password provided
            if (this.config.password) {
                await this.sendCommand(['AUTH', this.config.password])
            }

            // Select database if specified
            if (this.config.db !== 0) {
                await this.sendCommand(['SELECT', String(this.config.db)])
            }
        }
        return this.connection
    }

    private async sendCommand(args: string[]): Promise<string> {
        const conn = await this.connect()
        const encoder = new TextEncoder()
        const decoder = new TextDecoder()

        // Build RESP protocol command
        let command = `*${args.length}\r\n`
        for (const arg of args) {
            command += `$${arg.length}\r\n${arg}\r\n`
        }

        await conn.write(encoder.encode(command))

        // Read response
        const buffer = new Uint8Array(4096)
        const n = await conn.read(buffer)
        if (!n) throw new Error('Redis connection closed')

        const response = decoder.decode(buffer.subarray(0, n))
        return this.parseResponse(response)
    }

    private parseResponse(response: string): string {
        const type = response[0]

        if (type === '+') {
            // Simple string
            return response.substring(1, response.indexOf('\r\n'))
        } else if (type === '$') {
            // Bulk string
            const lines = response.split('\r\n')
            const length = parseInt(lines[0].substring(1))
            if (length === -1) return '' // NULL
            return lines[1] || ''
        } else if (type === '-') {
            // Error
            throw new Error(response.substring(1, response.indexOf('\r\n')))
        } else if (type === ':') {
            // Integer
            return response.substring(1, response.indexOf('\r\n'))
        }

        return ''
    }

    async read(sessionId: string): Promise<SessionData | null> {
        try {
            const data = await this.sendCommand(['GET', `session:${sessionId}`])
            if (!data) return null
            return JSON.parse(data) as SessionData
        } catch {
            return null
        }
    }

    async write(
        sessionId: string,
        data: SessionData,
        lifetime: number,
    ): Promise<void> {
        await this.sendCommand([
            'SETEX',
            `session:${sessionId}`,
            String(lifetime),
            JSON.stringify(data),
        ])
    }

    async destroy(sessionId: string): Promise<void> {
        await this.sendCommand(['DEL', `session:${sessionId}`])
    }

    async regenerate(oldId: string, newId: string): Promise<void> {
        const data = await this.read(oldId)
        if (data) {
            await this.write(newId, data, this.config.db ?? 7200)
            await this.destroy(oldId)
        }
    }

    async close(): Promise<void> {
        if (this.connection) {
            await this.sendCommand(['QUIT'])
            this.connection.close()
            this.connection = null
        }
    }
}
