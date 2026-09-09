/**
 * @fileoverview Redis session driver.
 *
 * A thin adapter over `@lockness/redis`: the connection discipline (single-flight
 * connect, per-connection command serialization, self-heal, lifecycle-drain
 * close) lives in {@link RedisClient}; this file adds only the session semantics —
 * the `session:<id>` key convention, JSON (de)serialization, the atomic
 * regenerate Lua script, and the outage-vs-miss distinction (`RedisReadError`
 * with a redacted id).
 *
 * @module @lockness/session/drivers/redis
 */

import { renderError } from '@lockness/contract'
import { RedisClient } from '@lockness/redis'
import type { SessionData, SessionDriver } from '../types.ts'

/**
 * A failed Redis read — a connection or protocol fault, never a cache miss.
 *
 * `RedisSessionDriver.read` throws this (rather than swallowing the failure as
 * `null`) so an outage is distinguishable from an absent key. Its message is
 * deliberately generic; the underlying cause travels on `.cause` for logs, not
 * for the client, so the framework renders a generic 500 with no RESP text or
 * connection detail (FR-005).
 */
export class RedisReadError extends Error {
    /**
     * @param message - The generic, client-safe message (no RESP or connection
     *   detail); the underlying fault travels on `options.cause` for logs only.
     * @param options - Optional `{ cause }` carrying the originating error.
     */
    constructor(message: string, options?: { cause?: unknown }) {
        super(message, options)
        this.name = 'RedisReadError'
    }
}

/**
 * A short, non-reversible fingerprint of a session id, safe to log.
 *
 * The session id is a bearer credential — `session:<id>` is the Redis key — so
 * the raw value must never reach a log store. `safeForLog` neutralises control
 * characters but passes a hex id through verbatim, so it cannot redact a
 * credential; an FNV-1a fingerprint lets an operator correlate log lines without
 * exposing the token (FR-005, decided at T014).
 *
 * @param sessionId - The raw session id.
 * @returns A `session#<8-hex>` fingerprint that never contains the raw id.
 */
function redactSessionId(sessionId: string): string {
    let hash = 0x811c9dc5
    for (let i = 0; i < sessionId.length; i++) {
        hash ^= sessionId.charCodeAt(i)
        hash = Math.imul(hash, 0x01000193)
    }
    return `session#${(hash >>> 0).toString(16).padStart(8, '0')}`
}

/**
 * Redis session driver.
 *
 * Persistent session storage using a Redis server, over the raw-RESP
 * {@link RedisClient} from `@lockness/redis` — no external dependency.
 *
 * @remarks
 * The client holds a single connection whose RESP reply reader expects exactly
 * one reply per command, so overlapping commands must never interleave their
 * frames. That is enforced inside the client (single-flight `connect()` and a
 * per-connection command queue), so the driver is safe to memoize and share
 * across requests per process (`drivers/registry.ts`).
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
    /**
     * The pooled RESP connection. The session driver's connection-lifetime tests
     * reach this to preset a fake socket and to assert self-heal cleared it, so
     * it stays a named field rather than an anonymous local.
     */
    private readonly client: RedisClient

    constructor(config: {
        hostname: string
        port?: number
        password?: string
        db?: number
        tls?: boolean
    }) {
        // The disposable name and priority preserve the session driver's
        // historical shutdown-drain identity (`session:redis`, priority 60) now
        // that the socket is owned by the shared client.
        this.client = new RedisClient({
            hostname: config.hostname,
            port: config.port,
            password: config.password,
            db: config.db,
            tls: config.tls,
            disposableName: 'session:redis',
            disposablePriority: 60,
        })
    }

    /**
     * Read a session by id.
     *
     * @param sessionId - The session identifier (the `session:<id>` Redis key).
     * @returns The stored session data, or `null` for a genuine cache miss (a
     *   RESP nil reply) only.
     * @throws {RedisReadError} On any connection or protocol failure — logged
     *   once at ERROR with the id redacted, then rethrown, so an outage is never
     *   mistaken for a miss (FR-005).
     */
    async read(sessionId: string): Promise<SessionData | null> {
        try {
            const reply = await this.client.command(
                'GET',
                `session:${sessionId}`,
            )
            // A RESP nil bulk is the ONLY cache miss — return null, no log.
            if (reply.type === 'nil') return null
            if (reply.type === 'bulk' || reply.type === 'simple') {
                return JSON.parse(reply.value) as SessionData
            }
            // Any other reply to a GET is a protocol violation, not a miss.
            throw new Error(`unexpected RESP reply for GET: ${reply.type}`)
        } catch (error) {
            // Every failure — connection down, protocol error, corrupt JSON —
            // is logged ONCE at ERROR with a redacted id (never the raw
            // `session:<id>`, a bearer credential) and rethrown as a typed error
            // (FR-005). Only the genuine nil above returns null. The upstream
            // framework handler renders this without re-logging, as a generic
            // 500 carrying no RESP text or connection detail.
            console.error(
                `[session] redis read failed for ${
                    redactSessionId(sessionId)
                }: ${renderError(error)}`,
            )
            throw new RedisReadError('session read failed', { cause: error })
        }
    }

    /**
     * Write a session with a fresh expiry, via `SETEX`.
     *
     * @param sessionId - The session identifier.
     * @param data - The session data to store (serialised to JSON).
     * @param lifetime - The session lifetime in seconds (the `SETEX` expiry).
     */
    async write(
        sessionId: string,
        data: SessionData,
        lifetime: number,
    ): Promise<void> {
        await this.client.command(
            'SETEX',
            `session:${sessionId}`,
            String(lifetime),
            JSON.stringify(data),
        )
    }

    /**
     * Destroy a session, via `DEL`.
     *
     * @param sessionId - The session identifier to delete.
     */
    async destroy(sessionId: string): Promise<void> {
        await this.client.command('DEL', `session:${sessionId}`)
    }

    /**
     * Atomic id rotation, server-side, in one round-trip.
     *
     * `GET` the old key; if present, `SET` the new key with the same value and a
     * fresh `EX <lifetime>`, then `DEL` the old key. Because a Redis Lua script
     * runs as one indivisible unit, no failure path can leave the authenticated
     * data on the new id while the attacker-known old id also still resolves
     * (FR-011). The session bytes never leave the server — they move key-to-key
     * inside Redis — and `EVAL` is one command / one reply, so it needs no
     * array-reply parsing added to the one-reply-per-command client (#145).
     */
    private static readonly REGENERATE_SCRIPT = [
        "local v = redis.call('GET', KEYS[1])",
        'if v then',
        "  redis.call('SET', KEYS[2], v, 'EX', ARGV[1])",
        "  redis.call('DEL', KEYS[1])",
        'end',
        'return 1',
    ].join('\n')

    async regenerate(
        oldId: string,
        newId: string,
        lifetime: number,
    ): Promise<void> {
        // Lifetime is the passed param — never `config.db`, which defaults to 0
        // and produced `SETEX <key> 0` (a login-500) in the pre-#139 body.
        await this.client.command(
            'EVAL',
            RedisSessionDriver.REGENERATE_SCRIPT,
            '2',
            `session:${oldId}`,
            `session:${newId}`,
            String(lifetime),
        )
    }

    /**
     * Close the connection and release its resources.
     *
     * Delegates to {@link RedisClient.close}: it deregisters the shutdown
     * disposable, serializes a `QUIT` after any in-flight command, and closes the
     * socket. Idempotent, and it never reopens a closed socket.
     */
    close(): Promise<void> {
        return this.client.close()
    }
}
