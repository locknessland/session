/**
 * A Redis outage is visible, not a silent logout (US3, FR-005 / SC-003).
 *
 * The #139 defect: `read()` wrapped everything in `catch { return null }`, so a
 * dropped connection or protocol error was indistinguishable from a cache miss —
 * every user silently logged out, no log line. These pin the fix: `read()`
 * returns `null` ONLY for a genuine RESP nil; every failure logs exactly once
 * (with a redacted id — never the raw `session:<id>`) and rethrows a typed
 * error, which the framework renders as a generic 500 with no RESP/connection
 * detail (T020).
 */

import { assert, assertEquals, assertRejects } from '@std/assert'
import { RedisReadError, RedisSessionDriver } from '../drivers/redis.ts'
import { startFakeRedis } from './fake_redis.ts'

const ID = 'f'.repeat(64)
const encode = (s: string): Uint8Array => new TextEncoder().encode(s)

/** Run `fn` with `console.error` captured; returns the lines it emitted. */
async function withCapturedErrors(
    fn: () => Promise<void>,
): Promise<string[]> {
    const original = console.error
    const lines: string[] = []
    console.error = (...args: unknown[]) => {
        lines.push(args.map((a) => String(a)).join(' '))
    }
    try {
        await fn()
    } finally {
        console.error = original
    }
    return lines
}

/** Preset a fake connection on the driver so no real socket is opened. */
function presetConn(driver: RedisSessionDriver, conn: Deno.Conn): void {
    // The socket now lives on the shared RedisClient's AuthenticatedConnection
    // (`client.conn.connection`), the one home for dial + handshake + self-heal.
    ;(driver as unknown as {
        client: { conn: { connection: Deno.Conn | null } }
    }).client.conn.connection = conn
}

Deno.test('redis read - a dropped connection mid-read throws (not null) and logs exactly once (SC-003)', async () => {
    const driver = new RedisSessionDriver({ hostname: '127.0.0.1', port: 1 })
    // write() accepts the frame; the read half is dead — EOF immediately.
    presetConn(driver, {
        write: (b: Uint8Array) => Promise.resolve(b.byteLength),
        read: () => Promise.resolve(null),
        close() {},
    } as unknown as Deno.Conn)

    let threw = false
    const lines = await withCapturedErrors(async () => {
        try {
            await driver.read(ID)
        } catch (error) {
            threw = error instanceof RedisReadError
        }
    })

    assert(threw, 'read threw a typed RedisReadError, not returning null')
    assertEquals(lines.length, 1, 'exactly one ERROR line')
    assert(!lines[0].includes(ID), 'the raw session id is not logged')
    assert(lines[0].includes('session#'), 'a redacted fingerprint is logged')
})

Deno.test('redis read - a wire fault discards the desynced connection so the next command reconnects', async () => {
    const driver = new RedisSessionDriver({ hostname: '127.0.0.1', port: 1 })
    let closed = false
    // write() accepts the frame; the read half is dead (EOF) — a wire desync,
    // not a framed `-ERR`. The connection must be closed and dropped so a
    // subsequent command opens a fresh one rather than reusing a poisoned socket.
    presetConn(driver, {
        write: (b: Uint8Array) => Promise.resolve(b.byteLength),
        read: () => Promise.resolve(null),
        close() {
            closed = true
        },
    } as unknown as Deno.Conn)

    await withCapturedErrors(async () => {
        await assertRejects(() => driver.read(ID), RedisReadError)
    })

    assert(closed, 'the desynced connection was closed')
    assertEquals(
        (driver as unknown as {
            client: { conn: { connection: Deno.Conn | null } }
        }).client.conn.connection,
        null,
        'the connection was discarded — the next command reconnects clean',
    )
})

Deno.test('redis read - a framed -ERR KEEPS the in-sync connection for the next command', async () => {
    // A `-ERR` reply is a complete, well-framed server error: the whole reply
    // line was read, so the socket stays in sync and the driver must reuse it.
    // The witness for the RespServerError branch — a mutant that discards on
    // every read error closes this socket and nulls the field, failing here.
    const driver = new RedisSessionDriver({ hostname: '127.0.0.1', port: 1 })
    let closed = false
    let served = false
    const conn = {
        write: (b: Uint8Array) => Promise.resolve(b.byteLength),
        read: (p: Uint8Array) => {
            if (served) return Promise.resolve(null)
            served = true
            const b = encode('-ERR server-level failure\r\n')
            p.set(b.subarray(0, p.byteLength))
            return Promise.resolve(b.byteLength)
        },
        close() {
            closed = true
        },
    } as unknown as Deno.Conn

    presetConn(driver, conn)
    await withCapturedErrors(async () => {
        await assertRejects(() => driver.read(ID), RedisReadError)
    })

    assert(!closed, 'an in-sync server error does not close the socket')
    assertEquals(
        (driver as unknown as {
            client: { conn: { connection: Deno.Conn | null } }
        }).client.conn.connection,
        conn,
        'the in-sync connection is retained for the next command',
    )
})

Deno.test('redis read - a structural framing fault DISCARDS the desynced connection', async () => {
    // An oversized bulk length: the `$<len>\r\n` line is consumed but the 11 MiB
    // payload is never drained — bytes remain on the wire and the socket is
    // desynced, so the driver must close and drop it. The witness for the
    // RespFramingError branch — a mutant that keeps on every read error leaves
    // this poisoned socket in place, failing here.
    const driver = new RedisSessionDriver({ hostname: '127.0.0.1', port: 1 })
    let closed = false
    let served = false
    const conn = {
        write: (b: Uint8Array) => Promise.resolve(b.byteLength),
        read: (p: Uint8Array) => {
            if (served) return Promise.resolve(null)
            served = true
            const b = encode(`$${11 * 1024 * 1024}\r\n`)
            p.set(b.subarray(0, p.byteLength))
            return Promise.resolve(b.byteLength)
        },
        close() {
            closed = true
        },
    } as unknown as Deno.Conn

    presetConn(driver, conn)
    await withCapturedErrors(async () => {
        await assertRejects(() => driver.read(ID), RedisReadError)
    })

    assert(closed, 'the desynced connection was closed')
    assertEquals(
        (driver as unknown as {
            client: { conn: { connection: Deno.Conn | null } }
        }).client.conn.connection,
        null,
        'the desynced connection was discarded — the next command reconnects',
    )
})

Deno.test('redis read - a GET on a missing key returns null with no log (the one legit null)', async () => {
    const redis = await startFakeRedis()
    try {
        const driver = new RedisSessionDriver({
            hostname: '127.0.0.1',
            port: redis.port,
        })
        const lines = await withCapturedErrors(async () => {
            assertEquals(await driver.read(ID), null, 'a miss is null')
        })
        assertEquals(lines.length, 0, 'a cache miss logs nothing')
        await driver.close()
    } finally {
        redis.stop()
    }
})

Deno.test('redis read - a -ERR reply throws (it is not a cache miss) and logs once', async () => {
    const driver = new RedisSessionDriver({ hostname: '127.0.0.1', port: 1 })
    let served = false
    presetConn(driver, {
        write: (b: Uint8Array) => Promise.resolve(b.byteLength),
        read: (p: Uint8Array) => {
            if (served) return Promise.resolve(null)
            served = true
            const b = encode('-ERR protocol boom\r\n')
            p.set(b.subarray(0, p.byteLength))
            return Promise.resolve(b.byteLength)
        },
        close() {},
    } as unknown as Deno.Conn)

    const lines = await withCapturedErrors(async () => {
        await assertRejects(() => driver.read(ID), RedisReadError)
    })
    assertEquals(lines.length, 1, 'exactly one ERROR line')
})

Deno.test('redis read - the thrown error is generic, carrying no RESP text or raw id to the client (T020 / FR-005)', async () => {
    const driver = new RedisSessionDriver({ hostname: '127.0.0.1', port: 1 })
    let served = false
    presetConn(driver, {
        write: (b: Uint8Array) => Promise.resolve(b.byteLength),
        read: (p: Uint8Array) => {
            if (served) return Promise.resolve(null)
            served = true
            const b = encode('-ERR NOAUTH secret-leaking detail\r\n')
            p.set(b.subarray(0, p.byteLength))
            return Promise.resolve(b.byteLength)
        },
        close() {},
    } as unknown as Deno.Conn)

    // Suppress the (expected) one ERROR log while asserting the client surface.
    const original = console.error
    console.error = () => {}
    try {
        const error = await driver.read(ID).then(
            () => {
                throw new Error('expected read to reject')
            },
            (e) => e,
        )
        assert(error instanceof RedisReadError, 'a typed error')
        // The framework renders `message` (see @lockness/contract renderError,
        // which ignores cause/stack) → a generic 500.
        assertEquals(error.message, 'session read failed')
        assert(
            !error.message.includes('NOAUTH'),
            'no RESP text reaches the client-facing message',
        )
        assert(!error.message.includes(ID), 'no raw id in the message')
    } finally {
        console.error = original
    }
})
