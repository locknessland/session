/**
 * The Redis driver over the wire — what bytes actually leave the socket.
 *
 * These drive the real `RedisSessionDriver` against the verifying fake in
 * `resp_server.ts`, which parses by declared bulk length and so can tell a
 * correct frame from the #141 under-declared one. A fake that split on CRLF
 * would accept both and prove nothing (plan §9, top risk). Every test checks
 * `obs.error === null` first, so a truncated capture can never be read as a
 * complete observation.
 *
 * SC-004 mutation record — measured 2026-09-01: mutating the encoder
 * `bytes.byteLength → arg.length` in `packages/redis/resp.ts` gives **5 failed
 * / 8 passed** across resp.test.ts + redis_wire.test.ts. The five falsifiers are
 * every test that carries a non-ASCII argument; the timeout below turns what
 * would be a driver hang into a clean 3s failure:
 *   - FR-008 "AUTH with a non-ASCII password …" — the mutated $2 AUTH frame
 *     parses malformed at the fake, leaving a stray byte the parser cannot
 *     re-enter from, so the following SETEX never gets a reply and the driver's
 *     read stalls; `withTimeout` fails it (3s).
 *   - FR-009 "a non-ASCII session value is one command …" — same stall on the
 *     desynced SETEX (3s).
 *   - SC-001 "a non-ASCII session round-trips …" — its SETEX also carries the
 *     non-ASCII value, so it stalls the same way (3s).
 *   - FR-007 "a non-ASCII argument declares its UTF-8 byte length" and the
 *     surrogate-pair test in resp.test.ts — fail instantly on the byte diff.
 * The eight that stay GREEN pin invariants this mutation does not break — the
 * empty-string, pure-ASCII and CRLF encodes (the two encodings agree on ASCII),
 * both writeFrame tests, the FR-006 surface test, the oracle-negative test
 * (it hand-builds the broken frame, so it does not depend on the encoder), and
 * FR-004a. They are not this mutation's falsifiers, and not defective.
 */

import { assertEquals, assertRejects } from '@std/assert'
import { RedisSessionDriver } from '../drivers/redis.ts'
import { readReply } from '@lockness/redis'
import { startRespServer } from './resp_server.ts'
import { startFakeRedis } from './fake_redis.ts'

/**
 * Bound a wire operation in time. A correct driver completes in milliseconds;
 * a desynced one (e.g. under the SC-004 mutation, where the fake cannot parse
 * the under-declared frame and never replies) would otherwise block the
 * driver's `read()` forever. The timeout turns that hang into a clean failure,
 * which is what the mutation gate needs and what keeps a future desync
 * regression from wedging CI.
 */
function withTimeout<T>(work: Promise<T>, ms = 3000): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const guard = new Promise<never>((_, reject) => {
        timer = setTimeout(
            () =>
                reject(new Error(`wire operation exceeded ${ms}ms — desync?`)),
            ms,
        )
    })
    return Promise.race([work, guard]).finally(() =>
        clearTimeout(timer)
    ) as Promise<T>
}

Deno.test('redis wire - AUTH with a non-ASCII password declares its UTF-8 byte length', async () => {
    const server = await startRespServer()
    try {
        // 'pÿ' is 2 UTF-16 units, 3 UTF-8 bytes. The broken encoder wrote $2.
        const driver = new RedisSessionDriver({
            hostname: '127.0.0.1',
            port: server.port,
            password: 'pÿ',
        })
        await withTimeout(driver.write('a'.repeat(64), { ok: 1 }, 3600))
        await withTimeout(driver.close())

        const obs = await server.done()
        assertEquals(obs.error, null, 'the server captured the whole stream')
        // connect() sends AUTH first, then the SETEX; default db=0 → no SELECT.
        assertEquals(obs.commands[0].args, ['AUTH', 'pÿ'])
        assertEquals(
            obs.commands[0].wellTerminated,
            true,
            'the password bulk string was followed by a real CRLF',
        )
        assertEquals(obs.trailing.byteLength, 0, 'no bytes were left unparsed')
    } finally {
        server.stop()
    }
})

Deno.test('redis wire - a non-ASCII session value is one command, consumed whole', async () => {
    const server = await startRespServer()
    try {
        const driver = new RedisSessionDriver({
            hostname: '127.0.0.1',
            port: server.port,
        })
        // The injection shape: a non-ASCII run in front of an ASCII command.
        // Through the value path this is JSON.stringify'd; correctly length-
        // prefixed, it is inert data — one SETEX, nothing after it.
        await withTimeout(driver.write(
            'c'.repeat(64),
            { n: 'é'.repeat(20) + 'SET INJECTED yes' },
            3600,
        ))
        await withTimeout(driver.close())

        const obs = await server.done()
        assertEquals(obs.error, null, 'the server captured the whole stream')
        const nonQuit = obs.commands.filter((c) => c.args[0] !== 'QUIT')
        assertEquals(
            nonQuit.map((c) => c.args[0]),
            ['SETEX'],
            'exactly one storage command reached the server — no injected second command',
        )
        assertEquals(nonQuit[0].wellTerminated, true)
        assertEquals(
            obs.trailing.byteLength,
            0,
            'nothing parsed past the frame',
        )
    } finally {
        server.stop()
    }
})

Deno.test('redis wire - a non-ASCII session round-trips: write then read the same value (SC-001)', async () => {
    // The read direction. The fake replies with a bulk string carrying a
    // non-ASCII JSON payload; the driver must GET it and decode it intact. The
    // write is proven byte-exact by the tests above; this proves the cycle.
    const stored = JSON.stringify({ name: 'Renée', role: 'admin' })
    const replyBytes = new TextEncoder().encode(stored)
    const server = await startRespServer(
        `$${replyBytes.byteLength}\r\n${stored}\r\n`,
    )
    try {
        const driver = new RedisSessionDriver({
            hostname: '127.0.0.1',
            port: server.port,
        })
        await withTimeout(
            driver.write(
                'e'.repeat(64),
                { name: 'Renée', role: 'admin' },
                3600,
            ),
        )
        const readBack = await withTimeout(driver.read('e'.repeat(64)))
        await withTimeout(driver.close())

        const obs = await server.done()
        assertEquals(obs.error, null, 'the server captured the whole stream')
        assertEquals(
            readBack,
            { name: 'Renée', role: 'admin' },
            'the non-ASCII value survived the write→read cycle',
        )
        // Both the SETEX and the GET reached the server as one command each.
        const nonQuit = obs.commands.filter((c) => c.args[0] !== 'QUIT')
        assertEquals(nonQuit.map((c) => c.args[0]), ['SETEX', 'GET'])
        assertEquals(nonQuit.every((c) => c.wellTerminated), true)
        assertEquals(obs.trailing.byteLength, 0)
    } finally {
        server.stop()
    }
})

Deno.test('redis wire - the fake can tell the broken frame apart (oracle negative test)', async () => {
    // Feed the fake the frame the PRE-FIX encoder built for the same command,
    // raw. If the oracle could not distinguish it from a correct frame, every
    // test above would be worthless. The detection is pinned to the EXACT
    // shape the defect takes, not a loose disjunction any truncated stream
    // would satisfy: one command, ill-terminated, with the injected tail left
    // over verbatim.
    const server = await startRespServer()
    try {
        const enc = new TextEncoder()
        const args = [
            'SETEX',
            'session:' + 'a'.repeat(56),
            '3600',
            'é'.repeat(13) + 'SET pwned 1',
        ]
        // The bug: length prefix = arg.length (UTF-16 units), not byteLength.
        let broken = `*${args.length}\r\n`
        for (const a of args) broken += `$${a.length}\r\n${a}\r\n`

        const client = await Deno.connect({
            hostname: '127.0.0.1',
            port: server.port,
        })
        await client.write(enc.encode(broken))
        // Deterministic: the fake replies +OK once it has parsed the (malformed)
        // SETEX. Waiting for that byte proves the whole frame arrived, replacing
        // a fixed sleep that a slow scheduler could cut short.
        const ack = new Uint8Array(8)
        await withTimeout(client.read(ack) as Promise<unknown>)
        client.close()

        const obs = await server.done()
        assertEquals(obs.error, null, 'the server captured the whole stream')
        assertEquals(
            obs.commands.length,
            1,
            'the multibulk parsed as one command',
        )
        assertEquals(
            obs.commands[0].wellTerminated,
            false,
            'the under-declared value left a non-CRLF where the terminator should be',
        )
        assertEquals(
            new TextDecoder().decode(obs.trailing),
            'SET pwned 1\r\n',
            'the injected tail is exactly what a length-honouring parser leaves over',
        )
    } finally {
        server.stop()
    }
})

Deno.test('redis wire - a write failure closes and discards the connection so the next command reconnects (FR-004a)', async () => {
    const driver = new RedisSessionDriver({ hostname: '127.0.0.1', port: 1 })

    // Preset a connection whose write always rejects. connect() returns it as
    // already-established, so the command writes into the failing socket.
    // The socket lives on the shared RedisClient's AuthenticatedConnection
    // (`client.conn.connection`) — the pinned private teardown contract.
    let closed = false
    const failing = {
        write: () => Promise.reject(new Error('BrokenPipe')),
        close: () => {
            closed = true
        },
    } as unknown as Deno.Conn
    const internal = (driver as unknown as {
        client: { conn: { connection: Deno.Conn | null } }
    }).client.conn
    internal.connection = failing

    await assertRejects(
        () => driver.destroy('d'.repeat(64)),
        Error,
        'BrokenPipe',
    )
    assertEquals(
        closed,
        true,
        'the poisoned socket was closed, not leaked',
    )
    assertEquals(
        internal.connection,
        null,
        'and discarded, so the next command cannot reuse it',
    )
    // A second call must not reuse it — it reconnects, and port 1 refuses.
    await assertRejects(
        () => withTimeout(driver.destroy('d'.repeat(64))),
        Deno.errors.ConnectionRefused,
    )
})

// =============================================================================
// US4 — a large session round-trips, and a split bulk body reassembles (SC-004)
// =============================================================================

Deno.test('redis wire - a >8KB session value round-trips byte-identical (SC-004)', async () => {
    // The reply is far larger than one 4096-byte read; a single-shot reader
    // truncates it and JSON.parse throws. The drained reader reassembles it.
    const redis = await startFakeRedis()
    try {
        const driver = new RedisSessionDriver({
            hostname: '127.0.0.1',
            port: redis.port,
        })
        const data = { blob: 'x'.repeat(9000), n: 7 } // serialized > 8192 bytes
        await withTimeout(driver.write('g'.repeat(64), data, 3600))
        const readBack = await withTimeout(driver.read('g'.repeat(64)))
        await withTimeout(driver.close())

        assertEquals(
            readBack,
            data,
            'the large value survived write→read intact',
        )
    } finally {
        redis.stop()
    }
})

Deno.test('redis wire - a bulk body split across two reads reassembles (SC-004 split-read)', async () => {
    // The fake conn delivers the header + first half in one read and the rest in
    // a second read, so only a draining reader completes the frame.
    const enc = new TextEncoder()
    const body = 'y'.repeat(5000) // one bulk value, spanning multiple reads
    const full = enc.encode(`$${body.length}\r\n${body}\r\n`)
    const splitAt = 2010 // mid-body, past the length prefix
    const queue = [full.subarray(0, splitAt), full.subarray(splitAt)]
    const conn = {
        read(p: Uint8Array): Promise<number | null> {
            if (queue.length === 0) return Promise.resolve(null)
            const chunk = queue[0]
            const n = Math.min(chunk.byteLength, p.byteLength)
            p.set(chunk.subarray(0, n))
            if (n < chunk.byteLength) queue[0] = chunk.subarray(n)
            else queue.shift()
            return Promise.resolve(n)
        },
        close() {},
    } as unknown as Deno.Conn

    const reply = await withTimeout(readReply(conn))
    assertEquals(reply, { type: 'bulk', value: body })
})
