/**
 * @fileoverview A fake RESP server for driving the Redis driver over loopback.
 *
 * This is the one oracle for the wire tests (plan §5, feature 007). It exists
 * to answer two questions about the bytes a client actually sent, and it MUST
 * answer them from the bytes — never by importing `encodeCommand`, which would
 * make the test ask the encoder whether the encoder is right.
 *
 * 1. **Does each `$N` bulk-length prefix match the bytes that follow it?** The
 *    #141 defect is a prefix shorter than its payload, so a fake that reads the
 *    payload by splitting on CRLF instead of honouring `N` would accept the
 *    broken frame and prove nothing. This parser reads exactly `N` bytes and
 *    records whether the two bytes after them are CRLF.
 * 2. **How many complete commands were in the stream, and were any bytes left
 *    over?** One client command must parse as exactly one server command with
 *    no trailing bytes; the injection surfaces here as a second parsed command.
 *
 * @module @lockness/session/tests/resp_server
 */

/** One command the fake parsed off the wire, as decoded argument strings. */
export interface ParsedCommand {
    /** The command's arguments, each decoded from its bulk string's bytes. */
    args: string[]
    /**
     * True when every bulk string in this command was followed by a literal
     * CRLF. The #141 frame lands the next command mid-payload, so a command
     * parsed out of the surplus reads this as `false`.
     */
    wellTerminated: boolean
}

/** What the fake observed for one accepted connection. */
export interface Observation {
    /** Every byte received on the connection, in order. */
    raw: Uint8Array
    /** Each complete command parsed by declared bulk length. */
    commands: ParsedCommand[]
    /** Bytes after the last complete command that did not parse. */
    trailing: Uint8Array
    /**
     * An error the server hit that was NOT a clean client disconnect, or
     * `null`. A test asserting on `commands` / `trailing` must check this
     * first: a truncated capture reported as complete is exactly how a broken
     * oracle passes (plan §9 top risk).
     */
    error: Error | null
}

/**
 * Parse a RESP2 byte stream by declared bulk length.
 *
 * Multibulk only (`*` frames) — the driver sends nothing else. Each `$N` reads
 * exactly `N` bytes as the argument, then notes whether the following two bytes
 * are CRLF, then advances past them. Parsing stops at the first byte that does
 * not begin a `*` frame or that runs past the buffer; whatever remains is
 * `trailing`.
 *
 * @param raw - The bytes received.
 * @returns The commands parsed and any unparsed trailing bytes.
 */
function parse(raw: Uint8Array): {
    commands: ParsedCommand[]
    trailing: Uint8Array
} {
    const decoder = new TextDecoder()
    const commands: ParsedCommand[] = []
    let pos = 0

    const readLine = (): string | null => {
        const start = pos
        while (pos < raw.byteLength && raw[pos] !== 0x0d /* \r */) pos++
        if (pos + 1 >= raw.byteLength || raw[pos + 1] !== 0x0a /* \n */) {
            return null
        }
        const line = decoder.decode(raw.subarray(start, pos))
        pos += 2
        return line
    }

    while (pos < raw.byteLength) {
        if (raw[pos] !== 0x2a /* * */) break
        const startOfCommand = pos
        pos++ // consume '*'
        const countLine = readLine()
        if (countLine === null) {
            pos = startOfCommand
            break
        }
        const count = Number(countLine)

        const args: string[] = []
        let wellTerminated = true
        let complete = true
        for (let i = 0; i < count; i++) {
            const lenLine = readLine()
            if (lenLine === null || lenLine[0] !== '$') {
                complete = false
                break
            }
            const n = Number(lenLine.slice(1))
            // Need the N payload bytes AND the two terminator bytes, or the
            // frame is truncated. Checking only `pos + n` would report a frame
            // cut off exactly at its final CRLF as complete with no trailing.
            if (pos + n + 2 > raw.byteLength) {
                complete = false
                break
            }
            args.push(decoder.decode(raw.subarray(pos, pos + n)))
            const term = raw.subarray(pos + n, pos + n + 2)
            if (term[0] !== 0x0d || term[1] !== 0x0a) wellTerminated = false
            pos += n + 2 // advance by n + 2, honouring the declared length
        }

        if (!complete) {
            pos = startOfCommand
            break
        }
        commands.push({ args, wellTerminated })
    }

    return { commands, trailing: raw.subarray(pos) }
}

/** A running fake RESP server handle. */
export interface RespServer {
    /** The loopback port the server is listening on. */
    port: number
    /** Resolves with the observation once the client connection closes. */
    done(): Promise<Observation>
    /** Close the listener; safe to call more than once. */
    stop(): void
}

/**
 * Start a fake RESP server on a fresh loopback port.
 *
 * Accepts one connection, replies with `reply` once per complete command it
 * parses so the client's per-command read resolves, records every byte, and
 * exposes the parse — plus any non-disconnect error — once the client closes.
 *
 * @param reply - The bytes to write back for each command the client sends.
 *   Defaults to `+OK\r\n`. Pass a bulk-string reply (e.g. `$2\r\nhi\r\n`) to
 *   drive `RedisSessionDriver.read`.
 * @returns The running server handle.
 * @example
 * ```typescript
 * const server = await startRespServer()
 * try {
 *   const driver = new RedisSessionDriver({ hostname: '127.0.0.1', port: server.port })
 *   await driver.write('a'.repeat(64), { name: 'Renée' }, 3600)
 *   await driver.close()
 *   const obs = await server.done()
 *   assertEquals(obs.error, null)
 *   assertEquals(obs.commands.length, 1)
 * } finally {
 *   server.stop()
 * }
 * ```
 */
export function startRespServer(
    reply: string = '+OK\r\n',
): Promise<RespServer> {
    const listener = Deno.listen({ hostname: '127.0.0.1', port: 0 })
    const port = (listener.addr as Deno.NetAddr).port
    const replyBytes = new TextEncoder().encode(reply)

    let resolveDone!: (o: Observation) => void
    const donePromise = new Promise<Observation>((r) => (resolveDone = r))
    let repliedFor = 0
    let listenerClosed = false
    ;(async () => {
        const chunks: number[] = []
        let error: Error | null = null
        let conn: Deno.Conn | null = null
        try {
            conn = await listener.accept()
            const buf = new Uint8Array(4096)
            while (true) {
                const n = await conn.read(buf)
                if (n === null) break
                for (let i = 0; i < n; i++) chunks.push(buf[i])
                // Reply once per newly-completed command so the client's
                // per-command read resolves and it can proceed.
                const seen = parse(new Uint8Array(chunks)).commands.length
                for (let i = repliedFor; i < seen; i++) {
                    await conn.write(replyBytes)
                }
                repliedFor = Math.max(repliedFor, seen)
            }
        } catch (caught) {
            // A closed listener/conn after `stop()` is the normal end of a
            // test; anything else is a real failure the observation must carry,
            // so a truncated capture is never read as a complete one.
            const e = caught instanceof Error
                ? caught
                : new Error(String(caught))
            const benign = e instanceof Deno.errors.BadResource ||
                e instanceof Deno.errors.Interrupted ||
                e instanceof Deno.errors.ConnectionReset
            if (!benign) error = e
        } finally {
            conn?.close()
        }
        const raw = new Uint8Array(chunks)
        const { commands, trailing } = parse(raw)
        resolveDone({ raw, commands, trailing, error })
    })()

    return Promise.resolve({
        port,
        done: () => donePromise,
        stop: () => {
            if (listenerClosed) return
            listenerClosed = true
            listener.close()
        },
    })
}
