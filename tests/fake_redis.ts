/**
 * @fileoverview A small stateful fake Redis for the session driver tests.
 *
 * The verifying `resp_server.ts` records what bytes were sent but holds no
 * state, so it cannot answer "does the new id read back the data, and is the old
 * id gone?" (FR-008 / Security S2) or "did a full login round-trip succeed?"
 * (FR-009). This double keeps a real key→value map and answers the subset of
 * commands the driver issues — `AUTH`, `SELECT`, `PING`, `GET`, `SET`, `SETEX`,
 * `DEL`, `EVAL`, `QUIT`. It parses the wire **by declared bulk length**, like
 * `resp_server.ts`, so it never imports `encodeCommand`.
 *
 * `EVAL` **interprets the script text it receives** (`args[1]`), not a hardcoded
 * rotation: it walks each `redis.call('OP', …)` the script names, in order,
 * resolving `KEYS[n]` / `ARGV[n]` / string literals / a `local` bound from a
 * prior `GET`, and applies ONLY the ops the script actually contains. So a
 * production script that drops `DEL KEYS[1]` makes the double stop deleting too,
 * and the fixation/atomicity/e2e destroy-path assertions go red — the destroy
 * path is genuinely falsifiable on Redis, not validated against a fake that
 * always rotates (HIGH review finding; SC-005 / Security S2). `setFailEval(true)`
 * makes the next `EVAL` reply an error without touching the store, so an
 * atomicity test can assert the both-or-neither outcome (SC-007).
 *
 * @module @lockness/session/tests/fake_redis
 */

const encoder = new TextEncoder()
const decoder = new TextDecoder()

/** A running fake Redis handle. */
export interface FakeRedis {
    /** The loopback port the server is listening on. */
    port: number
    /** The backing store: Redis key (`session:<id>`) → stored value. */
    store: Map<string, string>
    /** Make the next `EVAL` reply an error and leave the store untouched. */
    setFailEval(fail: boolean): void
    /** Close the listener and any live connection; safe to call twice. */
    stop(): void
}

/**
 * Parse exactly one multibulk (`*`) command from `buf` starting at `pos`,
 * honouring each `$N` declared length. Returns the decoded args and the offset
 * just past the command, or `null` if the buffer does not yet hold a full
 * command.
 */
function parseOne(
    buf: Uint8Array,
    pos: number,
): { args: string[]; next: number } | null {
    if (pos >= buf.byteLength || buf[pos] !== 0x2a /* * */) return null
    let p = pos + 1

    const readLine = (): string | null => {
        const start = p
        while (p < buf.byteLength && buf[p] !== 0x0d /* \r */) p++
        if (p + 1 >= buf.byteLength || buf[p + 1] !== 0x0a /* \n */) return null
        const line = decoder.decode(buf.subarray(start, p))
        p += 2
        return line
    }

    const countLine = readLine()
    if (countLine === null) return null
    const count = Number(countLine)
    const args: string[] = []
    for (let i = 0; i < count; i++) {
        const lenLine = readLine()
        if (lenLine === null || lenLine[0] !== '$') return null
        const n = Number(lenLine.slice(1))
        if (p + n + 2 > buf.byteLength) return null
        args.push(decoder.decode(buf.subarray(p, p + n)))
        p += n + 2 // advance past payload + CRLF, honouring the declared length
    }
    return { args, next: p }
}

/**
 * Interpret the subset of a Lua `EVAL` body the session driver ever sends —
 * a sequence of `redis.call('OP', …)` invocations — against `store`.
 *
 * This does NOT reimplement the regenerate script from memory; it reads the
 * script text and applies exactly the ops it names, so dropping a `redis.call`
 * from the production script changes what the fake does. Supported ops: `GET`
 * (optionally bound to a `local`), `SET key value ['EX' ttl]`, `DEL key`. Calls
 * inside an `if <var> then … end` run only when that var resolved to a value —
 * modelling the script's "rotate only if the old key exists" guard.
 *
 * Argument tokens resolve as `KEYS[n]` / `ARGV[n]` (1-based) from the EVAL's
 * key/argv arrays, a `'literal'`, or a variable bound by an earlier `GET`.
 *
 * @param script - The Lua source passed as `EVAL`'s first argument.
 * @param keys - The `KEYS` array (the numkeys operands).
 * @param argv - The `ARGV` array (operands past the keys).
 * @param store - The backing key→value map to mutate.
 */
function runEvalScript(
    script: string,
    keys: string[],
    argv: string[],
    store: Map<string, string>,
): void {
    const vars = new Map<string, string | undefined>()
    const resolve = (raw: string): string | undefined => {
        const tok = raw.trim()
        const keyMatch = tok.match(/^KEYS\[(\d+)\]$/)
        if (keyMatch) return keys[Number(keyMatch[1]) - 1]
        const argMatch = tok.match(/^ARGV\[(\d+)\]$/)
        if (argMatch) return argv[Number(argMatch[1]) - 1]
        const litMatch = tok.match(/^'([^']*)'$/)
        if (litMatch) return litMatch[1]
        return vars.get(tok)
    }

    // The one `if <var> then … end` guard the regenerate script uses. Calls
    // whose position falls inside it run only when the guard var is truthy.
    const ifMatch = script.match(/\bif\s+(\w+)\s+then\b/)
    const guardVar = ifMatch ? ifMatch[1] : null
    const thenIdx = script.search(/\bthen\b/)
    const endIdx = script.search(/\bend\b/)

    const callRe =
        /(?:local\s+(\w+)\s*=\s*)?redis\.call\(\s*'(\w+)'\s*(?:,\s*([^)]*))?\)/g
    for (let m = callRe.exec(script); m !== null; m = callRe.exec(script)) {
        const bind = m[1]
        const op = m[2].toUpperCase()
        const operands = m[3] ? m[3].split(',').map((s) => s.trim()) : []

        const inGuard = guardVar !== null && thenIdx !== -1 &&
            m.index > thenIdx && (endIdx === -1 || m.index < endIdx)
        // Lua treats only `nil`/`false` as falsy — an empty-string GET is
        // TRUTHY. The guard var is bound from a prior `GET`, so it is either a
        // string (present, including `''`) or `undefined` (the key missed → Lua
        // nil). Guard on presence, not JS truthiness, or an empty stored session
        // value would wrongly skip the rotation the production script runs.
        if (inGuard && vars.get(guardVar) === undefined) continue

        switch (op) {
            case 'GET': {
                const value = store.get(resolve(operands[0]) ?? '')
                if (bind) vars.set(bind, value)
                break
            }
            case 'SET': {
                const key = resolve(operands[0])
                const value = resolve(operands[1])
                if (key !== undefined && value !== undefined) {
                    store.set(key, value)
                }
                break
            }
            case 'DEL': {
                const key = resolve(operands[0])
                if (key !== undefined) store.delete(key)
                break
            }
            default:
                // The driver sends no other op inside EVAL; ignore anything
                // unexpected rather than guess at its effect.
                break
        }
    }
}

const simple = (s: string): Uint8Array => encoder.encode(`+${s}\r\n`)
const error = (s: string): Uint8Array => encoder.encode(`-${s}\r\n`)
const integer = (n: number): Uint8Array => encoder.encode(`:${n}\r\n`)
const bulk = (s: string | null): Uint8Array =>
    s === null
        ? encoder.encode('$-1\r\n')
        : encoder.encode(`$${encoder.encode(s).byteLength}\r\n${s}\r\n`)

/**
 * Start a stateful fake Redis on a fresh loopback port.
 *
 * @returns The running handle (port, store, `setFailEval`, `stop`).
 * @example
 * ```typescript
 * const redis = await startFakeRedis()
 * try {
 *   const driver = new RedisSessionDriver({ hostname: '127.0.0.1', port: redis.port })
 *   await driver.write('a'.repeat(64), { userId: 1 }, 3600)
 *   await driver.close()
 * } finally {
 *   redis.stop()
 * }
 * ```
 */
export function startFakeRedis(): Promise<FakeRedis> {
    const listener = Deno.listen({ hostname: '127.0.0.1', port: 0 })
    const port = (listener.addr as Deno.NetAddr).port
    const store = new Map<string, string>()
    let failEval = false
    let listenerClosed = false
    let liveConn: Deno.Conn | null = null

    const handle = (args: string[]): { reply: Uint8Array; quit: boolean } => {
        const cmd = (args[0] ?? '').toUpperCase()
        switch (cmd) {
            case 'AUTH':
            case 'SELECT':
                return { reply: simple('OK'), quit: false }
            case 'PING':
                return { reply: simple('PONG'), quit: false }
            case 'GET':
                return { reply: bulk(store.get(args[1]) ?? null), quit: false }
            case 'SET': {
                store.set(args[1], args[2])
                return { reply: simple('OK'), quit: false }
            }
            case 'SETEX': {
                const ttl = Number(args[2])
                if (!Number.isFinite(ttl) || ttl <= 0) {
                    // Real Redis rejects a non-positive expire — this is exactly
                    // the pre-#139 `SETEX <key> 0` login-500.
                    return {
                        reply: error('ERR invalid expire time in setex'),
                        quit: false,
                    }
                }
                store.set(args[1], args[3])
                return { reply: simple('OK'), quit: false }
            }
            case 'DEL': {
                const existed = store.delete(args[1])
                return { reply: integer(existed ? 1 : 0), quit: false }
            }
            case 'EVAL': {
                if (failEval) {
                    return {
                        reply: error('ERR forced eval failure'),
                        quit: false,
                    }
                }
                // EVAL script numkeys k1..kN a1..aM. Split KEYS from ARGV by the
                // declared numkeys, then run the ops the SCRIPT names — never a
                // hardcoded rotation (HIGH review finding).
                const script = args[1] ?? ''
                const numKeys = Number(args[2])
                const keys = args.slice(3, 3 + numKeys)
                const argv = args.slice(3 + numKeys)
                runEvalScript(script, keys, argv, store)
                return { reply: integer(1), quit: false }
            }
            case 'QUIT':
                return { reply: simple('OK'), quit: true }
            default:
                return {
                    reply: error(`ERR unknown command '${cmd}'`),
                    quit: false,
                }
        }
    }
    ;(async () => {
        let conn: Deno.Conn | null = null
        try {
            conn = await listener.accept()
            liveConn = conn
            let buf = new Uint8Array(0)
            const chunk = new Uint8Array(4096)
            while (true) {
                const n = await conn.read(chunk)
                if (n === null) break
                const merged = new Uint8Array(buf.byteLength + n)
                merged.set(buf)
                merged.set(chunk.subarray(0, n), buf.byteLength)
                buf = merged

                let pos = 0
                let quitting = false
                while (true) {
                    const parsed = parseOne(buf, pos)
                    if (parsed === null) break
                    pos = parsed.next
                    const { reply, quit } = handle(parsed.args)
                    await conn.write(reply)
                    if (quit) {
                        quitting = true
                        break
                    }
                }
                buf = buf.subarray(pos)
                if (quitting) break
            }
        } catch {
            // A closed listener/conn after `stop()` is the normal end of a test;
            // nothing here needs to surface — assertions are on `store`.
        } finally {
            try {
                conn?.close()
            } catch {
                // Already closed by the client's QUIT or by stop().
            }
            liveConn = null
        }
    })()

    return Promise.resolve({
        port,
        store,
        setFailEval: (fail: boolean) => {
            failEval = fail
        },
        stop: () => {
            if (listenerClosed) return
            listenerClosed = true
            try {
                liveConn?.close()
            } catch {
                // Already closed.
            }
            listener.close()
        },
    })
}
