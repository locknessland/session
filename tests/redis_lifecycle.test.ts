/**
 * @fileoverview Redis driver lifecycle under the shared-socket model (#145).
 *
 * Single-flight connect (FR-004), the shutdown close path (SC-005/FR-009), the
 * QUIT-vs-in-flight ordering (FR-008), and both self-heal branches — a connect
 * rejection and a mid-stream command failure (SC-006/FR-005). `Deno.connect` is
 * stubbed via `Object.defineProperty`, the same pattern `driver_memo.test.ts`
 * uses for `Deno.openKv`, to count opens and to inject failures.
 *
 * @module @lockness/session/tests/redis_lifecycle
 */

import { assertEquals } from '@std/assert'
import { RedisSessionDriver } from '../drivers/redis.ts'
import { startFakeRedis } from './fake_redis.ts'

const id = (n: number): string => String(n).padStart(64, '0')

/**
 * Replace `Deno.connect` with `value`, run `body`, and always restore it.
 * Centralises the defineProperty dance every lifecycle test needs.
 */
async function withConnectStub(
    // deno-lint-ignore no-explicit-any
    value: (opts: any) => Promise<Deno.Conn>,
    body: () => Promise<void>,
): Promise<void> {
    const real = Deno.connect
    Object.defineProperty(Deno, 'connect', { configurable: true, value })
    try {
        await body()
    } finally {
        Object.defineProperty(Deno, 'connect', {
            configurable: true,
            value: real,
        })
    }
}

/**
 * connect() lives on the RedisClient the driver composes; TS-`private`
 * (compile-time only), reachable at runtime for a unit test.
 */
type Connectable = { connect(): Promise<Deno.Conn> }

Deno.test('redis lifecycle - connect() is single-flighted: concurrent callers open ONE socket (FR-004)', async () => {
    // The command mutex serializes reads, so a burst of READS alone cannot prove
    // the single-flight — the mutex would keep connects==1 even without the
    // guard (review H1). So drive connect() DIRECTLY and concurrently, with a
    // slow Deno.connect that lets both callers enter before the first resolves.
    // With the connectPromise guard: one open. Remove it: two. Genuinely
    // falsifiable.
    const redis = await startFakeRedis()
    const real = Deno.connect
    let opens = 0
    await withConnectStub(
        (opts) => {
            opens++
            return new Promise((resolve) =>
                setTimeout(() => resolve(real(opts)), 25)
            )
        },
        async () => {
            const driver = new RedisSessionDriver({
                hostname: '127.0.0.1',
                port: redis.port,
            })
            const connectable =
                (driver as unknown as { client: Connectable }).client
            await Promise.all([connectable.connect(), connectable.connect()])
            assertEquals(
                opens,
                1,
                'two concurrent connect() calls opened exactly one socket',
            )
            await driver.close()
        },
    )
    redis.stop()
})

Deno.test('redis lifecycle - a burst of reads opens ONE connection and issues AUTH once (SC-001)', async () => {
    const redis = await startFakeRedis()
    for (let i = 0; i < 6; i++) {
        redis.store.set(`session:${id(i)}`, JSON.stringify({ i }))
    }
    const real = Deno.connect
    let opens = 0
    await withConnectStub(
        (opts) => {
            opens++
            return real(opts)
        },
        async () => {
            // AUTH is unconditionally the first thing inside connect(), so one
            // open ⇒ one AUTH. The user-facing guarantee (SC-001) holds via the
            // serialization; the single-flight guard is tested above.
            const driver = new RedisSessionDriver({
                hostname: '127.0.0.1',
                port: redis.port,
                password: 's3cret',
            })
            await Promise.all(
                Array.from({ length: 6 }, (_, i) => driver.read(id(i))),
            )
            assertEquals(
                opens,
                1,
                'the burst opened one TCP connection (and thus one AUTH)',
            )
            await driver.close()
        },
    )
    redis.stop()
})

Deno.test('redis lifecycle - close() closes the socket, is idempotent, and QUIT does not reopen (SC-005/FR-009)', async () => {
    const redis = await startFakeRedis()
    redis.store.set(`session:${id(1)}`, JSON.stringify({ v: 1 }))
    const real = Deno.connect
    let opens = 0
    await withConnectStub(
        (opts) => {
            opens++
            return real(opts)
        },
        async () => {
            const driver = new RedisSessionDriver({
                hostname: '127.0.0.1',
                port: redis.port,
            })
            await driver.read(id(1)) // opens the socket
            assertEquals(opens, 1, 'one socket opened')
            await driver.close() // QUIT + socket close
            await driver.close() // idempotent: no live socket, must not throw or reopen
            assertEquals(opens, 1, 'close() did not reopen a socket')
        },
    )
    redis.stop()
})

Deno.test('redis lifecycle - close() QUIT drains after an in-flight command, not through it (FR-008)', async () => {
    const redis = await startFakeRedis()
    redis.store.set(`session:${id(3)}`, JSON.stringify({ v: 3 }))
    const driver = new RedisSessionDriver({
        hostname: '127.0.0.1',
        port: redis.port,
    })
    try {
        // Start a read and close() WITHOUT awaiting the read first. close()'s
        // QUIT serializes through the same command queue, so it runs after the
        // read's exchange — the read must complete with its own value, not be
        // torn out by the QUIT/socket-close.
        const [data] = await Promise.all([driver.read(id(3)), driver.close()])
        assertEquals(
            (data as { v: number }).v,
            3,
            'the in-flight read finished intact before QUIT',
        )
    } finally {
        redis.stop()
    }
})

Deno.test('redis lifecycle - a connect rejection self-heals on the next command (SC-006/FR-005)', async () => {
    const redis = await startFakeRedis()
    redis.store.set(`session:${id(4)}`, JSON.stringify({ up: true }))
    const real = Deno.connect
    let opens = 0
    await withConnectStub(
        (opts) => {
            opens++
            // The FIRST connect rejects (a refused/blipped dial); the retry works.
            if (opens === 1) {
                return Promise.reject(new Error('connection refused'))
            }
            return real(opts)
        },
        async () => {
            const driver = new RedisSessionDriver({
                hostname: '127.0.0.1',
                port: redis.port,
            })
            let firstThrew = false
            try {
                await driver.read(id(4))
            } catch {
                firstThrew = true
            }
            assertEquals(
                firstThrew,
                true,
                'the connect rejection surfaced (not swallowed as a miss)',
            )
            // connectPromise was dropped on rejection, so the next read reopens.
            const data = await driver.read(id(4))
            assertEquals(
                (data as { up: boolean }).up,
                true,
                'the retry opened a fresh socket and read',
            )
            assertEquals(
                opens,
                2,
                'exactly one retry — the rejected connect was not cached forever',
            )
            await driver.close()
        },
    )
    redis.stop()
})

Deno.test('redis lifecycle - a mid-stream command failure self-heals on the next command (SC-006/FR-005)', async () => {
    const redis = await startFakeRedis()
    redis.store.set(`session:${id(2)}`, JSON.stringify({ recovered: true }))
    const real = Deno.connect
    let opens = 0
    await withConnectStub(
        (opts) => {
            opens++
            if (opens === 1) {
                // First socket: writes accept, but the read faults mid-stream —
                // a wire fault that desyncs the socket (not a RespServerError).
                return Promise.resolve({
                    write: (p: Uint8Array) => Promise.resolve(p.byteLength),
                    read: () => Promise.reject(new Error('connection reset')),
                    close: () => {},
                } as unknown as Deno.Conn)
            }
            return real(opts) // the retry gets a real, working socket
        },
        async () => {
            const driver = new RedisSessionDriver({
                hostname: '127.0.0.1',
                port: redis.port,
            })
            let firstThrew = false
            try {
                await driver.read(id(2))
            } catch {
                firstThrew = true
            }
            assertEquals(
                firstThrew,
                true,
                'the mid-stream fault surfaced (not swallowed as a miss)',
            )
            // The desync-close path dropped connection AND connectPromise, so
            // this read reconnects on a fresh socket instead of failing.
            const data = await driver.read(id(2))
            assertEquals(
                (data as { recovered: boolean }).recovered,
                true,
                'the next command reconnected and read',
            )
            assertEquals(
                opens,
                2,
                'exactly one reconnect — not permanently bricked',
            )
            await driver.close()
        },
    )
    redis.stop()
})
