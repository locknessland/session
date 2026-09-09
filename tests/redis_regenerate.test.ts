/**
 * Regenerate on Redis is one atomic command carrying the lifetime (US1).
 *
 * The #139 defects on this path: regenerate ran `read → write → destroy` as
 * three separate round-trips (non-atomic — a mid-op failure strands the
 * attacker-known old id), and the `write` passed `config.db` as the TTL, so a
 * default `db=0` produced `SETEX <key> 0`, which errors and 500s the login.
 *
 * The fix issues a single `EVAL` (`GET old → SET new EX lifetime → DEL old`)
 * carrying the lifetime in `ARGV`. This observes, off the wire, that exactly one
 * `EVAL` reaches the server, that it carries `7200` (never `config.db`), and
 * that no separate GET/SET/DEL frames appear.
 *
 * SC-005 mutation record: reverting regenerate to `read → write(config.db) →
 * destroy` makes both assertions below go red — the command list becomes
 * `GET, SETEX, DEL` (no `EVAL`), and no frame carries `7200`.
 */

import { assertEquals } from '@std/assert'
import { RedisSessionDriver } from '../drivers/redis.ts'
import { startRespServer } from './resp_server.ts'

/**
 * Bound a wire operation in time so a desync fails cleanly in 3s rather than
 * wedging CI (the pattern from `redis_wire.test.ts`).
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

Deno.test('redis regenerate - one EVAL carrying the lifetime, never config.db, never GET+SET+DEL', async () => {
    const server = await startRespServer()
    try {
        // db defaults to 0; the broken body passed that as the TTL. Prove the
        // lifetime (7200) is what travels, and that it is one atomic command.
        const driver = new RedisSessionDriver({
            hostname: '127.0.0.1',
            port: server.port,
        })
        await withTimeout(
            driver.regenerate('a'.repeat(64), 'b'.repeat(64), 7200),
        )
        await withTimeout(driver.close())

        const obs = await server.done()
        assertEquals(obs.error, null, 'the server captured the whole stream')

        const nonQuit = obs.commands.filter((c) => c.args[0] !== 'QUIT')
        assertEquals(
            nonQuit.map((c) => c.args[0]),
            ['EVAL'],
            'regenerate is exactly one EVAL — not a GET+SET+DEL sequence',
        )
        assertEquals(
            nonQuit[0].args.includes('7200'),
            true,
            'the EVAL carries the lifetime (7200), never config.db',
        )
        assertEquals(
            nonQuit[0].args.includes('0'),
            false,
            'the db index (0) is not the TTL',
        )

        // The script body itself must name all three ops against the right keys.
        // The stateful `fake_redis` interprets this text, so dropping any of
        // these from the production script fails the destroy-path tests there;
        // pinning it here — off the recorder — makes the mutation red even
        // without the stateful fake (HIGH review finding, SC-005).
        const script = nonQuit[0].args[1]
        assertEquals(
            /redis\.call\(\s*'GET'\s*,\s*KEYS\[1\]/.test(script),
            true,
            'the script GETs the old key (KEYS[1])',
        )
        assertEquals(
            /redis\.call\(\s*'SET'\s*,\s*KEYS\[2\].*'EX'\s*,\s*ARGV\[1\]/.test(
                script,
            ),
            true,
            'the script SETs the new key (KEYS[2]) with EX <lifetime>',
        )
        assertEquals(
            /redis\.call\(\s*'DEL'\s*,\s*KEYS\[1\]/.test(script),
            true,
            'the script DELs the old key (KEYS[1]) — the destroy path',
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
