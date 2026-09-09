/**
 * Regenerate carries a FRESH lifetime on the memory driver (A-M1, SC-002).
 *
 * The A-M1 decision: `MemorySessionDriver.regenerate` must recompute the new
 * record's `expires` from the passed lifetime — the same `now + lifetime` a
 * `write()` applies on every other driver — not copy the old record's `{ data,
 * expires }` verbatim, which would preserve the *remaining* lifetime. This
 * mirrors `regenerate_ttl.test.ts` (the deno-kv side) for the driver that had no
 * such coverage.
 *
 * Mutation record: reverting `regenerate` to a verbatim `{ data, expires:
 * session.expires }` copy makes the "fresh, not remaining" assertion below go
 * red — the new expiry then reflects the short 60s lifetime, not the fresh
 * 7200s one.
 */

import { assert, assertEquals } from '@std/assert'
import { MemorySessionDriver } from '../drivers/memory.ts'

/** The private `{ data, expires }` record shape the driver keeps per id. */
type SessionsMap = Map<string, { data: unknown; expires: number }>

/** Reach the driver's private `sessions` map to read a record's raw expiry. */
function sessionsOf(driver: MemorySessionDriver): SessionsMap {
    return (driver as unknown as { sessions: SessionsMap }).sessions
}

Deno.test('memory regenerate - the new id carries the passed lifetime, not the old remaining one (A-M1)', async () => {
    const driver = new MemorySessionDriver()
    const data = { userId: 42 }

    // Pre-login: a short-lived anonymous session.
    await driver.write('old-id', data, 60)

    const before = Date.now()
    await driver.regenerate('old-id', 'new-id', 7200)
    const after = Date.now()

    const entry = sessionsOf(driver).get('new-id')
    assert(entry !== undefined, 'the new id was written')

    // The new expiry must reflect the FRESH 7200s lifetime, computed at
    // regenerate time — not the ~60s that remained on the old record.
    const seconds = (entry!.expires - before) / 1000
    assert(
        Math.abs(seconds - 7200) <= (after - before) / 1000 + 1,
        `expected ~7200s fresh TTL, saw ${seconds}s`,
    )
    assert(
        seconds > 60,
        'the new TTL is the fresh lifetime, not the old remaining ~60s',
    )
})

Deno.test('memory regenerate - the old id no longer resolves, the new one carries the data', async () => {
    const driver = new MemorySessionDriver()
    const data = { userId: 99, role: 'admin' }
    await driver.write('mem-old', data, 3600)
    await driver.regenerate('mem-old', 'mem-new', 7200)

    assertEquals(await driver.read('mem-old'), null, 'old id gone')
    assertEquals(await driver.read('mem-new'), data, 'new id carries the data')
})
