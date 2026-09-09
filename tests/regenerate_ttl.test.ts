/**
 * Regenerate carries a fresh lifetime — the deno-kv side (US1, SC-002).
 *
 * The #139 defect: `DenoKvSessionDriver.regenerate` wrote the new key with no
 * `expireIn`, so an authenticated session became immortal server-side. These
 * pin that a regenerate applies the lifetime it was handed — the same value a
 * `write()` receives — and that the old key is gone.
 *
 * SC-005 mutation record: dropping `expireIn` from the deno-kv regenerate (the
 * pre-#139 body) makes the "carries the 7200s TTL" assertion below go red,
 * because the recorded `expireInMs` is then `undefined`.
 */

import { assertEquals, assertNotEquals } from '@std/assert'
import { DenoKvSessionDriver } from '../drivers/deno_kv.ts'
import { FakeKv } from './fake_kv.ts'

/**
 * Run `work` with `Deno.openKv` stubbed to hand back `fake`. `Deno.openKv` is a
 * getter-only property; `defineProperty` is the supported way to replace it.
 */
async function withFakeKv(
    fake: FakeKv,
    work: () => Promise<void>,
): Promise<void> {
    const realOpenKv = Deno.openKv
    Object.defineProperty(Deno, 'openKv', {
        configurable: true,
        value: () => Promise.resolve(fake as unknown as Deno.Kv),
    })
    try {
        await work()
    } finally {
        Object.defineProperty(Deno, 'openKv', {
            configurable: true,
            value: realOpenKv,
        })
    }
}

Deno.test('deno-kv regenerate - the new key carries the passed lifetime as its TTL (SC-002)', async () => {
    const fake = new FakeKv()
    await withFakeKv(fake, async () => {
        const driver = new DenoKvSessionDriver()
        const data = { userId: 42 }
        await driver.write('old-id', data, 60) // some pre-login lifetime
        await driver.regenerate('old-id', 'new-id', 7200)

        const entry = fake.entryFor('new-id')
        assertNotEquals(
            entry,
            undefined,
            'the new key was written',
        )
        assertNotEquals(
            entry?.expireInMs,
            undefined,
            'the new key was written WITH an expireIn — not the immortal pre-#139 body',
        )
        // Within 1s of 7200s (the fake records the exact ms the driver passed).
        const seconds = (entry!.expireInMs as number) / 1000
        assertEquals(
            Math.abs(seconds - 7200) <= 1,
            true,
            `expected ~7200s TTL, saw ${seconds}s`,
        )

        await driver.close()
    })
})

Deno.test('deno-kv regenerate - the old key no longer resolves, the new one carries the data', async () => {
    const fake = new FakeKv()
    await withFakeKv(fake, async () => {
        const driver = new DenoKvSessionDriver()
        const data = { userId: 99, role: 'admin' }
        await driver.write('kv-old', data, 3600)
        await driver.regenerate('kv-old', 'kv-new', 7200)

        assertEquals(await driver.read('kv-old'), null, 'old id gone')
        assertEquals(
            await driver.read('kv-new'),
            data,
            'new id carries the data',
        )

        await driver.close()
    })
})
