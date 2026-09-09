/**
 * The rejection reporter — the thing that replaced `catch { return null }`.
 *
 * It had no tests at all: the first-warn branch, the counting, the summary and
 * the clear could each have been deleted with the suite fully green. That is the
 * same shape as the silent catch it replaced — code that runs on every forged
 * cookie and that nothing watches.
 *
 * Since #236 the reporter is an instance (`RejectionReporter`), not module
 * scope, so each test constructs a fresh one — no process-wide reset needed. The
 * classification of a value into a rejection class is still exercised through
 * `openSealed` where the two meet (the hostile-value test), because that is the
 * path that must never leak the value into the log.
 */

import { assertEquals } from '@std/assert'
import { generateAppKey } from '../secret.ts'
import { RejectionReporter } from '../drivers/cookie.ts'
import { openSealed, type Rejection } from '../drivers/cookie_seal.ts'

const KEY = generateAppKey()

/** Capture `console.warn` for the duration of `fn`. */
async function captureWarnings(fn: () => Promise<void>): Promise<string[]> {
    const lines: string[] = []
    const warn = console.warn
    console.warn = (...a: unknown[]) => void lines.push(a.join(' '))
    try {
        await fn()
    } finally {
        console.warn = warn
    }
    return lines
}

Deno.test('reporting - the first rejection warns immediately', async () => {
    const reporter = new RejectionReporter()

    const lines = await captureWarnings(() => {
        reporter.report('bad-prefix')
        return Promise.resolve()
    })

    assertEquals(lines.length, 1)
    assertEquals(lines[0].includes('bad-prefix'), true)
})

Deno.test('reporting - the rejected VALUE never reaches the log', async () => {
    // The single most likely place for somebody to attach the offending cookie
    // "for debuggability". It is attacker-controlled and Hono has already
    // URL-decoded it, so CR/LF arrives raw. `openSealed` classifies it to a
    // closed literal, and the reporter is fed the literal — the value has no path
    // to the log by construction.
    const reporter = new RejectionReporter()
    const hostile = 'PWNED\r\nFAKE LOG LINE'
    const classified = await openSealed(KEY, hostile)
    assertEquals(classified, 'bad-prefix') // a string, not an opened payload

    const lines = await captureWarnings(() => {
        reporter.report(classified as 'bad-prefix')
        return Promise.resolve()
    })

    assertEquals(lines.join('\n').includes('PWNED'), false)
    assertEquals(lines.join('\n').includes('FAKE LOG LINE'), false)
})

Deno.test('reporting - later rejections are counted, not logged one by one', async () => {
    // The flooding vector: a line per rejection is output an attacker controls.
    const reporter = new RejectionReporter()

    const lines = await captureWarnings(() => {
        for (let i = 0; i < 50; i++) reporter.report('bad-prefix')
        return Promise.resolve()
    })

    assertEquals(lines.length, 1, '50 rejections produced more than one line')
})

Deno.test('reporting - every rejection class is reported distinctly', async () => {
    // The classification of a value into a class is `openSealed`'s job; that the
    // reporter surfaces exactly the class it was handed is this one's.
    const cases: Array<[Rejection, string]> = [
        ['bad-prefix', 'no-marker-at-all'],
        ['too-long', 'v1.' + 'A'.repeat(5000)],
        ['bad-base64', 'v1.@@@'],
        ['too-short', 'v1.AAAA'],
    ]

    for (const [expected, value] of cases) {
        const reporter = new RejectionReporter()
        const classified = await openSealed(KEY, value)
        assertEquals(classified, expected, `openSealed classifies ${expected}`)
        reporter.report(expected)
        assertEquals(reporter.lastRejection(), expected, `for ${expected}`)
    }
})

Deno.test('reporting - reset clears the class, so a stale read cannot pass for a fresh one', () => {
    // A fresh instance IS the reset: instance-owned state means one file's
    // rejections cannot bleed into the next (#236).
    const reporter = new RejectionReporter()

    assertEquals(reporter.lastRejection(), undefined)
})

Deno.test('reporting - the first rejection is warned, NOT also counted', async () => {
    // It was reported twice: once on its own line, and again inside the first
    // summary's total. A count that reports one event twice is worse than no
    // count, because somebody sizes an incident from it — and the defect was
    // invisible for 60 seconds, which is why the counts needed a test seam at
    // all.
    const reporter = new RejectionReporter()

    await captureWarnings(() => {
        reporter.report('bad-prefix')
        return Promise.resolve()
    })

    assertEquals(reporter.pendingRejections(), {})
})

Deno.test('reporting - subsequent rejections accumulate per class', async () => {
    const reporter = new RejectionReporter()

    await captureWarnings(() => {
        reporter.report('bad-prefix') // warned, not counted
        reporter.report('bad-prefix')
        reporter.report('bad-prefix')
        reporter.report('bad-base64')
        return Promise.resolve()
    })

    assertEquals(reporter.pendingRejections(), {
        'bad-prefix': 2,
        'bad-base64': 1,
    })
})
