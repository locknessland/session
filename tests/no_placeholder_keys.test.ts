/**
 * No placeholder key ships. Enforced as a test, not as a checklist.
 *
 * The first draft of this feature planned a one-off sweep for
 * `change-me-in-production`. That search was wrong twice over: it missed
 * `your-secret-key-here-change-in-production`, which is **not** a superstring of
 * it, and a sweep does not survive the next placeholder somebody adds. So the
 * search is built from {@link REJECTED} itself — the same array the validator
 * refuses — and it runs on every `deno task test`.
 */

import { assertEquals } from '@std/assert'
import { REJECTED } from '../secret.ts'

const ROOT = new URL('../../../', import.meta.url).pathname

/**
 * Files allowed to contain a placeholder, and why.
 *
 * Kept deliberately short. Each entry is a place whose *job* is to name the
 * strings nobody may use — anywhere else, naming one is shipping one.
 */
const ALLOWED = [
    'packages/contract/crypto_key.ts', // the list's single home (validator)
    'packages/contract/tests/crypto_key.test.ts', // exercises the validator
    'packages/crypto/tests/key.test.ts', // asserts a placeholder is rejected
    'packages/session/secret.ts', // re-exports the list
    'packages/session/tests/secret.test.ts', // exercises the list
    'packages/session/tests/no_placeholder_keys.test.ts', // this file
    'packages/core/tests/session_boot.test.ts', // asserts a placeholder is refused
    'packages/session/tests/wire_format.test.ts', // asserts the driver refuses one
]

/**
 * The file set is **what git tracks**, and nothing else.
 *
 * An untracked file must not decide a test: a developer's own `.env` is theirs,
 * differs between machines, and is absent on a fresh clone — three ways for the
 * same assertion to mean three different things. What ships is what is tracked.
 */
async function trackedFiles(): Promise<string[]> {
    const git = new Deno.Command('git', {
        args: ['ls-files', '-z'],
        cwd: ROOT,
        stdout: 'piped',
    })
    const { stdout } = await git.output()

    return new TextDecoder().decode(stdout)
        .split('\0')
        .filter((path) =>
            path && !path.startsWith('.specnaut/') &&
            /\.(ts|tsx|md|stub|json|yml|yaml)$|\.env/.test(path)
        )
}

Deno.test('no placeholder key survives anywhere in the tree', async () => {
    const offenders: string[] = []

    for (const relative of await trackedFiles()) {
        if (ALLOWED.includes(relative)) continue

        const text = await Deno.readTextFile(`${ROOT}${relative}`)
        for (const placeholder of REJECTED) {
            const quoted = placeholder.replace(/[.*+?^${}()|[\]\\!]/g, '\\$&')
            // Two shapes, and the first one matters more than it looks.
            //
            // The original search anchored to `APP_KEY=<ph>` and `secret: <ph>`.
            // Neither is the shape this repository actually shipped: the literal
            // lived in `Deno.env.get('APP_KEY') || 'change-me-in-production'`
            // and in `secret === 'change-me-in-production'`. Reintroducing it
            // exactly as it was left the guard green — verified. So the search
            // is now for the placeholder **as a string literal anywhere**, which
            // is the only position it can occupy in code, plus the bare
            // env-file assignment where quotes are optional.
            const asLiteral = new RegExp(`['"\`]${quoted}['"\`]`)
            const asEnvValue = new RegExp(
                `^\\s*APP_KEY\\s*=\\s*["']?${quoted}`,
                'm',
            )

            if (asLiteral.test(text) || asEnvValue.test(text)) {
                offenders.push(`${relative} → ${placeholder}`)
            }
        }
    }

    assertEquals(offenders, [], 'these files ship a placeholder key')
})

Deno.test('the reject list is not silently emptied', () => {
    // The test above passes trivially against an empty list. This is the guard
    // that makes it mean something.
    assertEquals(REJECTED.length >= 10, true)
    assertEquals(REJECTED.includes('change-me-in-production'), true)
})
