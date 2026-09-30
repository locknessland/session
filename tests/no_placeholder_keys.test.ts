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

import { assert, assertEquals, assertRejects } from '@std/assert'
import { dirname, fromFileUrl } from '@std/path'
import { gitEnvFromCwd } from '../../../tests/mutations/harness.ts'
import { REJECTED } from '../secret.ts'

// `fromFileUrl`, not `URL.pathname`: the latter keeps percent-encoding, so a
// checkout under a path with a space would never match git's own spelling of it.
const ROOT = fromFileUrl(new URL('../../../', import.meta.url))

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
 *
 * **It fails closed (#378).** A git that cannot answer — not a repository, git
 * missing, a corrupt index — prints nothing on stdout, and an empty list made
 * the scan below pass having read no file. So a non-zero exit throws with git's
 * own words, and an empty list throws too: a scan that saw nothing proved
 * nothing. Absolute paths are cut from git's stderr so the failure message
 * names no location on the machine that ran it.
 *
 * @param root - The directory git runs in; its repository is the one listed.
 * @param env - The whole environment git gets (`clearEnv`). The scan passes
 *   {@link gitEnvFromCwd}, so an inherited `GIT_DIR` cannot redirect the listing
 *   away from the tree whose files are then read from `root`.
 * @returns The tracked paths the scan covers, relative to `root`.
 * @throws {Error} When git exits non-zero, or when no file is left to scan.
 */
async function trackedFiles(
    root: string,
    env: Record<string, string>,
): Promise<string[]> {
    const git = new Deno.Command('git', {
        args: ['ls-files', '-z'],
        cwd: root,
        clearEnv: true,
        env,
        stdout: 'piped',
        stderr: 'piped',
    })
    const { success, code, stdout, stderr } = await git.output()

    if (!success) {
        const reason = new TextDecoder().decode(stderr).trim()
            .replaceAll(root.replace(/[\\/]$/, ''), '.')
        throw new Error(`git ls-files exited ${code}: ${reason}`)
    }

    const files = new TextDecoder().decode(stdout)
        .split('\0')
        .filter((path) =>
            path && !path.startsWith('.specnaut/') &&
            /\.(ts|tsx|md|stub|json|yml|yaml)$|\.env/.test(path)
        )

    if (files.length === 0) {
        throw new Error('git ls-files listed no file to scan')
    }

    return files
}

Deno.test('no placeholder key survives anywhere in the tree', async () => {
    const offenders: string[] = []

    for (const relative of await trackedFiles(ROOT, gitEnvFromCwd())) {
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

/**
 * A fresh directory git will not climb out of. `GIT_CEILING_DIRECTORIES` stops
 * discovery at the directory's parent, so whatever repository might enclose the
 * temp dir on the machine running this cannot answer in its place.
 *
 * @returns The directory, the environment git gets inside it, and its removal.
 */
async function isolatedDir(): Promise<
    { dir: string; env: Record<string, string> } & AsyncDisposable
> {
    // A space in the name, so the relativization is proven on a path that
    // percent-encoding would have spelled differently.
    const dir = await Deno.realPath(
        await Deno.makeTempDir({ prefix: 'placeholder scan ' }),
    )
    return {
        dir,
        // `LC_ALL=C` pins git's wording, which the witness below reads.
        env: {
            ...gitEnvFromCwd(),
            GIT_CEILING_DIRECTORIES: dirname(dir),
            LC_ALL: 'C',
        },
        [Symbol.asyncDispose]: () => Deno.remove(dir, { recursive: true }),
    }
}

Deno.test('a git that cannot list the tree fails the scan instead of passing it', async () => {
    await using sandbox = await isolatedDir()

    // The message is pinned to the exit-status branch: the empty-list guard
    // would also throw here, and must not be what turns this green.
    const error = await assertRejects(
        () => trackedFiles(sandbox.dir, sandbox.env),
        Error,
        'git ls-files exited',
    )
    // git's own reason is carried with the error.
    assert(error.message.includes('not a git repository'), error.message)
})

Deno.test('a git failure naming an absolute path reports it relative to the root', async () => {
    await using sandbox = await isolatedDir()
    // An inherited `GIT_DIR` pointing at no repository — the #356 situation —
    // is a failure git reports by echoing the path it was given, absolute.
    const env = { ...sandbox.env, GIT_DIR: `${sandbox.dir}/missing` }

    const error = await assertRejects(
        () => trackedFiles(sandbox.dir, env),
        Error,
        'git ls-files exited',
    )
    assert(error.message.includes('./missing'), error.message)
    assert(!error.message.includes(sandbox.dir), error.message)
})

Deno.test('a repository tracking no file fails the scan instead of passing it', async () => {
    await using sandbox = await isolatedDir()
    const init = await new Deno.Command('git', {
        args: ['init', '--quiet'],
        cwd: sandbox.dir,
        clearEnv: true,
        env: sandbox.env,
    }).output()
    assert(init.success, 'git init failed in the sandbox')

    await assertRejects(
        () => trackedFiles(sandbox.dir, sandbox.env),
        Error,
        'listed no file to scan',
    )
})
