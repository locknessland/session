/**
 * @fileoverview #389's mutation battery — a destroy that cannot revoke leaves
 * the cookie alone.
 *
 * The test this battery checks used to assert that no revocation entry was
 * written. That could never fail: the missing-`absoluteLifetime` throw happens
 * while `revoke`'s arguments are evaluated, so `revoke` is not entered whether
 * the guard is right or wrong. The property that can actually regress is the
 * ORDER — revoke first, delete the cookie second. Reversed, a destroy that
 * fails to revoke still logs the browser out, and a logout that looks like it
 * worked leaves a captured cookie authenticating.
 *
 * Runs under the shared harness: green baseline before anything is mutated, an
 * atomic per-file lock, anchors matched exactly once, a non-compiling mutant
 * reported DEAD, and every kill attributed to the test that claims it.
 *
 * ```bash
 * deno run -A packages/session/tests/mutations/revocation_guard_389.ts
 * ```
 *
 * @module @lockness/session/tests/mutations/revocation_guard_389
 */

import { type Mutation, runBattery } from '@mutations/harness.ts'

const COOKIE = new URL('../../drivers/cookie.ts', import.meta.url)
const SUITES = [
    new URL('../cookie_revocation.test.ts', import.meta.url).pathname,
]

const MUTATIONS: Mutation[] = [
    {
        label: 'the cookie is deleted above the revocation guard, so a ' +
            'destroy that fails to revoke still logs the browser out',
        file: COOKIE,
        edits: [[
            '    async destroy(_sessionId: string): Promise<void> {\n' +
            '        if (this.config.revocation && this.#store && this.#issued?.jti) {\n' +
            '            await this.#store.revoke(this.#issued.jti, this.#revocationTtl())\n' +
            '        }\n' +
            '        deleteCookie(this.context, this.config.cookieName, {\n' +
            '            path: this.config.path,\n' +
            '            domain: this.config.domain,\n' +
            '        })\n',
            '    async destroy(_sessionId: string): Promise<void> {\n' +
            '        deleteCookie(this.context, this.config.cookieName, {\n' +
            '            path: this.config.path,\n' +
            '            domain: this.config.domain,\n' +
            '        })\n' +
            '        if (this.config.revocation && this.#store && this.#issued?.jti) {\n' +
            '            await this.#store.revoke(this.#issued.jti, this.#revocationTtl())\n' +
            '        }\n',
        ]],
        killedBy: 'destroy fails loud and leaves the cookie in place',
    },
]

if (import.meta.main) {
    Deno.exit(
        await runBattery(
                '#389 — a destroy that cannot revoke leaves the cookie alone',
                SUITES,
                MUTATIONS,
            ) > 0
            ? 1
            : 0,
    )
}
