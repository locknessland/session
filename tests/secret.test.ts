/**
 * The session secret contract — `APP_KEY` is key *material*, not a password.
 *
 * Two rules this file pins, both of which the first draft of the plan got wrong:
 *
 * 1. **Shape, not length.** HKDF does not stretch, so the key must arrive
 *    strong. A 16-character floor reads like 128 bits and delivers ~25-40 for a
 *    human-chosen string. `base64:` + exactly 32 decoded bytes turns "is this
 *    key material?" from a guess into a parse.
 * 2. **The value never reaches the output.** `assertUsableSecret` is a validator
 *    that receives the key and throws, at boot, where output is captured by
 *    whatever collects container logs. The message an implementer naturally
 *    writes interpolates the argument.
 */

import { assertEquals, assertThrows } from '@std/assert'
import {
    assertUsableSecret,
    generateAppKey,
    REJECTED,
    type SecretRejection,
    SessionSecretError,
} from '../secret.ts'

const GOOD = generateAppKey()

Deno.test('secret - a generated key passes its own validator', () => {
    // The round-trip that keeps the generator and the validator from drifting.
    // They live in one file precisely so this can be asserted.
    const bytes = assertUsableSecret(generateAppKey(), 'config')

    assertEquals(bytes.byteLength, 32)
})

Deno.test('secret - two generated keys differ', () => {
    const seen = new Set(Array.from({ length: 16 }, () => generateAppKey()))

    assertEquals(seen.size, 16)
})

Deno.test('secret - exactly 32 decoded bytes, not 31 and not 33', () => {
    // Distinct bytes, not a zero-filled buffer: an all-zero 32-byte value is
    // now refused as degenerate, and this test is about LENGTH. Building it from
    // zeros made it fail for the wrong reason the moment that check landed.
    const b64 = (n: number) => {
        const u = new Uint8Array(n)
        for (let i = 0; i < n; i++) u[i] = (i * 7 + 1) & 0xff
        let s = ''
        for (const b of u) s += String.fromCharCode(b)
        return 'base64:' + btoa(s)
    }

    assertUsableSecret(b64(32), 'config')
    assertThrows(
        () => assertUsableSecret(b64(31), 'config'),
        SessionSecretError,
    )
    assertThrows(
        () => assertUsableSecret(b64(33), 'config'),
        SessionSecretError,
    )
})

Deno.test('secret - the prefix is required', () => {
    // A bare base64 string of the right length is refused. The prefix is what
    // makes the shape declared rather than inferred.
    const bare = GOOD.slice('base64:'.length)

    assertThrows(() => assertUsableSecret(bare, 'config'), SessionSecretError)
})

Deno.test('secret - an absent secret is refused, not defaulted', () => {
    assertThrows(
        () => assertUsableSecret(undefined, 'app-key'),
        SessionSecretError,
    )
    assertThrows(() => assertUsableSecret('', 'app-key'), SessionSecretError)
})

Deno.test('secret - non-base64 after the prefix is refused', () => {
    assertThrows(
        () => assertUsableSecret('base64:not valid base64 !!', 'config'),
        SessionSecretError,
    )
})

Deno.test('secret - every historically shipped placeholder is refused', () => {
    // These are the strings this repository actually shipped. Three of them are
    // longer than 16 characters and would have passed the first draft's floor —
    // one is the session package's own documented example.
    const survivors = REJECTED.filter((placeholder) => {
        try {
            assertUsableSecret(placeholder, 'config')
            return true
        } catch {
            return false
        }
    })

    assertEquals(survivors, [], 'these placeholders were accepted as keys')
})

Deno.test('secret - the reject list still names the placeholders that shipped', () => {
    // REJECTED is a reporting aid once the shape check exists — but it is also
    // what the tree-wide grep test enumerates, so an entry going missing
    // silently un-guards a file.
    for (
        const required of [
            'change-me-in-production',
            'your-secret-key-here-change-in-production',
            'your-secret-key-here',
            'production-secret-key',
            'a-very-long-secret-key-32-chars',
        ]
    ) {
        assertEquals(
            REJECTED.includes(required),
            true,
            `${required} must stay on the list`,
        )
    }
})

Deno.test('secret - no rejection message carries the value', () => {
    // FR-018. Asserted per branch rather than against one fixed message: a test
    // pinning the exact string passes forever and says nothing about the next
    // branch somebody adds.
    const cases: Array<[string, string]> = [
        ['not-prefixed', 'kJ8sQpWvNzR4tYuIoPaSdFgHjKlZxCvB'],
        ['wrong-length', 'base64:' + btoa('short')],
        ['not-base64', 'base64:@@@not-base64@@@'],
        ['known-placeholder', 'change-me-in-production'],
    ]

    for (const [label, value] of cases) {
        const error = assertThrows(
            () => assertUsableSecret(value, 'app-key'),
            SessionSecretError,
        )

        assertEquals(
            `${error.message} ${error.stack ?? ''}`.includes(value),
            false,
            `${label}: the message carries the secret`,
        )
    }
})

Deno.test('secret - the message does not vary with the secret, only with the reason', () => {
    // The length check that actually holds. A message containing the secret's
    // length would differ between two inputs of the same rejection class and
    // different lengths; the required key size is a constant and legitimately
    // appears. Comparing two inputs per class separates the two.
    const pairs: Array<[SecretRejection, string, string]> = [
        ['not-prefixed', 'ab', 'a'.repeat(200)],
        [
            'wrong-length',
            'base64:' + btoa('x'),
            'base64:' + btoa('y'.repeat(99)),
        ],
        [
            'known-placeholder',
            'change_me',
            'your-secret-key-here-change-in-production',
        ],
    ]

    for (const [reason, short, long] of pairs) {
        const a = assertThrows(
            () => assertUsableSecret(short, 'app-key'),
            SessionSecretError,
        )
        const b = assertThrows(
            () => assertUsableSecret(long, 'app-key'),
            SessionSecretError,
        )

        assertEquals(a.reason, reason)
        assertEquals(
            a.message,
            b.message,
            `${reason}: the message changes with the input, so it leaks key metadata`,
        )
    }
})

Deno.test('secret - the error names the reason and the source, so the operator can act', () => {
    const error = assertThrows(
        () => assertUsableSecret(undefined, 'app-key'),
        SessionSecretError,
    )

    assertEquals(error.reason, 'missing')
    assertEquals(error.source, 'app-key')
    assertEquals(error.message.includes('APP_KEY'), true)
})

Deno.test('secret - a degenerate key is refused', () => {
    // 32 bytes of one repeated value is shape-valid and worthless. The parse
    // establishes shape, never entropy — this catches only the specific mistake
    // of padding a value out to satisfy the length check.
    const repeated = (byte: number) => {
        const u = new Uint8Array(32).fill(byte)
        let s = ''
        for (const b of u) s += String.fromCharCode(b)
        return 'base64:' + btoa(s)
    }

    for (const byte of [0x00, 0xff, 0x41]) {
        const error = assertThrows(
            () => assertUsableSecret(repeated(byte), 'app-key'),
            SessionSecretError,
        )
        assertEquals(error.reason, 'degenerate')
    }
})

Deno.test('secret - the parse does NOT claim to establish entropy', () => {
    // Stated as a test so nobody later reads the shape check as a strength
    // check. A base64-encoded passphrase is 32 bytes and passes; that is the
    // documented limit of what a parse can do, and generateAppKey is the answer.
    const passphrase = 'base64:' + btoa('correct horse battery staple 123')

    assertEquals(assertUsableSecret(passphrase, 'config').byteLength, 32)
})
