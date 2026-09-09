/**
 * @fileoverview The session secret contract — what `APP_KEY` must be, and the
 * one place that decides it.
 *
 * **Why a shape and not a length.** The cookie driver derives its AES key with
 * HKDF, which expands key material but does not *stretch* it: a weak input stays
 * weak, and an attacker holding one captured cookie can guess offline at roughly
 * a derivation per microsecond. A character count cannot establish strength —
 * 16 characters is 128 bits only if every character is a uniformly random byte,
 * and a human-chosen one carries closer to 30. So the key must arrive as
 * declared key material: `base64:` followed by exactly 32 decoded bytes. That
 * makes {@link generateAppKey}'s output the natural way to satisfy it.
 *
 * **What this establishes, and what it does not.** It establishes *shape*: the
 * value is 32 bytes and was declared as such. It does **not** establish entropy,
 * and no parse can — `base64:` + a 32-character passphrase passes, as does any
 * 32 bytes an operator chose badly. Only the degenerate case (one byte repeated)
 * is refused, because that is the specific mistake of padding a value out to
 * length. The rest is the operator's to get right, and {@link generateAppKey}
 * exists so they never have to.
 *
 * **Why the value never leaves.** {@link assertUsableSecret} receives the key and
 * throws, at boot, where output is collected by whatever gathers container logs
 * and by whoever pastes a stack trace into an issue. {@link SessionSecretError}
 * therefore cannot be constructed with the value — not by convention, but
 * because its constructor does not accept one. Its *length* is withheld too: a
 * length is key metadata.
 *
 * @module @lockness/session/secret
 * @since 0.2.2
 */

import {
    decodeBase64 as contractDecodeBase64,
    encodeBase64 as contractEncodeBase64,
    generateAppKey as contractGenerateAppKey,
    KEY_BYTES as CONTRACT_KEY_BYTES,
    KEY_PREFIX as CONTRACT_KEY_PREFIX,
    KeyMaterialError,
    type KeyRejection,
    REJECTED_KEYS,
    resolveKeyMaterial,
} from '@lockness/contract'

/** Where a secret came from, so an operator knows what to change. */
export type SecretSource = 'config' | 'app-key' | 'generated'

/**
 * Why a secret was refused. Carries no part of the value. Mirrors
 * `@lockness/contract`'s {@link KeyRejection} — the validation is single-homed
 * there now; this alias preserves the session package's public API.
 */
export type SecretRejection = KeyRejection

/** The declared-key-material prefix (re-exported from the single home). */
export const KEY_PREFIX = CONTRACT_KEY_PREFIX

/** The exact decoded size of a usable key (re-exported from the single home). */
export const KEY_BYTES = CONTRACT_KEY_BYTES

/**
 * Every placeholder secret this project has shipped. Re-exported from
 * `@lockness/contract` (the validator's home); `no_placeholder_keys.test.ts`
 * still enumerates it, and the strings now live beside {@link resolveKeyMaterial}.
 */
export const REJECTED: readonly string[] = REJECTED_KEYS

const REASONS: Record<SecretRejection, string> = {
    missing: 'no session secret was provided',
    'not-prefixed': `a session secret must start with "${KEY_PREFIX}"`,
    'not-base64': 'the session secret is not valid base64',
    'wrong-length':
        `a session secret must decode to exactly ${KEY_BYTES} bytes`,
    degenerate: 'the session secret is a single byte repeated 32 times',
    'known-placeholder':
        'the session secret is one of the placeholders this framework ships; it is public',
}

const SOURCES: Record<SecretSource, string> = {
    config: 'the session configuration',
    'app-key': 'the APP_KEY environment variable',
    generated: 'a generated key',
}

/**
 * A session secret was absent or unusable.
 *
 * **The value is not a constructor parameter.** Nothing that constructs this
 * error can attach the secret to it, so no message, stack or aggregator entry
 * can carry one.
 *
 * @example
 * ```typescript
 * throw new SessionSecretError('missing', 'app-key')
 * ```
 */
export class SessionSecretError extends Error {
    /** Why it was refused. */
    readonly reason: SecretRejection
    /** Where it came from. */
    readonly source: SecretSource

    /**
     * @param reason - Why the secret was refused.
     * @param source - Where the secret came from.
     */
    constructor(reason: SecretRejection, source: SecretSource) {
        super(
            `Session secret rejected: ${REASONS[reason]} (from ${
                SOURCES[source]
            }). ` +
                `Set APP_KEY to a value of the form "${KEY_PREFIX}<${KEY_BYTES} random bytes, base64>".`,
        )
        this.name = 'SessionSecretError'
        this.reason = reason
        this.source = source
    }
}

/**
 * Generate a usable application key.
 *
 * The **only** key generator in the framework: core's development fallback and
 * `lockness init`'s scaffolding both call this one, so the length and encoding
 * cannot drift apart between them.
 *
 * @returns A key of the exact shape {@link assertUsableSecret} accepts.
 *
 * @example
 * ```typescript
 * await Deno.writeTextFile('.env', `APP_KEY=${generateAppKey()}\n`)
 * ```
 */
export const generateAppKey: () => string = contractGenerateAppKey

/**
 * Parse a session secret, or refuse it.
 *
 * **Delegates to the single home** (`@lockness/contract`'s
 * {@link resolveKeyMaterial}) — a session app and a session-less `Crypt` app now
 * share one validator — and re-wraps its failure as a {@link SessionSecretError}
 * so this package's error type and `source` context are preserved.
 *
 * @param secret - The candidate, or `undefined` when nothing was configured.
 * @param source - Where it came from, for the error message.
 * @returns The 32 decoded key bytes.
 * @throws {SessionSecretError} When the secret is absent or not key material.
 *
 * @example
 * ```typescript
 * const keyBytes = assertUsableSecret(Deno.env.get('APP_KEY'), 'app-key')
 * ```
 */
export function assertUsableSecret(
    secret: string | undefined,
    source: SecretSource,
): Uint8Array {
    try {
        return resolveKeyMaterial(secret)
    } catch (error) {
        if (error instanceof KeyMaterialError) {
            throw new SessionSecretError(error.reason, source)
        }
        throw error
    }
}

/** Base64-encode bytes (re-exported from the single home). */
export const encodeBase64: (bytes: Uint8Array) => string = contractEncodeBase64

/** Decode standard base64 to bytes (re-exported from the single home). */
export const decodeBase64: (value: string) => Uint8Array = contractDecodeBase64
