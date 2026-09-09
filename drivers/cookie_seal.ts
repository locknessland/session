/**
 * @fileoverview Cookie session — the sealed wire format (the crypto value layer).
 *
 * **Sealing is `@lockness/crypto`'s {@link Crypt}** (#265). Both this driver and
 * `Crypt` are AES-256-GCM with a fresh per-message HKDF salt, a random 96-bit
 * IV, and the version prefix bound as GCM `additionalData` — `Crypt` is "the
 * proven session cookie construction, generalised". So the session no longer
 * carries its own AES-256-GCM *sealing*: {@link seal} delegates to
 * {@link Crypt.encrypt}, and new cookies are written in `Crypt`'s wire format
 * (prefix `c1.`).
 *
 * **The two formats are deliberately not byte-compatible.** `Crypt` derives with
 * a distinct HKDF `info` (`lockness/crypt/v1`), domain-separated from the legacy
 * cookie's (`lockness/session/cookie/v1`) by a binding crypto invariant, so a
 * legacy `v1.` cookie cannot be opened by `Crypt` and vice-versa. To avoid
 * logging every existing session out, {@link openSealed} keeps an **authenticated
 * `v1.` read-compat path** alongside the `c1.` `Crypt` path — see the note below.
 *
 * Legacy wire: `v1.` + base64(`salt(16) ‖ iv(12) ‖ ciphertext‖tag`) over a
 * plaintext of `{ d, iat, exp, jti, sub? }`. `Crypt`'s wire is the same layout
 * under the `c1.` prefix.
 *
 * This module is **pure and offline**: it seals and opens, and it does no I/O,
 * holds no request context, and keeps no mutable state. The per-request driver
 * (`cookie.ts`) composes these functions; the revocation decision and the
 * rejection reporting both live there, not here — an offline crypto function
 * must not grow a network call or a side effect.
 *
 * Which part does what, because it is easy to credit the wrong one:
 *
 * - **The version prefix is format discrimination, not a security control.** It
 *   is public, an attacker prepends it for free, and a conforming forgery then
 *   dies on the GCM tag. Its value is that a wrong format is rejected *before*
 *   base64-decoding, which is also where the length ceiling lives. It is passed
 *   as GCM `additionalData` as well, so a cross-version downgrade is not free.
 * - **The control is that there is no *unencrypted* path.** This driver once
 *   fell back to `btoa` when the secret was empty — the cookie was
 *   attacker-writable by design. That branch is gone, and nothing may
 *   reintroduce it. The `v1.` read-compat path is **not** that window: it is
 *   AES-256-GCM authenticated, so forging a legacy cookie still needs the key.
 *   What is forbidden is an *unauthenticated* read, not a second authenticated
 *   format kept only to open the cookies we already issued.
 * - **`exp` lives inside the ciphertext.** `maxAge` on the cookie is a browser
 *   hint an attacker ignores, and this driver keeps no server-side record, so
 *   without an authenticated expiry a captured cookie authenticates for ever —
 *   across the victim's logout, since `destroy()` can only delete the client's
 *   copy.
 * - **The salt is fresh per cookie, so each derived key encrypts exactly one
 *   message.** That is why the ~2³² random-96-bit-IV ceiling does not apply
 *   here. Caching the derived key — the first optimisation anyone proposes on
 *   seeing HKDF called per request — silently reinstates that bound. Do not.
 *
 * @module @lockness/session/drivers/cookie_seal
 */

import { Crypt } from '@lockness/crypto'
import type { SessionData } from '../types.ts'
import { assertUsableSecret, decodeBase64 } from '../secret.ts'

/**
 * The legacy wire-format marker, still accepted on read for backward
 * compatibility. New cookies are sealed in `Crypt`'s format ({@link CRYPT_VERSION}).
 * Public by design; see the module note.
 */
export const WIRE_VERSION = 'v1.'

/**
 * `@lockness/crypto`'s `Crypt` wire prefix — the format {@link seal} now writes.
 *
 * Not exported by `@lockness/crypto`; mirrored here only to *classify* a cookie's
 * format before delegating, so a truncated or malformed `c1.` cookie still earns
 * a granular {@link Rejection} rather than collapsing to `tag-mismatch`.
 * {@link Crypt.decrypt} validates its own prefix independently; this constant is
 * a read-side classifier, never the authority. Both markers are 3 chars, so the
 * body always starts at index 3.
 */
const CRYPT_VERSION = 'c1.'

/**
 * The first-issuance identity of a session, preserved across re-seals.
 *
 * `iat` and `jti` are one concept — both minted when a session is first issued,
 * both carried unchanged through every re-seal, both reset on `regenerate()`. So
 * they travel as one value object, not two parallel fields. `iat` anchors the
 * absolute-lifetime cap (measured from first issuance, not from the last write);
 * `jti` is the per-session nonce the revocation set keys on.
 */
export interface IssuedIdentity {
    /** Epoch seconds of first issuance — the absolute cap is measured from here. */
    iat: number
    /** A ≥128-bit CSPRNG session nonce, the revocation key. */
    jti: string
}

/**
 * Mint a fresh 128-bit session nonce (hex), from the same CSPRNG as salt/IV.
 *
 * **Internal.** Shared with the driver so a jti-less pre-feature cookie can be
 * given a nonce on read; it is the sole minter, so the format of a `jti` has one
 * home.
 *
 * @returns A 32-character lowercase hex string (16 random bytes).
 * @internal
 */
export function mintJti(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(16))
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** 16 bytes of HKDF salt — the legacy cookie's per-message salt. */
const SALT_BYTES = 16
/** 12 bytes of AES-GCM IV — the legacy cookie's per-message IV. */
const IV_BYTES = 12
/** The AES-GCM authentication tag, at the end of the ciphertext. */
const TAG_BYTES = 16
/**
 * The largest cookie value this driver will look at.
 *
 * Browsers cap a cookie at roughly 4 KB, so anything larger was never issued by
 * us. Bounding it before base64-decoding keeps an oversized header from being
 * decoded and mapped on every request.
 */
const MAX_COOKIE_CHARS = 4096

const decoder = new TextDecoder()
/**
 * The legacy `v1.` GCM `additionalData` and HKDF `info`. Used **only** by the
 * `v1.` read-compat path in {@link openSealed}; new cookies are sealed through
 * {@link Crypt}, which owns its own (`c1.`) domain-separated pair.
 */
const LEGACY_AAD = new TextEncoder().encode(WIRE_VERSION)
const LEGACY_INFO = new TextEncoder().encode('lockness/session/cookie/v1')

/**
 * Why a cookie was refused.
 *
 * A **closed union of literals**, which is why nothing here needs an encoder:
 * the only thing reaching the log is one of these six compile-time constants.
 * The moment any contextual field is added — the offending value being the
 * obvious temptation — it is attacker-controlled, post-`decodeURIComponent`,
 * CR/LF included, and it must go through `safeForLog` first.
 *
 * {@link openSealed} returns one of these instead of the opened payload; the
 * driver hands it to its `RejectionReporter`. The value never travels with it.
 */
export type Rejection =
    | 'bad-prefix'
    | 'too-long'
    | 'bad-base64'
    | 'too-short'
    | 'tag-mismatch'
    | 'expired'
    // The idle `exp` passed. Kept distinct from `absolute-expired` so an operator
    // can tell an idle timeout from a hard-cap eviction in the summary line.
    | 'absolute-expired'
    // The session's `jti` is in the revocation set, or the revocation store could
    // not be read (fail-closed — a store outage refuses, never authenticates).
    | 'revoked'

/**
 * Derive a legacy `v1.` cookie's AES key, for the read-compat path only.
 *
 * HKDF, not PBKDF2: the secret is required to be 32 bytes of real key material
 * (see `secret.ts`), so there is nothing to stretch, and PBKDF2 at 100 000
 * iterations cost 13.45 ms per call on this runtime — twice per request, an
 * unauthenticated client's denial-of-service amplifier. New cookies no longer
 * derive here at all — {@link Crypt} does, under its own `info`.
 *
 * @param keyBytes - The 32 validated key bytes.
 * @param salt - The legacy cookie's salt.
 * @returns An AES-256-GCM key for decrypting exactly one legacy message.
 */
async function deriveLegacyKey(
    keyBytes: Uint8Array,
    salt: Uint8Array,
): Promise<CryptoKey> {
    const material = await crypto.subtle.importKey(
        'raw',
        keyBytes as BufferSource,
        'HKDF',
        false,
        ['deriveKey'],
    )

    return await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt as BufferSource,
            info: LEGACY_INFO,
        },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt'],
    )
}

/**
 * Seal session data into a cookie value.
 *
 * @param secret - The application key, in `base64:` form.
 * @param data - The session contents.
 * @param lifetime - Seconds until the payload's idle `exp`, authenticated inside
 *   it. Refreshed on every call.
 * @param issued - The session's first-issuance identity (`iat`/`jti`) to
 *   preserve across a re-seal. Omit for a brand-new session — a fresh `iat` and a
 *   128-bit `jti` are minted.
 * @param sub - The opaque subject token (#147), embedded beside `jti`. The
 *   session layer never interprets it; the auth guard populates it and the
 *   per-user eviction check keys on it. Omit for a session with no subject (a
 *   pre-`#147` or unauthenticated session).
 * @returns The cookie value.
 * @throws {SessionSecretError} When the secret is absent or not key material.
 *
 * @example
 * ```typescript
 * const value = await seal(config.secret, { userId: 1 }, 7200)
 * ```
 */
export async function seal(
    secret: string | undefined,
    data: SessionData,
    lifetime: number,
    issued?: IssuedIdentity,
    sub?: string,
): Promise<string> {
    const now = Math.floor(Date.now() / 1000)
    // First-issuance identity is PRESERVED across re-seals: an already-issued
    // session keeps its original `iat` (so the absolute cap measures real age,
    // not time-since-last-write) and its `jti` (so a re-seal cannot shed a
    // revocation). A brand-new session mints both. `exp` — the idle window — is
    // always fresh.
    const iat = issued?.iat ?? now
    const jti = issued?.jti ?? mintJti()
    // `sub` is additive JSON — omitted entirely when absent, so no `WIRE_VERSION`
    // bump and a `sub`-less cookie is byte-identical to a pre-`#147` one.
    const payload = sub === undefined
        ? { d: data, iat, exp: now + lifetime, jti }
        : { d: data, iat, exp: now + lifetime, jti, sub }
    return await sealPayload(secret, payload)
}

/**
 * Encrypt an arbitrary payload object into a cookie value via {@link Crypt}.
 *
 * `assertUsableSecret` runs first and is **not** redundant with `Crypt`'s own
 * key resolution: the session mandates a *configured* secret and must throw
 * {@link SessionSecretError} when it is absent or unusable. Handing an absent
 * secret to `Crypt` instead would let it fall back to `APP_KEY` (or, in explicit
 * development, an ephemeral key) — silently sealing under a key the session
 * never configured. The validated secret is then passed to `Crypt` as its
 * explicit key, so both derive from the same 32 bytes.
 */
async function sealPayload(
    secret: string | undefined,
    payload: unknown,
): Promise<string> {
    assertUsableSecret(secret, 'config')
    return await Crypt.encrypt(JSON.stringify(payload), secret)
}

/**
 * Seal an arbitrary payload object, bypassing {@link seal}'s `{ d, iat, exp, jti }`
 * construction.
 *
 * **Test-only, and deliberately absent from `mod.ts`.** It exists so a test can
 * craft a GCM-valid `c1.` cookie with a missing or non-numeric `iat` — a shape a
 * real `seal()` never produces — to prove `open()`'s absolute-cap `iat`-present
 * gate fails closed. Without it that fail-closed branch could be deleted with the
 * suite still green.
 *
 * @param secret - The application key.
 * @param payload - The exact object to seal (no fields are added).
 * @returns The cookie value.
 * @internal
 */
export function sealArbitrary(
    secret: string | undefined,
    payload: unknown,
): Promise<string> {
    return sealPayload(secret, payload)
}

/**
 * Open a sealed cookie value, or refuse it.
 *
 * Every rejection is a **decision**, taken before the crypto call where it can
 * be — the length ceiling, the prefix, the minimum structural size. The
 * `try/catch` is a backstop, not the mechanism: relying on `OperationError` to
 * reject a truncated payload means a narrowed catch later turns an empty session
 * into a 500.
 *
 * @param secret - The application key, in `base64:` form.
 * @param value - The attacker-controlled cookie value.
 * @param absoluteLifetime - When a number, the hard ceiling: the payload is
 *   refused if `now - iat` exceeds it or if `iat` is missing/non-numeric. Gated
 *   on `typeof === 'number'`, so `0` enforces rather than disables. Omit to skip
 *   the cap.
 * @returns The session contents, or `null` for anything not authentically ours.
 * @throws {SessionSecretError} When the secret is absent or not key material.
 *
 * @example
 * ```typescript
 * const data = await open(config.secret, cookieValue)
 * ```
 */
export async function open(
    secret: string | undefined,
    value: string,
    absoluteLifetime?: number,
): Promise<SessionData | null> {
    const opened = await openSealed(secret, value, absoluteLifetime)
    return typeof opened === 'string' ? null : opened.data
}

/**
 * One opened, verified sealed payload — the fields the driver needs beyond the
 * data itself.
 */
export interface OpenedPayload {
    /** The session contents. */
    data: SessionData
    /** First-issuance epoch seconds (the absolute-cap anchor). */
    iat: number
    /** Idle-expiry epoch seconds. */
    exp: number
    /** The session nonce, absent on a pre-feature (jti-less) cookie. */
    jti?: string
    /**
     * The opaque subject token (#147), absent on a pre-`#147` or unauthenticated
     * cookie. The session layer never interprets it — the per-user eviction check
     * keys on it, the guard populates it.
     */
    sub?: string
}

/**
 * Decrypt, verify and surface a sealed cookie — the same checks {@link open}
 * makes, but returning `iat`/`exp`/`jti` so the driver can preserve the identity
 * across re-seals and run the revocation check. **Pure and offline**: it does no
 * I/O and takes no store — the revocation decision lives in the driver's
 * `read()`, not here (an offline crypto function must not grow a network call).
 *
 * On rejection it **returns the {@link Rejection} class** rather than mutating a
 * reporter: the classification is a pure decision, and reporting is the driver's
 * to do (it owns the process-shared `RejectionReporter`). The value never
 * travels with the class — only the closed literal does.
 *
 * @param secret - The application key.
 * @param value - The raw cookie value.
 * @param absoluteLifetime - When a number, the hard ceiling: the payload is
 *   refused if `now - iat` exceeds it, or if `iat` is missing/non-numeric. The
 *   gate is `typeof === 'number'`, never truthiness — `0` does not disable it.
 * @returns The opened payload, or a {@link Rejection} literal for any rejection.
 */
export async function openSealed(
    secret: string | undefined,
    value: string,
    absoluteLifetime?: number,
): Promise<OpenedPayload | Rejection> {
    const keyBytes = assertUsableSecret(secret, 'config')

    if (value.length > MAX_COOKIE_CHARS) return 'too-long'
    // Classify by prefix before touching the body. A cookie is ours only if it
    // carries the current `Crypt` marker or the legacy one; everything else is a
    // wrong format, rejected without a crypto call. Keeping the `c1.` classifier
    // here (rather than deferring wholesale to `Crypt.decrypt`) is what lets a
    // malformed `c1.` cookie earn a granular `too-short`/`bad-base64` instead of
    // collapsing to `tag-mismatch`.
    const isCrypt = value.startsWith(CRYPT_VERSION)
    const isLegacy = value.startsWith(WIRE_VERSION)
    if (!isCrypt && !isLegacy) return 'bad-prefix'

    // Structural checks are format-agnostic: both wires are the same
    // `salt(16) ‖ iv(12) ‖ ciphertext‖tag` layout under a 3-char prefix.
    let combined: Uint8Array
    try {
        combined = decodeBase64(value.slice(3))
    } catch {
        return 'bad-base64'
    }

    if (combined.byteLength < SALT_BYTES + IV_BYTES + TAG_BYTES) {
        return 'too-short'
    }

    // Authenticate. New (`c1.`) cookies go through `Crypt` — the single-home
    // primitive, which returns `null` on any tamper/wrong-key. Legacy (`v1.`)
    // cookies are opened locally under the session's own domain-separated key,
    // so no existing session is stranded (#265 backward compatibility).
    let plaintextText: string
    if (isCrypt) {
        const opened = await Crypt.decrypt(value, secret)
        if (opened === null) return 'tag-mismatch'
        plaintextText = opened
    } else {
        const salt = combined.subarray(0, SALT_BYTES)
        const iv = combined.subarray(SALT_BYTES, SALT_BYTES + IV_BYTES)
        const ciphertext = combined.subarray(SALT_BYTES + IV_BYTES)
        try {
            const plaintext = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv as BufferSource,
                    additionalData: LEGACY_AAD,
                },
                await deriveLegacyKey(keyBytes, salt),
                ciphertext as BufferSource,
            )
            plaintextText = decoder.decode(plaintext)
        } catch {
            return 'tag-mismatch'
        }
    }

    let payload: {
        d?: SessionData
        exp?: number
        iat?: number
        jti?: string
        sub?: string
    }
    try {
        payload = JSON.parse(plaintextText)
    } catch {
        return 'tag-mismatch'
    }

    if (
        typeof payload.exp !== 'number' ||
        payload.exp <= Math.floor(Date.now() / 1000)
    ) {
        return 'expired'
    }
    // The absolute cap: enforced iff a numeric `absoluteLifetime` is configured
    // (never truthiness — `0` must not silently disable it). A cap-enforced
    // payload whose `iat` is missing or non-numeric is refused, so a future
    // `seal()` change cannot let a session skip the ceiling by omission.
    if (typeof absoluteLifetime === 'number') {
        if (typeof payload.iat !== 'number') return 'absolute-expired'
        if (Math.floor(Date.now() / 1000) - payload.iat > absoluteLifetime) {
            return 'absolute-expired'
        }
    }
    if (
        typeof payload.d !== 'object' || payload.d === null ||
        Array.isArray(payload.d)
    ) {
        // `exp` was guarded and `d` was not, which is an asymmetry rather than a
        // hole — the GCM tag already proves we wrote this. It is checked anyway
        // because the alternative is that a future change to what gets sealed
        // hands a string or an array to `SessionStore` as if it were a record.
        return 'tag-mismatch'
    }

    return {
        data: payload.d,
        // `iat` is present on every cookie #137+ sealed; when the cap is off it
        // may be absent on a pre-cap cookie — fall back to `exp - lifetime` is
        // not knowable here, so default to `exp` (a conservative, never-younger
        // anchor). The driver only uses it to preserve across re-seals.
        iat: typeof payload.iat === 'number' ? payload.iat : payload.exp,
        exp: payload.exp,
        jti: typeof payload.jti === 'string' ? payload.jti : undefined,
        sub: typeof payload.sub === 'string' ? payload.sub : undefined,
    }
}
