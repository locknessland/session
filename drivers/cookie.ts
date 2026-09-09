/**
 * @fileoverview Cookie-based session driver — stateless, sealed-cookie sessions.
 *
 * The cryptographic value layer lives in `cookie_seal.ts` (seal/open, the wire
 * format, the key derivation). This module is the **per-request driver**: it
 * reads and writes the cookie, preserves the first-issuance identity across a
 * re-seal, runs the revocation check, and owns the rejection reporter. It holds
 * a Hono `Context` and is constructed fresh per request (the driver registry
 * keeps it off the per-process memo), so it must not open or leak a resource.
 *
 * **A secret is mandatory.** There is no unencrypted mode; see the `cookie_seal`
 * module note for why the `btoa` fallback was removed and must not return.
 *
 * @module @lockness/session/drivers/cookie
 */

import type { Context } from 'hono'
import { deleteCookie, getCookie, setCookie } from '@lockness/hono'
import type { SessionConfig, SessionData, SessionDriver } from '../types.ts'
import { assertUsableSecret } from '../secret.ts'
import type { RevocationStore } from './revocation_store.ts'
import {
    type IssuedIdentity,
    mintJti,
    openSealed,
    type Rejection,
    seal,
} from './cookie_seal.ts'

/** The rolling-summary window for {@link RejectionReporter}. */
const WINDOW_MS = 60_000

/**
 * Bounded rejection reporting for refused cookies.
 *
 * A rejected cookie is a tamper signal and must not be swallowed — but a log
 * line per rejection is a flooding vector the attacker controls, and warning
 * only once turns a sustained campaign into a single line for the reporter's
 * lifetime. So: warn on the first, then a rolling summary while the rate is
 * non-zero. The rejection *class* is reported; the value never is.
 *
 * **The state lives on an instance, not in module scope (#236).** The instance
 * the driver uses is process-shared by default (see the driver constructor) —
 * the signal that matters is "rejections across this process just went from
 * 0/hour to 40k/hour", and the cookie driver is built fresh per request, so a
 * per-request reporter would warn afresh on every forged cookie and never
 * accumulate. A test instead constructs a fresh reporter and drives it directly,
 * which is why there is no module-wide reset.
 *
 * @example
 * ```typescript
 * const reporter = new RejectionReporter()
 * reporter.report('bad-prefix')
 * assertEquals(reporter.lastRejection(), 'bad-prefix')
 * ```
 */
export class RejectionReporter {
    readonly #rejections = new Map<Rejection, number>()
    #firstWarned = false
    #windowStartedAt = 0
    #flushTimer: ReturnType<typeof setTimeout> | undefined
    #lastReason: Rejection | undefined

    /**
     * Record a rejection: warn on the very first, then count into the rolling
     * summary drained by a timer.
     *
     * @param reason - The rejection class. A closed literal — never the value.
     *
     * @example
     * ```typescript
     * reporter.report('tag-mismatch')
     * ```
     */
    report(reason: Rejection): void {
        this.#lastReason = reason
        const now = Date.now()

        if (!this.#firstWarned) {
            this.#firstWarned = true
            this.#windowStartedAt = now
            console.warn(
                `⚠️  Session cookie rejected (${reason}). ` +
                    'This is a tamper or a stale cookie from before a key rotation.',
            )
            // Returns WITHOUT counting it. The first rejection is reported on its
            // own line; also counting it would put it in the next summary's total
            // as well, and a count that reports one event twice is worse than no
            // count — somebody sizes an incident from it.
            return
        }

        this.#rejections.set(reason, (this.#rejections.get(reason) ?? 0) + 1)

        // Drained by a timer, not by the next rejection.
        //
        // Draining only when another rejection arrives means a burst followed by
        // silence — what a probe that gives up looks like, and the shape most
        // worth seeing — is never reported at all, and the eventual line
        // mislabels an interval that has long since passed.
        //
        // `unrefTimer` keeps this from holding the process open, so it needs no
        // shutdown hook and cannot delay an exit.
        if (this.#flushTimer === undefined) {
            this.#windowStartedAt = now
            const timer = setTimeout(() => this.#flush(), WINDOW_MS)
            Deno.unrefTimer(timer)
            this.#flushTimer = timer
        }
    }

    /**
     * The most recent rejection class.
     *
     * **Test-only observability, and deliberately absent from `mod.ts`.**
     * `open()` returns `null` for every rejection class, which is right for a
     * caller and useless for a test: an assertion that a truncated payload yields
     * `null` is equally satisfied by a tag mismatch, so it stays green with the
     * structural check deleted. This makes the class observable.
     *
     * @returns The most recent rejection class, or `undefined` if there has been
     *   none.
     *
     * @example
     * ```typescript
     * reporter.report('bad-prefix')
     * assertEquals(reporter.lastRejection(), 'bad-prefix')
     * ```
     */
    lastRejection(): Rejection | undefined {
        return this.#lastReason
    }

    /**
     * Rejections counted but not yet summarised.
     *
     * **Test-only observability, and deliberately absent from `mod.ts`.** The
     * counts only reach a human 60 seconds later, so without this the
     * first-rejection accounting is unobservable: reporting that one event both
     * on its own line and again in the next summary's total is a real defect —
     * somebody sizes an incident from that number — and no test could see it.
     *
     * @returns The pending count per rejection class.
     *
     * @example
     * ```typescript
     * assertEquals(reporter.pendingRejections(), {})
     * ```
     */
    pendingRejections(): Readonly<Record<string, number>> {
        return Object.fromEntries(this.#rejections)
    }

    /** Emit the rolling summary and clear the window. */
    #flush(): void {
        this.#flushTimer = undefined
        if (this.#rejections.size === 0) return

        const total = [...this.#rejections.values()].reduce((a, b) => a + b, 0)
        const classes = [...this.#rejections.entries()]
            .map(([k, n]) => `${k}=${n}`)
            .join(' ')
        console.warn(
            `⚠️  ${total} session cookies rejected in the last ${
                Math.round((Date.now() - this.#windowStartedAt) / 1000)
            }s — ${classes}`,
        )
        this.#rejections.clear()
    }
}

/**
 * The process-shared reporter every cookie driver uses by default.
 *
 * Process-wide by design: the tamper signal is a process-level rate, and the
 * driver is per-request. Exposed to the driver constructor as an overridable
 * default (not a hidden module singleton) so a test — or a future caller that
 * wants an isolated reporter — can inject its own instance.
 */
const sharedRejectionReporter = new RejectionReporter()

/**
 * Cookie-based session driver.
 *
 * Stores session data directly in a sealed cookie (stateless). Best for small
 * session payloads — a browser caps a cookie at roughly 4 KB, and the sealed
 * format costs 28 bytes plus base64 expansion.
 *
 * **A secret is mandatory.** There is no unencrypted mode; see the `cookie_seal`
 * module note.
 *
 * @example
 * ```typescript
 * const driver = new CookieSessionDriver(context, config)
 * await driver.write('session-id', { userId: 123 }, 3600)
 * ```
 */
export class CookieSessionDriver implements SessionDriver {
    private readonly context: Context
    private readonly config: SessionConfig
    /**
     * The process-shared revocation store, injected by the registry when
     * revocation is enabled. The driver holds only a reference — it never opens a
     * KV handle itself, so it stays per-request without leaking a handle per
     * request. Absent when revocation is off.
     */
    readonly #store?: RevocationStore
    /**
     * The rejection reporter this driver feeds when it refuses a cookie. Shared
     * across the process by default (the signal is a process-level rate and the
     * driver is per-request); injectable for isolation in tests.
     */
    readonly #reporter: RejectionReporter
    /**
     * The first-issuance identity read from the incoming cookie, preserved so a
     * re-seal in the same request keeps the original `iat`/`jti`. Undefined for a
     * brand-new session (the next `write` mints a fresh one).
     */
    #issued?: IssuedIdentity
    /**
     * The opaque subject token (#147) to embed on the next `seal()`. Read from the
     * incoming cookie so a re-seal preserves it, set explicitly by
     * {@link CookieSessionDriver.setSubject} (the guard, after every
     * `regenerate()`), and **reset on `regenerate()`** so a rotated session carries
     * no stale subject until the guard re-asserts one. Undefined for a
     * subject-less session.
     */
    #subject?: string
    /**
     * Set once `destroy()` has run, so a trailing `write()` from `save()` in the
     * same request does not re-seal a just-revoked/just-deleted session.
     */
    #destroyed = false

    /**
     * @param context - The Hono request context.
     * @param config - The resolved session configuration.
     * @param revocationStore - The process-shared revocation store, when
     *   revocation is enabled (injected by the driver registry).
     * @param reporter - The rejection reporter to feed on a refused cookie.
     *   Defaults to the process-shared instance; injectable for tests.
     * @throws {SessionSecretError} When the configured secret is unusable.
     */
    constructor(
        context: Context,
        config: SessionConfig,
        revocationStore?: RevocationStore,
        reporter: RejectionReporter = sharedRejectionReporter,
    ) {
        // Asked here, decided in secret.ts. Constructing a driver that cannot
        // seal is a configuration error, and the request path is the wrong place
        // to discover it.
        assertUsableSecret(config.secret, 'config')
        this.context = context
        this.config = config
        this.#store = revocationStore
        this.#reporter = reporter
    }

    /**
     * The TTL for a revocation entry: a full absolute-cap window from now. Longer
     * than the cookie's remaining life, so the entry always outlives every use of
     * the cookie — and raising `absoluteLifetime` later cannot expire an entry
     * before the cookie it revokes (a fixed window, not one derived from the live
     * config at read time).
     *
     * **`absoluteLifetime` only — no `?? lifetime` fallback (#147).** The
     * `@lockness/core` boot gate refuses `revocation` without `absoluteLifetime`,
     * so the cap is always set here; a `configureSession` bypass that produced a
     * short `lifetime`-bounded entry could otherwise expire before the cookie it
     * revokes, resurrecting it. Non-null assertion is safe under that gate.
     */
    #revocationTtl(): number {
        // The `@lockness/core` boot gate refuses `revocation` without
        // `absoluteLifetime`, so this is normally present. Fail LOUD rather than
        // returning `undefined` → a `NaN` KV TTL if a caller bypassed that gate
        // (e.g. a direct `configureSession`) — a NaN TTL would silently drop the
        // revocation entry (#147 review).
        const cap = this.config.absoluteLifetime
        if (cap === undefined) {
            throw new Error(
                'session revocation requires absoluteLifetime — the revocation entry has no retention horizon without it',
            )
        }
        return cap
    }

    /**
     * Read the session out of the cookie.
     *
     * The session id is ignored: this driver keeps no server-side record, so the
     * cookie *is* the session.
     *
     * @param _sessionId - Unused; the cookie carries the data.
     * @returns The session contents, or `null` for an absent, forged, tampered
     * or expired cookie. Never throws on cookie content.
     *
     * @example
     * ```typescript
     * const data = await driver.read(sessionId)
     * ```
     */
    async read(_sessionId: string): Promise<SessionData | null> {
        const value = getCookie(this.context, this.config.cookieName)
        if (!value) return null

        const opened = await openSealed(
            this.config.secret,
            value,
            this.config.absoluteLifetime,
        )
        // A string result is a rejection class — report it and refuse. Reporting
        // lives here, not in the pure `openSealed`, so the crypto path stays free
        // of side effects (#236).
        if (typeof opened === 'string') {
            this.#reporter.report(opened)
            return null
        }

        // Preserve the first-issuance identity so a re-seal in this request keeps
        // the original `iat` (cap anchor) and `jti` (revocation key). A
        // pre-feature cookie with no `jti` mints one now, so it becomes revocable
        // from its next write on; its `iat` is preserved either way.
        this.#issued = { iat: opened.iat, jti: opened.jti ?? mintJti() }
        // Preserve the subject (#147) across a re-seal in this request. A
        // subject-less cookie leaves it undefined; the guard re-asserts one after
        // login/regenerate.
        this.#subject = opened.sub

        // Revocation check — fail CLOSED. Only when opted in, a store is present,
        // and the cookie carries a `jti` (a jti-less pre-feature cookie has no
        // revocation entry and is bounded by the absolute cap instead).
        if (this.config.revocation && this.#store && opened.jti) {
            let revoked: boolean
            try {
                revoked = await this.#store.isRevoked(opened.jti)
            } catch {
                // A store outage must never let a possibly-revoked cookie
                // authenticate: refuse, do not treat the error as "not revoked".
                this.#reporter.report('revoked')
                return null
            }
            if (revoked) {
                this.#reporter.report('revoked')
                return null
            }
        }

        // Per-user eviction check (#147) — fail CLOSED, beside the per-session
        // `jti` check. Only when opted in, a store is present, and the cookie
        // carries a `sub` (a subject-less cookie has no eviction epoch and is
        // bounded by the cap). A session is refused when its first-issuance `iat`
        // is STRICTLY before its subject's eviction epoch; `iat == epoch` (same
        // second) survives, which is why "log out everywhere" also revokes the
        // acting `jti` above.
        if (this.config.revocation && this.#store && opened.sub) {
            let revokedSince: number | null
            try {
                revokedSince = await this.#store.userRevokedSince(opened.sub)
            } catch {
                // A store outage must never let a possibly-evicted cookie
                // authenticate: refuse, do not treat the error as "not evicted".
                this.#reporter.report('revoked')
                return null
            }
            if (revokedSince !== null && opened.iat < revokedSince) {
                this.#reporter.report('revoked')
                return null
            }
        }

        return opened.data
    }

    /**
     * Seal the session into the cookie.
     *
     * @param _sessionId - Unused; the cookie carries the data.
     * @param data - The session contents.
     * @param lifetime - Seconds until expiry, authenticated inside the payload
     * as well as set as `maxAge`. Only the former binds an attacker.
     * @throws {SessionSecretError} When the configured secret is unusable.
     *
     * @example
     * ```typescript
     * await driver.write(sessionId, { userId: 1 }, 7200)
     * ```
     */
    async write(
        _sessionId: string,
        data: SessionData,
        lifetime: number,
    ): Promise<void> {
        // `destroy()` already emitted a deletion and revoked the session; the
        // middleware's trailing `save()` (the session is dirty after logout) must
        // NOT re-seal it back to life with the just-revoked identity.
        if (this.#destroyed) return
        setCookie(
            this.context,
            this.config.cookieName,
            // Preserve the issued identity AND the subject across the re-seal
            // (undefined ⇒ a fresh identity is minted / no subject is embedded).
            await seal(
                this.config.secret,
                data,
                lifetime,
                this.#issued,
                this.#subject,
            ),
            {
                path: this.config.path,
                domain: this.config.domain,
                secure: this.config.secure,
                httpOnly: this.config.httpOnly,
                sameSite: this.config.sameSite,
                maxAge: lifetime,
            },
        )
    }

    /**
     * Delete the client's copy of the cookie and, when revocation is enabled,
     * revoke the session so a captured copy can no longer authenticate.
     *
     * With revocation **off** this is the original stateless behaviour — it drops
     * the client cookie and a copy captured beforehand keeps working until the
     * cap or idle `exp`. With revocation **on**, the current session's `jti` is
     * added to the revocation set (the write propagates on failure — a logout
     * that silently fails to revoke is worse than one that errors), and the
     * trailing re-seal from `save()` is suppressed so the deletion stands.
     *
     * @param _sessionId - Unused; the cookie carries the identity.
     * @throws When revocation is on and the store write fails (fail-closed).
     *
     * @example
     * ```typescript
     * await driver.destroy(sessionId)
     * ```
     */
    async destroy(_sessionId: string): Promise<void> {
        if (this.config.revocation && this.#store && this.#issued?.jti) {
            await this.#store.revoke(this.#issued.jti, this.#revocationTtl())
        }
        deleteCookie(this.context, this.config.cookieName, {
            path: this.config.path,
            domain: this.config.domain,
        })
        // Suppress the trailing re-seal (see write()): the session is gone.
        this.#destroyed = true
    }

    /**
     * Rotate the session identity.
     *
     * With revocation **off** this stays a stateless no-op beyond resetting the
     * preserved identity, so the next {@link write} mints a fresh `iat`/`jti`
     * (a fresh absolute clock — correct for a login). With revocation **on**, the
     * OLD `jti` is revoked first, so a cookie captured before the rotation can no
     * longer authenticate. **Not symmetric with `destroy()`**: `regenerate()`
     * resets the identity so the session continues under a new one; `destroy()`
     * suppresses the re-seal so the session ends.
     *
     * @param _oldId - Unused.
     * @param _newId - Unused.
     * @param _lifetime - Unused: the cookie carries its own expiry.
     * @throws When revocation is on and the store write fails (fail-closed).
     *
     * @example
     * ```typescript
     * await driver.regenerate(oldId, newId, lifetime)
     * ```
     */
    async regenerate(
        _oldId: string,
        _newId: string,
        _lifetime: number,
    ): Promise<void> {
        if (this.config.revocation && this.#store && this.#issued?.jti) {
            await this.#store.revoke(this.#issued.jti, this.#revocationTtl())
        }
        // Reset so the next write mints a fresh identity (new clock, new nonce)
        // AND carries no stale subject — the guard re-asserts `sub` after every
        // `regenerate()` (#147), so a set-before-regenerate would be lost here.
        this.#issued = undefined
        this.#subject = undefined
    }

    /**
     * Stash the opaque subject token to embed on the next {@link write} (#147).
     *
     * Cookie-only — the optional `SessionDriver.setSubject?` the server-side
     * drivers do not implement. The session layer never interprets `sub`; the
     * auth guard calls this after every `regenerate()` so the rotated session
     * carries its subject and the per-user eviction check has a key.
     *
     * @param sub - The opaque subject token (the authenticated principal's id).
     *
     * @example
     * ```typescript
     * driver.setSubject('42')
     * ```
     */
    setSubject(sub: string): void {
        this.#subject = sub
    }

    /**
     * Evict every session of a subject (#147): record the subject's eviction
     * epoch so a cookie whose `iat` predates it is refused by {@link read}.
     *
     * Cookie-only — the optional `SessionDriver.revokeUser?`. A no-op when
     * revocation is off or no store is present. The epoch value itself is computed
     * in the store (plan §5 row 5); the driver only supplies the retention window.
     *
     * @param sub - The opaque subject token to evict.
     * @throws When revocation is on and the store write fails (fail-closed — a
     *   silent log-out-everywhere failure is worse than one that errors).
     *
     * @example
     * ```typescript
     * await driver.revokeUser('42')
     * ```
     */
    async revokeUser(sub: string): Promise<void> {
        if (this.config.revocation && this.#store) {
            await this.#store.revokeUser(sub, this.#revocationTtl())
        }
    }
}
