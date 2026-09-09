/**
 * @fileoverview An in-memory `Deno.Kv` double for the session driver tests.
 *
 * It exists to answer questions the real `Deno.Kv` cannot be asked in a test:
 * **what `expireIn` was applied to a written key** (SC-002 — the real store
 * exposes no remaining TTL), and **what an atomic rotation leaves behind when
 * its commit is forced to fail** (SC-007). It implements only the surface the
 * `DenoKvSessionDriver` touches — `get`, `set`, `delete`, `atomic().set()
 * .delete().commit()`, `close` — and records the `expireIn` of every write so a
 * test can assert the TTL a regenerate carried.
 *
 * It is never imported by production code; it is stubbed in via
 * `Object.defineProperty(Deno, 'openKv', …)`, the supported way to replace the
 * getter-only `Deno.openKv`.
 *
 * @module @lockness/session/tests/fake_kv
 */

/** One stored value plus the `expireIn` (ms) the write carried, if any. */
export interface FakeKvEntry {
    /** The stored value. */
    value: unknown
    /** The `expireIn` in milliseconds the write declared, or `undefined`. */
    expireInMs?: number
    /** `Date.now()` at write time — used to honour expiry on read. */
    writtenAt: number
}

/** An op queued on a {@link FakeAtomic} until `commit()`. */
type AtomicOp =
    | { kind: 'set'; key: string; value: unknown; expireInMs?: number }
    | { kind: 'delete'; key: string }

/**
 * The atomic builder returned by {@link FakeKv.atomic}.
 *
 * Mirrors the fluent `Deno.AtomicOperation` shape used by the driver: `set` and
 * `delete` queue ops, and `commit` applies them all-or-nothing. A commit forced
 * to fail applies **none** of them, modelling Deno KV's transactional guarantee.
 */
export class FakeAtomic {
    readonly #kv: FakeKv
    readonly #ops: AtomicOp[] = []

    constructor(kv: FakeKv) {
        this.#kv = kv
    }

    /**
     * Queue a set, recording its `expireIn`.
     * @param key - The KV key parts.
     * @param value - The value to store.
     * @param options - Optional `{ expireIn }` in milliseconds.
     * @returns This builder, for chaining.
     */
    set(
        key: readonly unknown[],
        value: unknown,
        options?: { expireIn?: number },
    ): this {
        this.#ops.push({
            kind: 'set',
            key: JSON.stringify(key),
            value,
            expireInMs: options?.expireIn,
        })
        return this
    }

    /**
     * Queue a delete.
     * @param key - The KV key parts.
     * @returns This builder, for chaining.
     */
    delete(key: readonly unknown[]): this {
        this.#ops.push({ kind: 'delete', key: JSON.stringify(key) })
        return this
    }

    /**
     * Apply every queued op atomically, or none if the commit is forced to fail.
     * @returns `{ ok: true }` on success, `{ ok: false }` when forced to fail.
     */
    commit(): Promise<{ ok: boolean; versionstamp?: string }> {
        if (this.#kv.failNextCommit) {
            this.#kv.failNextCommit = false
            return Promise.resolve({ ok: false })
        }
        for (const op of this.#ops) {
            if (op.kind === 'set') {
                this.#kv.store.set(op.key, {
                    value: op.value,
                    expireInMs: op.expireInMs,
                    writtenAt: Date.now(),
                })
            } else {
                this.#kv.store.delete(op.key)
            }
        }
        return Promise.resolve({ ok: true, versionstamp: '00000000' })
    }
}

/**
 * An in-memory stand-in for `Deno.Kv` covering the driver's surface.
 *
 * @example
 * ```typescript
 * const fake = new FakeKv()
 * const realOpenKv = Deno.openKv
 * Object.defineProperty(Deno, 'openKv', {
 *   configurable: true,
 *   value: () => Promise.resolve(fake as unknown as Deno.Kv),
 * })
 * try {
 *   // …exercise DenoKvSessionDriver…
 * } finally {
 *   Object.defineProperty(Deno, 'openKv', { configurable: true, value: realOpenKv })
 * }
 * ```
 */
export class FakeKv {
    /** The backing store, keyed by the JSON-encoded key parts. */
    readonly store = new Map<string, FakeKvEntry>()
    /** When true, the next `atomic().commit()` applies nothing and reports failure. */
    failNextCommit = false

    #key(key: readonly unknown[]): string {
        return JSON.stringify(key)
    }

    /**
     * Read a value, honouring any recorded `expireIn`.
     * @param key - The KV key parts.
     * @returns A `Deno.KvEntryMaybe`-shaped result (`value` is `null` if absent).
     */
    get<T = unknown>(
        key: readonly unknown[],
    ): Promise<
        {
            key: readonly unknown[]
            value: T | null
            versionstamp: string | null
        }
    > {
        const entry = this.store.get(this.#key(key))
        if (!entry) {
            return Promise.resolve({ key, value: null, versionstamp: null })
        }
        if (
            entry.expireInMs !== undefined &&
            Date.now() > entry.writtenAt + entry.expireInMs
        ) {
            this.store.delete(this.#key(key))
            return Promise.resolve({ key, value: null, versionstamp: null })
        }
        return Promise.resolve({
            key,
            value: entry.value as T,
            versionstamp: '00000000',
        })
    }

    /**
     * Write a value, recording its `expireIn`.
     * @param key - The KV key parts.
     * @param value - The value to store.
     * @param options - Optional `{ expireIn }` in milliseconds.
     * @returns `{ ok: true }`.
     */
    set(
        key: readonly unknown[],
        value: unknown,
        options?: { expireIn?: number },
    ): Promise<{ ok: true; versionstamp: string }> {
        this.store.set(this.#key(key), {
            value,
            expireInMs: options?.expireIn,
            writtenAt: Date.now(),
        })
        return Promise.resolve({ ok: true, versionstamp: '00000000' })
    }

    /**
     * Delete a value.
     * @param key - The KV key parts.
     */
    delete(key: readonly unknown[]): Promise<void> {
        this.store.delete(this.#key(key))
        return Promise.resolve()
    }

    /**
     * Begin an atomic operation.
     * @returns A fresh {@link FakeAtomic}.
     */
    atomic(): FakeAtomic {
        return new FakeAtomic(this)
    }

    /** Close the store (no-op; present for the driver's shutdown path). */
    close(): void {}

    /**
     * Read the recorded entry for a session id, for TTL assertions.
     * @param sessionId - The session id whose `['sessions', id]` entry to fetch.
     * @returns The recorded entry, or `undefined` if absent.
     */
    entryFor(sessionId: string): FakeKvEntry | undefined {
        return this.store.get(this.#key(['sessions', sessionId]))
    }
}
