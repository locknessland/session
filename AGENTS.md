# `@lockness/session` — agent brief

Session management across four drivers (cookie, memory, Deno KV, Redis).
`store.ts` holds driver-independent behaviour, `middleware.ts` attaches the
session to the request context. `@lockness/auth`'s session guard reads through
this.

User-facing documentation: [README.md](README.md) ·
[docs/DOCS.md](docs/DOCS.md). This brief does not repeat it.

## Invariants

- **The dependency contract above is binding.** Importing anything outside it
  fails `deno task deps:analyze`, and the failure is a design question, not a
  lint to silence.

- **There is no unencrypted cookie path.** The cookie driver refuses to
  construct without a usable secret. It once fell back to `btoa` when the secret
  was empty — and empty was the package default — so the documented
  `sessionMiddleware()` call shipped an attacker-writable cookie that
  `@lockness/auth`'s session guard trusted. Nothing may reintroduce a
  compatibility read path: that is a window in which forged cookies still work.
- **"Is this secret usable" is decided in `secret.ts` and nowhere else.** The
  cookie driver and the bootstrap step _ask_; a second test is a second decider,
  and two deciders agree only until one of them changes.
- **This package never reads `Deno.env` and never asks whether it is in
  production.** A library cannot know, and reading env needs a permission its
  consumer did not grant. Core resolves; this package validates.
- **Every sealed cookie has its own salt, so every derived key encrypts exactly
  one message.** That is why the ~2³² random-96-bit-IV ceiling does not apply.
  Caching the derived key — the first optimisation anyone proposes on seeing
  HKDF called per request — silently reinstates it. If it is ever cached, the IV
  must become a counter.
- **The key never reaches output.** `SessionSecretError` cannot be constructed
  with the value, and the rejection logger reports a closed union of literal
  classes, never the offending cookie.
- **The session id is validated at the boundary.** It reaches a storage backend
  as a key, from a cookie Hono has already URL-decoded, so `%0D%0A` arrives as
  raw CR/LF. `middleware.ts` accepts only `/^[0-9a-f]{64}$/`.

## Dependency contract

<!-- generated:deps -->

| Direction                                      | Packages                                                                                                                    |
| :--------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------- |
| Imports (static)                               | `contract`, `crypto`, `hono`, `redis`                                                                                       |
| Imports (soft, via `tryImportOptionalPackage`) | —                                                                                                                           |
| Imported by                                    | `auth`, `core`, `devtools`                                                                                                  |
| **Must never import**                          | `auth`, `auth-provider`, `core`, `devtools`, `testing` — each already reaches this package, so importing one closes a cycle |

Enforced by `deno task deps:analyze` against `deps.policy.jsonc`. A soft edge is
deliberately **not** declared in this package's `deno.json`: the consuming
application installs it, or the feature stays off.

<!-- /generated:deps -->

## Public surface

<!-- generated:surface -->

| Kind      | Exports                                                                                                                         |
| :-------- | :------------------------------------------------------------------------------------------------------------------------------ |
| class     | `CookieSessionDriver`, `DenoKvSessionDriver`, `MemorySessionDriver`, `RedisSessionDriver`, `SessionSecretError`, `SessionStore` |
| function  | `assertUsableSecret`, `configureSession`, `getSession`, `getSessionConfig`, `sessionMiddleware`                                 |
| interface | `RedisConfig`, `Session`, `SessionConfig`, `SessionData`, `SessionDriver`                                                       |
| typeAlias | `SecretRejection`, `SecretSource`                                                                                               |
| variable  | `KEY_BYTES`, `KEY_PREFIX`, `REJECTED`, `generateAppKey`                                                                         |

Anything not listed is internal and free to change.

<!-- /generated:surface -->

## Where to work

| Concern                                 | Path            |
| --------------------------------------- | --------------- |
| Driver-independent behaviour            | `store.ts`      |
| A backend                               | `drivers/*.ts`  |
| Request attachment and cookie lifecycle | `middleware.ts` |
| Configuration shape                     | `config.ts`     |

## Pitfalls

- The cookie driver stores state client-side: it has a hard size limit, and it
  seals rather than signs — `v1.` + base64(`salt ‖ iv ‖ ciphertext`),
  AES-256-GCM under a per-cookie HKDF key, with `exp` inside the ciphertext
  because `maxAge` is a browser hint an attacker ignores.
- `createDriver` runs **per request** (`middleware.ts`), so a driver holding
  instance state holds it for one request only. That is why the memory driver
  does not persist across requests — see #138 and #142.
- Session middleware must run before auth middleware, or the session guard finds
  no session and fails closed.

## Tests

<!-- generated:tests -->

25 test files for 18 source files:

- `packages/session/tests/config_resolution.test.ts`
- `packages/session/tests/cookie_absolute_lifetime.test.ts`
- `packages/session/tests/cookie_revocation.test.ts`
- `packages/session/tests/driver_memo.test.ts`
- `packages/session/tests/drivers.test.ts`
- `packages/session/tests/memory_regenerate_ttl.test.ts`
- `packages/session/tests/middleware.test.ts`
- `packages/session/tests/no_placeholder_keys.test.ts`
- `packages/session/tests/redis_error.test.ts`
- `packages/session/tests/redis_lifecycle.test.ts`
- `packages/session/tests/redis_login_e2e.test.ts`
- `packages/session/tests/redis_mutex.test.ts`
- `packages/session/tests/redis_regenerate.test.ts`
- `packages/session/tests/redis_wire.test.ts`
- `packages/session/tests/regenerate_atomicity.test.ts`
- `packages/session/tests/regenerate_fixation.test.ts`
- `packages/session/tests/regenerate_ttl.test.ts`
- `packages/session/tests/reporter_wiring.test.ts`
- `packages/session/tests/reporting.test.ts`
- `packages/session/tests/resp.test.ts`
- `packages/session/tests/secret.test.ts`
- `packages/session/tests/secure_default.test.ts`
- `packages/session/tests/store.test.ts`
- `packages/session/tests/user_revocation.test.ts`
- `packages/session/tests/wire_format.test.ts`

<!-- /generated:tests -->

## Before you call it done

<!-- generated:gate -->

The framework-wide gate, from the repository root:

```bash
deno fmt && deno lint && deno check && deno task test
deno task deps:analyze     # cycles, declaration drift, tier policy
deno task agents:brief     # refresh this file's generated blocks
```

Then, specific to this package: run its 25 test files directly —

```bash
deno test -A packages/session/
```

<!-- /generated:gate -->

---

_Framework-wide rules live in the root [AGENTS.md](../../AGENTS.md). The
dependency contract, public surface and test sections are generated by
`deno task agents:brief` — edit the code, not those blocks._
