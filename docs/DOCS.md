# Session Management

Lockness provides a robust, multi-driver session management system. It allows
you to store user data across requests securely and efficiently.

---

## The application key

`APP_KEY` is **key material**, not a password. It must be `base64:` followed by
exactly 32 random bytes, base64-encoded — the shape `lockness init` generates:

```
APP_KEY=base64:xQ8vN2mK...44 characters...=
```

Anything else is refused at boot. There is no fallback, no default and no
unencrypted mode: a cookie-driver application with no usable key **does not
start** in production, and outside production it runs on a random key generated
for that process only (so sessions do not survive a restart).

### If you have been running on a placeholder key — rotate

Earlier versions fell back to a key committed to this repository, and the cookie
driver silently skipped encryption entirely when the key was empty — which was
the package default. **Every session cookie ever issued under either condition
is forgeable by anyone**, and stays forgeable until `APP_KEY` is rotated.
Upgrading does not undo cookies already issued.

Generate a new one and deploy it:

```bash
deno eval "const b=crypto.getRandomValues(new Uint8Array(32));let s='';for(const x of b)s+=String.fromCharCode(x);console.log('base64:'+btoa(s))"
```

Every user is signed out once when the key changes. That is the intended cost:
the alternative is honouring cookies issued under a key the whole internet has.

## 🚀 Features

- 🔐 **Encrypted Cookie Sessions** (AES-GCM encryption)
- 🗄️ **Multiple Drivers**: Cookie, Memory, Deno KV, and Redis.
- ⚡ **Flash Messages**: One-time messages for next request.
- 🔄 **Session Regeneration**: Security best practices for login.

---

## ⚙️ Configuration

Sessions are configured in your `app/kernel.ts` using the `configureSession()`
function.

```typescript
import { configureSession, sessionMiddleware } from '@lockness/core'

configureSession({
    driver: 'cookie', // 'cookie' | 'deno-kv' | 'memory' | 'redis'
    secret: Deno.env.get('APP_KEY'),
    lifetime: 7200, // 2 hours — the IDLE window, refreshed on every write
    absoluteLifetime: 604800, // 7 days — the hard ceiling (optional; see below)
    revocation: true, // optional; requires absoluteLifetime (cookie driver)
    // `secure` is optional: it defaults to true unless DENO_ENV/APP_ENV is
    // explicitly 'development' (fail-closed). Set it only to override that —
    // e.g. `secure: false` for a plaintext-localhost setup without the env var.
})
```

### `lifetime` vs `absoluteLifetime`

- **`lifetime`** is the **idle** window: seconds of inactivity after which a
  session expires. It is refreshed on every write, so an active session keeps
  going.
- **`absoluteLifetime`** is the **hard ceiling**: seconds since the session was
  **first issued**, never refreshed by activity. Once `now - iat` exceeds it the
  session is refused no matter how recently it was used — bounding how long a
  captured cookie can be replayed. It is **opt-in**: leave it unset for no cap
  (`0`/negative is a configuration error, not "off"). Recommended when enabled:
  `604800` (7 days). A cap below `lifetime` simply evicts sooner. Only the
  cookie driver enforces it today.

### Cookie revocation and its limits

`revocation: true` (cookie driver only, **requires `absoluteLifetime`**) makes
logout and id-rotation add the session's nonce to a Deno-KV revocation set, so a
**captured copy of a logged-out cookie can no longer authenticate** — closing
the "a stateless logout revokes nothing" gap. With it on, `open()` does one KV
read per request and **fails closed** (a KV outage refuses the cookie rather
than letting a possibly-revoked one through), and the process holds a KV handle;
with it off the cookie driver stays fully stateless.

What it does **not** do, and what to reach for instead:

- **It does not evict a stolen cookie used _before_ logout.** The cap bounds the
  **maximum** exposure; within the window a stolen cookie authenticates as the
  victim until logout or the ceiling.
- Lowering `absoluteLifetime` later is safe; **raising** it does not re-horizon
  revocation entries already written.
- For a server-side session record, the `deno-kv` or `redis` driver keeps one
  and can be evicted by deleting it — a different mechanism than the cookie
  driver's revocation set.

**Per-user eviction — "log out everywhere" (#147).** Alongside the per-session
`jti` set, the cookie driver keeps a **per-user eviction epoch**: one Deno-KV
timestamp per subject meaning "sessions issued before this instant are dead".
The session cookie carries an opaque `sub` (subject) claim inside its sealed
plaintext (the session layer never interprets it — the auth guard populates it),
and `read()` refuses a cookie whose first-issuance `iat` is **strictly before**
its subject's epoch — fail-closed and strongly consistent, exactly like the
per-session check. One store write evicts every prior session of a user, so a
password change or account recovery **can** now evict existing sessions. The
epoch entry is retained for a fixed `absoluteLifetime` window (never
`lifetime`), so raising the cap later cannot resurrect an evicted session. This
is driven from `@lockness/auth`'s `guard.logoutEverywhere()` /
`guard.logoutOthers()` — see the auth docs. Same precondition as per-session
revocation: **`revocation: true` requires `absoluteLifetime`**, refused at boot
otherwise.

To enable sessions, you must add the `sessionMiddleware()` using the fluent API:

```typescript
app.useMiddleware(
    sessionMiddleware(),
    // ...
)

await app.init({
    controllers,
})
```

---

## 🛠 Usage in Controllers

Access the session using the `session(c)` helper.

### Getting and Setting Data

```typescript
@Controller('/dashboard')
export class DashboardController {
    @Get('/')
    index(c: Context) {
        const sess = session(c)

        // Set a value
        sess.set('theme', 'dark')

        // Get a value (with optional default)
        const visits = sess.get('visits', 0) as number
        sess.set('visits', visits + 1)

        return c.json({ visits })
    }
}
```

### Flash Messages

Flash messages are available only for the **next request**, which is perfect for
success or error notifications after a redirect.

```typescript
@Post('/login')
async login(c: Context) {
    // ...
    session(c).flash('success', 'Welcome back!')
    return c.redirect('/dashboard')
}

// In dashboard controller
@Get('/dashboard')
index(c: Context) {
    const successMessage = session(c).getFlash('success')
    return c.html(/* ... */)
}
```

---

## 🛡 Security

### Session Regeneration

To prevent session fixation attacks, you should **always** regenerate the
session ID after a successful login.

```typescript
@Post('/login')
async login(c: Context) {
    // ... logic
    await session(c).regenerate()
    session(c).set('user_id', user.id)
    return c.redirect('/profile')
}
```

`regenerate()` carries the session data to a fresh id and gives it a **fresh
lifetime** — the same `lifetime` a `write()` applies, drawn from the one source,
`SessionConfig.lifetime` — not the remaining lifetime left on the old id. On the
**Deno KV** and **Redis** drivers the rotation is **atomic**: the new key is
written and the old key destroyed as one indivisible operation (Deno KV via
`kv.atomic()`, Redis via a single `EVAL` script), so no failure path can leave
the authenticated data on the new id while the attacker-known old id also still
resolves.

### Session Destruction

To log out a user or clear all data:

```typescript
@Post('/logout')
async logout(c: Context) {
    await session(c).destroy()
    return c.redirect('/login')
}
```

---

## 🗄️ Drivers

| Driver      | Description                   | Best for                |
| ----------- | ----------------------------- | ----------------------- |
| **cookie**  | Encrypted client-side storage | Small data, Stateless   |
| **deno-kv** | Deno's native Key-Value store | Deno Deploy, Persistent |
| **redis**   | External Redis server         | Scalable Production     |
| **memory**  | In-memory storage             | Development only        |

### Redis driver reliability

The Redis driver speaks RESP2 over a single connection with no external
dependency. Two behaviours worth knowing:

- **A read failure is never a silent logout.** `read()` returns `null` **only**
  for a genuine cache miss (a RESP nil reply). A connection or protocol failure
  is logged once at ERROR (with the session id redacted to a short fingerprint —
  it is a bearer credential) and propagates as an error, which the framework
  renders as a generic 500. An outage is therefore distinguishable from a miss,
  rather than logging every user out with no trace.
- **Replies are drained in full and bounded.** Reply reading lives in
  `packages/redis/resp.ts` (`readReply`, beside `writeFrame`): it drains the
  connection until the RESP reply is complete, so a session larger than one
  4096-byte read round-trips intact, and it rejects a server-declared bulk
  length beyond 10 MiB before allocating it.
- **One shared, serialized connection per process.** The driver is memoized per
  process per resolved config (like `deno-kv`), so a redis-backed app opens
  **one** authenticated connection, not one per request. Sharing is safe because
  every command is serialized on the connection — two overlapping calls never
  interleave their frames; the second's write begins only after the first's
  reply is fully drained. `connect()` is single-flighted (a concurrent
  cold-start opens one socket), a mid-stream failure closes the socket and the
  next command transparently reconnects, and the connection is released through
  the framework's shutdown drain. Two configs on the same host with **different
  passwords** never share a socket: the memo key carries a SHA-256 digest of the
  password (never the cleartext), so the credential also stays out of logs.
