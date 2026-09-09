# @lockness/session

Multi-driver session management system with support for Cookie, Memory, Deno KV,
and **Redis** storage.

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

## Features

- 🔐 **Encrypted Cookie Sessions** - AES-GCM encryption for secure client-side
  storage
- 🗄️ **Multiple Drivers** - Cookie, Memory, Deno KV, and **Redis** support
- ⚡ **Flash Messages** - One-time messages for next request
- 🔄 **Session Regeneration** - Security feature for authentication
- ⏱️ **Automatic Expiration** - Configurable session lifetime
- 🧹 **Garbage Collection** - Automatic cleanup of expired sessions
- 🔒 **Secure by Default** - HttpOnly, SameSite, and HTTPS options
- 📦 **Modular Architecture** - SOLID principles with focused, single-purpose
  modules

## Architecture

The package follows a modular architecture with clear separation of concerns:

```
┌─────────────────────────────────────────┐
│  Public API (mod.ts)                     │  ← Single entry point, re-exports all APIs
├─────────────────────────────────────────┤
│  Core Modules                            │
│  ├─ types.ts        - Type definitions   │
│  ├─ config.ts       - Configuration      │
│  ├─ utils.ts        - Utility functions  │
│  ├─ store.ts        - SessionStore       │
│  └─ middleware.ts   - Middleware factory │
├─────────────────────────────────────────┤
│  Drivers Layer (drivers/)                │
│  ├─ cookie.ts       - Cookie driver      │
│  ├─ memory.ts       - Memory driver      │
│  ├─ deno_kv.ts      - Deno KV driver     │
│  ├─ redis.ts        - Redis driver       │
│  └─ mod.ts          - Driver factory     │
└─────────────────────────────────────────┘
```

### SOLID Principles

- **Single Responsibility**: Each module handles one concern (types, config,
  drivers, etc.)
- **Open/Closed**: New drivers can be added without modifying existing code
- **Liskov Substitution**: All drivers implement the same `SessionDriver`
  interface
- **Interface Segregation**: Clean interfaces without unnecessary methods
- **Dependency Inversion**: Middleware depends on driver abstraction, not
  concrete implementations

## Installation

```typescript
import {
    configureSession,
    getSession,
    sessionMiddleware,
} from '@lockness/session'
```

## Quick Start

### Configure Session

```typescript
import { configureSession } from '@lockness/session'

configureSession({
    driver: 'cookie', // or 'memory', 'deno-kv', 'redis'
    secret: Deno.env.get('APP_KEY')!,
    lifetime: 7200, // 2 hours
    cookieName: 'app_session',
    secure: true, // HTTPS only
    httpOnly: true,
    sameSite: 'Lax',
})
```

### Use Middleware

```typescript
import { Hono } from 'hono'
import { getSession, sessionMiddleware } from '@lockness/session'

const app = new Hono()

app.use('*', sessionMiddleware())

app.get('/profile', (c) => {
    const session = getSession(c)
    const userId = session.get<number>('userId')

    if (!userId) {
        return c.redirect('/login')
    }

    return c.text(`User ID: ${userId}`)
})

app.post('/login', async (c) => {
    const session = getSession(c)

    // Authenticate user...
    session.set('userId', 123)

    // Regenerate ID for security
    await session.regenerate()

    session.flash('message', 'Login successful!')
    return c.redirect('/dashboard')
})

app.get('/dashboard', (c) => {
    const session = getSession(c)
    const message = session.getFlash<string>('message')

    return c.html(`<h1>${message}</h1>`)
})
```

## Drivers

### Cookie Driver (Default)

Stores encrypted session data in a client-side cookie using AES-GCM encryption.

**Pros:**

- No server-side storage required
- Scales horizontally without shared state
- Works with any deployment model

**Cons:**

- Limited to ~4KB of data
- Cookie size affects every request
- Not suitable for large session data

```typescript
configureSession({
    driver: 'cookie',
    secret: Deno.env.get('APP_KEY')!,
    cookieName: 'app_session',
    lifetime: 7200,
})
```

### Memory Driver

Stores sessions in server memory. **For development/testing only.**

**Pros:**

- Fast, no I/O
- Simple for testing

**Cons:**

- Data lost on server restart
- Doesn't work with multiple instances
- Memory usage grows over time

```typescript
configureSession({
    driver: 'memory',
    secret: Deno.env.get('APP_KEY')!,
    cookieName: 'dev_session',
})
```

### Deno KV Driver

Stores sessions in Deno's built-in key-value database.

**Pros:**

- Persistent storage
- Built into Deno
- Automatic expiration (TTL)
- Works on Deno Deploy

**Cons:**

- Deno-specific
- Not suitable for very high traffic

```typescript
configureSession({
    driver: 'deno-kv',
    secret: Deno.env.get('APP_KEY')!,
    kvPath: './data/kv', // Optional path
    cookieName: 'kv_session',
    lifetime: 7200,
})
```

### Redis Driver ⭐

Stores sessions in Redis for production scalability.

**Pros:**

- Production-ready
- Scales horizontally
- Shared state across multiple servers
- Automatic expiration (TTL)
- Fast in-memory performance

**Cons:**

- Requires Redis server
- Additional infrastructure

```typescript
configureSession({
    driver: 'redis',
    secret: Deno.env.get('APP_KEY')!,
    cookieName: 'redis_session',
    lifetime: 7200,
    redis: {
        hostname: 'localhost',
        port: 6379,
        password: 'optional-password',
        db: 0, // Database number (default: 0)
    },
})
```

#### Redis Setup

**Local Development:**

```bash
# macOS
brew install redis
brew services start redis

# Docker
docker run -d -p 6379:6379 redis:7-alpine
```

**Production (Fly.io example):**

```bash
fly redis create my-redis
fly redis connect my-redis # Get connection details
```

**Environment Variables:**

```typescript
configureSession({
    driver: 'redis',
    secret: Deno.env.get('SESSION_SECRET')!,
    redis: {
        hostname: Deno.env.get('REDIS_HOST') || 'localhost',
        port: parseInt(Deno.env.get('REDIS_PORT') || '6379'),
        password: Deno.env.get('REDIS_PASSWORD'),
    },
})
```

## API Reference

### Session Methods

```typescript
const session = getSession(c)

// Get/Set values
session.get<T>(key: string, defaultValue?: T): T | undefined
session.set(key: string, value: unknown): void
session.has(key: string): boolean
session.forget(key: string): void
session.all(): SessionData
session.flush(): void

// Session lifecycle
await session.regenerate() // New ID (use after login)
await session.destroy()    // Delete session

// Flash messages (one-time)
session.flash(key: string, value: unknown)
session.getFlash<T>(key: string): T | undefined

// Metadata
session.getId(): string
session.isDirty(): boolean
```

### Configuration Options

```typescript
interface SessionConfig {
    driver: 'cookie' | 'memory' | 'deno-kv' | 'redis'
    cookieName: string // Cookie name
    lifetime: number // Seconds (default: 7200)
    secret: string // Min 32 characters for encryption
    path: string // Cookie path (default: '/')
    domain?: string // Cookie domain
    secure: boolean // HTTPS only (default: false)
    httpOnly: boolean // No JS access (default: true)
    sameSite: 'Strict' | 'Lax' | 'None' // Default: 'Lax'
    kvPath?: string // Deno KV path
    redis?: {
        hostname: string
        port?: number
        password?: string
        db?: number
    }
}
```

## Flash Messages

Flash data is available only for the **next request**, then automatically
deleted.

```typescript
// Request 1: Set flash
app.post('/update', (c) => {
    const session = getSession(c)
    session.flash('success', 'Profile updated!')
    return c.redirect('/profile')
})

// Request 2: Get flash (only once)
app.get('/profile', (c) => {
    const session = getSession(c)
    const message = session.getFlash<string>('success')
    // message = 'Profile updated!'
    return c.html(`<div>${message}</div>`)
})

// Request 3: Flash is gone
app.get('/profile', (c) => {
    const session = getSession(c)
    const message = session.getFlash<string>('success')
    // message = undefined
})
```

## Security Best Practices

### 1. **Use Strong Secrets**

```typescript
// ❌ Bad
secret: Deno.env.get('APP_KEY')!

// ✅ Good (min 32 characters)
secret: crypto.randomUUID() + crypto.randomUUID()
```

### 2. **Regenerate After Login**

```typescript
app.post('/login', async (c) => {
    const session = getSession(c)

    // Authenticate user...
    session.set('userId', user.id)

    // Prevent session fixation attacks
    await session.regenerate()

    return c.redirect('/dashboard')
})
```

### 3. **Enable Secure Cookies in Production**

```typescript
configureSession({
    secure: true, // HTTPS only
    httpOnly: true, // No JavaScript access
    sameSite: 'Strict', // CSRF protection
})
```

### 4. **Use Redis in Production**

```typescript
// Don't use 'memory' driver in production
// Use 'redis' for scalability and persistence
configureSession({
    driver: 'redis',
    redis: { hostname: 'redis.internal', port: 6379 },
})
```

### 5. **Set Appropriate Lifetime**

```typescript
configureSession({
    lifetime: 1800, // 30 minutes for sensitive apps
    // lifetime: 86400  // 24 hours for general apps
})
```

## Driver Comparison

| Feature            | Cookie     | Memory  | Deno KV     | Redis      |
| ------------------ | ---------- | ------- | ----------- | ---------- |
| **Persistent**     | ✅         | ❌      | ✅          | ✅         |
| **Multi-instance** | ✅         | ❌      | ❌          | ✅         |
| **Size limit**     | ~4KB       | ∞       | Large       | Large      |
| **Production**     | ✅         | ❌      | ⚠️          | ✅         |
| **Auto-expire**    | Browser    | Manual  | ✅          | ✅         |
| **Setup**          | None       | None    | None        | Redis      |
| **Best for**       | Small data | Testing | Deno Deploy | Production |

## Migration from Core

If you were using `lockness/core/session.ts`:

```typescript
// Old
import { getSession, sessionMiddleware } from '@lockness/contract'

// New
import { getSession, sessionMiddleware } from '@lockness/session'
```

Configuration and API remain the same.

## Testing

```bash
cd lockness/session
deno task test
```

**Note:** Redis driver tests require a running Redis instance on
`localhost:6379`. Use mock or Memory driver for CI/CD.

## License

MIT
