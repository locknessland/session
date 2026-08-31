# Session Management

Lockness provides a robust, multi-driver session management system. It allows
you to store user data across requests securely and efficiently.

---

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
    secret: Deno.env.get('APP_KEY') || 'a-very-long-secret-key-32-chars',
    lifetime: 7200, // 2 hours
    secure: Deno.env.get('APP_ENV') === 'production',
})
```

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
