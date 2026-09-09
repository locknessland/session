/**
 * When session configuration is resolved, and what the session id may be.
 *
 * The first of these is the defect that made #137 reachable on every kernel
 * application: `sessionMiddleware()` snapshotted the global config at
 * factory-call time, and the kernel calls that factory (in a field initialiser,
 * `loader.ts:136`) *before* bootstrap runs `configureSession` (`loader.ts:162`).
 * The middleware therefore held `secret: ''` no matter what the operator set.
 */

import { assertEquals } from '@std/assert'
import { Hono } from 'hono'
import { configureSession, getSession, sessionMiddleware } from '../mod.ts'
import { generateAppKey } from '../secret.ts'

/** The exact value from #137's report. */
const FORGERY = 'JTdCJTIyYXV0aF93ZWIlMjIlM0ExJTdE'

Deno.test('config - a secret set AFTER the factory call still reaches the driver', async () => {
    // The kernel's ordering, reproduced. Before FR-012 this emitted the #137
    // cookie value verbatim with a perfectly good key configured.
    const middleware = sessionMiddleware()
    configureSession({ driver: 'cookie', secret: generateAppKey() })

    const app = new Hono()
    app.use('*', middleware)
    app.get('/', (c) => {
        getSession(c).set('auth_web', 1)
        return c.text('ok')
    })

    const cookie = (await app.request('http://localhost/')).headers.get(
        'set-cookie',
    ) ?? ''

    assertEquals(
        cookie.includes(FORGERY),
        false,
        'the middleware emitted the unencrypted #137 cookie',
    )
    // Sealed through @lockness/crypto's Crypt since #265 — the `c1.` wire.
    assertEquals(cookie.includes('lockness_session=c1.'), true)
})

Deno.test('config - a session id that is not 64 hex characters is discarded', async () => {
    // FR-020. The id goes straight to a storage backend as a key
    // (redis.ts:114, deno_kv.ts:41), and Hono URL-decodes the cookie before we
    // see it — so %0D%0A arrives as raw CR/LF. Sending the encoded form is the
    // point of the test.
    configureSession({ driver: 'memory', secret: generateAppKey() })

    const app = new Hono()
    app.use('*', sessionMiddleware({ driver: 'memory' }))
    app.get('/', (c) => c.text(getSession(c).getId()))

    for (
        const hostile of [
            'session%0D%0AFLUSHALL',
            'not-hex-at-all',
            'a'.repeat(63),
            'a'.repeat(65),
            'A'.repeat(64), // uppercase: generateSessionId emits lowercase
        ]
    ) {
        const res = await app.request('http://localhost/', {
            headers: { cookie: `lockness_session=${hostile}` },
        })
        const id = await res.text()

        assertEquals(/^[0-9a-f]{64}$/.test(id), true, `rejected: ${hostile}`)
        assertEquals(id, id.toLowerCase())
    }
})

Deno.test('config - a well-formed session id is honoured', async () => {
    configureSession({ driver: 'memory', secret: generateAppKey() })

    const app = new Hono()
    app.use('*', sessionMiddleware({ driver: 'memory' }))
    app.get('/', (c) => c.text(getSession(c).getId()))

    const good = 'a'.repeat(64)
    const res = await app.request('http://localhost/', {
        headers: { cookie: `lockness_session=${good}` },
    })

    assertEquals(await res.text(), good)
})

Deno.test('config - a sealed cookie survives a real HTTP round trip', async () => {
    // The end-to-end gap: everything else asserts against seal/open directly or
    // against one request. This drives two requests through Hono, carrying the
    // Set-Cookie from the first into the second, which is the only shape that
    // proves the middleware, the driver and the wire format agree.
    configureSession({ driver: 'cookie', secret: generateAppKey() })

    const app = new Hono()
    app.use('*', sessionMiddleware())
    app.get('/set', (c) => {
        getSession(c).set('auth_web', 42)
        return c.text('set')
    })
    app.get(
        '/get',
        (c) => c.json({ seen: getSession(c).get('auth_web') ?? null }),
    )

    const first = await app.request('http://localhost/set')
    const cookie = (first.headers.get('set-cookie') ?? '').split(';')[0]

    // New cookies are sealed through @lockness/crypto's Crypt, whose wire marker
    // is `c1.` (#265). The legacy `v1.` format is still read, never written.
    assertEquals(cookie.startsWith('lockness_session=c1.'), true)

    const second = await app.request('http://localhost/get', {
        headers: { cookie },
    })

    assertEquals(await second.json(), { seen: 42 })
})

Deno.test('config - the round-trip cookie does not survive a key change', async () => {
    // The other half: what a rotation actually does to a live session.
    configureSession({ driver: 'cookie', secret: generateAppKey() })
    const app = new Hono()
    app.use('*', sessionMiddleware())
    app.get('/set', (c) => {
        getSession(c).set('auth_web', 42)
        return c.text('set')
    })
    app.get(
        '/get',
        (c) => c.json({ seen: getSession(c).get('auth_web') ?? null }),
    )

    const cookie = ((await app.request('http://localhost/set')).headers.get(
        'set-cookie',
    ) ??
        '').split(';')[0]

    configureSession({ driver: 'cookie', secret: generateAppKey() })
    const after = await app.request('http://localhost/get', {
        headers: { cookie },
    })

    assertEquals(await after.json(), { seen: null })
})
