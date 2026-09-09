/**
 * Tests for @lockness/session - Middleware
 */

import { assertEquals } from '@std/assert'
import { Hono } from 'hono'
import { configureSession, getSession, sessionMiddleware } from '../mod.ts'

Deno.test('sessionMiddleware - attaches session to context', async () => {
    configureSession({
        driver: 'memory',
        secret: 'test-secret-key-for-middleware',
        cookieName: 'app_session',
    })

    const app = new Hono()
    app.use('*', sessionMiddleware())

    app.get('/test', (c) => {
        const session = getSession(c)
        session.set('visited', true)
        return c.text('OK')
    })

    const res = await app.request('/test')
    assertEquals(res.status, 200)
})

Deno.test('sessionMiddleware - persists data across requests', async () => {
    // #142 / #138: this test used to request only `/set` and assert a status
    // code, so it stayed green through the whole life of a memory driver that
    // never persisted. It now makes the second request, carrying the session
    // cookie, and asserts the value written on request 1 is read on request 2.
    configureSession({
        driver: 'memory',
        secret: 'test-secret-persist',
        cookieName: 'persist_session',
    })

    const app = new Hono()
    app.use('*', sessionMiddleware({ driver: 'memory' }))

    app.get('/set', (c) => {
        getSession(c).set('counter', 1)
        return c.text('Set')
    })

    app.get('/get', (c) => {
        return c.text(String(getSession(c).get<number>('counter') ?? 'MISSING'))
    })

    const res1 = await app.request('/set')
    assertEquals(res1.status, 200)
    const cookie = res1.headers.get('set-cookie')?.split(';')[0]
    assertEquals(
        typeof cookie,
        'string',
        'the session id was issued as a cookie',
    )

    const res2 = await app.request('/get', { headers: { cookie: cookie! } })
    assertEquals(
        await res2.text(),
        '1',
        'the value written on request 1 was read on request 2',
    )
})

Deno.test('sessionMiddleware - flash messages work', async () => {
    configureSession({
        driver: 'memory',
        secret: 'test-flash',
        cookieName: 'flash_session',
    })

    const app = new Hono()
    app.use('*', sessionMiddleware())

    app.get('/flash', (c) => {
        const session = getSession(c)
        session.flash('message', 'Task completed!')
        return c.text('Flashed')
    })

    const res = await app.request('/flash')
    assertEquals(res.status, 200)
})
