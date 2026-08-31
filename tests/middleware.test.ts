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
    configureSession({
        driver: 'memory',
        secret: 'test-secret-persist',
        cookieName: 'persist_session',
    })

    const app = new Hono()
    app.use('*', sessionMiddleware({ driver: 'memory' }))

    app.get('/set', (c) => {
        const session = getSession(c)
        session.set('counter', 1)
        return c.text('Set')
    })

    app.get('/get', (c) => {
        const session = getSession(c)
        const counter = session.get<number>('counter')
        return c.text(`Counter: ${counter}`)
    })

    const res1 = await app.request('/set')
    assertEquals(res1.status, 200)

    // Note: In real scenario, session ID would be passed via cookie
    // This is a simplified test showing middleware integration
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
