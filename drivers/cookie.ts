/**
 * @fileoverview Cookie-based session driver.
 *
 * @module @lockness/session/drivers/cookie
 */

// deno-lint-ignore-file require-await

import type { Context } from 'hono'
import { deleteCookie, getCookie, setCookie } from '@lockness/hono'
import type { SessionConfig, SessionData, SessionDriver } from '../types.ts'

/**
 * Cookie-based session driver.
 *
 * Stores session data directly in an encrypted cookie (stateless).
 * Best for small session data sizes (< 4KB after encryption).
 *
 * **Security:** Uses AES-256-GCM encryption when a secret is provided.
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

    constructor(context: Context, config: SessionConfig) {
        this.context = context
        this.config = config
    }

    async read(_sessionId: string): Promise<SessionData | null> {
        const cookieValue = getCookie(this.context, this.config.cookieName)
        if (!cookieValue) return null

        try {
            const decoded = await this.decrypt(cookieValue)
            return JSON.parse(decoded) as SessionData
        } catch {
            return null
        }
    }

    async write(
        _sessionId: string,
        data: SessionData,
        lifetime: number,
    ): Promise<void> {
        const encrypted = await this.encrypt(JSON.stringify(data))
        setCookie(this.context, this.config.cookieName, encrypted, {
            path: this.config.path,
            domain: this.config.domain,
            secure: this.config.secure,
            httpOnly: this.config.httpOnly,
            sameSite: this.config.sameSite,
            maxAge: lifetime,
        })
    }

    async destroy(_sessionId: string): Promise<void> {
        deleteCookie(this.context, this.config.cookieName, {
            path: this.config.path,
            domain: this.config.domain,
        })
    }

    async regenerate(_oldId: string, _newId: string): Promise<void> {
        // For cookie driver, regeneration is handled at session level
        // No action needed here
    }

    // Simple encryption using Web Crypto API
    private async encrypt(data: string): Promise<string> {
        if (!this.config.secret) {
            // No encryption, just base64
            return btoa(encodeURIComponent(data))
        }

        const encoder = new TextEncoder()
        const key = await this.deriveKey(this.config.secret)
        const iv = crypto.getRandomValues(new Uint8Array(12))
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            encoder.encode(data),
        )

        // Combine IV + encrypted data
        const combined = new Uint8Array(iv.length + encrypted.byteLength)
        combined.set(iv)
        combined.set(new Uint8Array(encrypted), iv.length)

        return btoa(String.fromCharCode(...combined))
    }

    private async decrypt(encrypted: string): Promise<string> {
        if (!this.config.secret) {
            // No encryption, just base64
            return decodeURIComponent(atob(encrypted))
        }

        const combined = new Uint8Array(
            atob(encrypted)
                .split('')
                .map((c) => c.charCodeAt(0)),
        )
        const iv = combined.slice(0, 12)
        const data = combined.slice(12)

        const key = await this.deriveKey(this.config.secret)
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            data,
        )

        return new TextDecoder().decode(decrypted)
    }

    private async deriveKey(secret: string): Promise<CryptoKey> {
        const encoder = new TextEncoder()
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(secret),
            { name: 'PBKDF2' },
            false,
            ['deriveKey'],
        )

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode('lockness_session_salt'),
                iterations: 100000,
                hash: 'SHA-256',
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
        )
    }
}
