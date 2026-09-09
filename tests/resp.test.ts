/**
 * @fileoverview The RESP codec stays off `@lockness/session`'s public surface.
 *
 * The wire codec (`encodeCommand`/`writeFrame`/`readReply`) moved to
 * `@lockness/redis`, where its behaviour is tested. What session still owns is
 * the invariant that none of it leaks onto the session package surface — the
 * driver consumes the client internally and re-exports nothing of the wire. SC-005
 * pins this at build time via `agents:brief`; this pins it at test time.
 *
 * @module @lockness/session/tests/resp
 */

import { assertEquals } from '@std/assert'
import * as sessionPublic from '../mod.ts'

Deno.test('resp - the wire codec stays internal, off the package surface (FR-006)', () => {
    const surface = sessionPublic as Record<string, unknown>
    assertEquals(
        surface.encodeCommand,
        undefined,
        'encodeCommand is not exported',
    )
    assertEquals(surface.writeFrame, undefined, 'writeFrame is not exported')
    assertEquals(surface.readReply, undefined, 'readReply is not exported')
})
