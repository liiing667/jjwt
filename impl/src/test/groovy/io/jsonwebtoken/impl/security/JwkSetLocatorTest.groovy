/*
 * Copyright © 2026 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.JweHeader
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.JwkSet
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import static org.junit.Assert.*

/**
 * Asserts that key selection from a JWK Set is an operation-aware authorization transaction: a JWK's declared
 * {@code key_ops} must permit the actual JWS/JWE cryptographic use, and failures identify the real key and
 * operation instead of producing generic cryptographic errors.
 */
class JwkSetLocatorTest {

    private static Jwk<?> buildJwk(String kid, def key, def ops) {
        def b = Jwks.builder().key(key).id(kid)
        if (ops) {
            b.operations().add(ops as Collection).and()
        }
        return b.build()
    }

    private static JwkSet buildSet(Jwk<?>... jwks) {
        def b = Jwks.set()
        jwks.each { b.add(it) }
        return b.build()
    }

    private static JwsHeader jwsHeader(String kid = null) {
        def b = Jwts.header().add('alg', Jwts.SIG.HS256.id)
        if (kid) b.keyId(kid)
        return b.build() as JwsHeader
    }

    private static JweHeader jweHeader(String alg, String kid = null) {
        def b = Jwts.header().add('alg', alg).add('enc', Jwts.ENC.A128GCM.id)
        if (kid) b.keyId(kid)
        return b.build() as JweHeader
    }

    // ---------------------------------------------------------------------
    // Backwards compatibility: JWKs without key_ops are unrestricted
    // ---------------------------------------------------------------------

    @Test
    void testNoKeyOpsJwkIsAuthorizedForVerify() {
        def jwk = buildJwk('a', TestKeys.HS256, null)
        def locator = Jwks.setLocator(buildSet(jwk))
        assertSame TestKeys.HS256, locator.locate(jwsHeader('a'))
    }

    @Test
    void testNoKeyOpsJwkIsAuthorizedForDecrypt() {
        def jwk = buildJwk('a', TestKeys.A128GCM, null)
        def locator = Jwks.setLocator(buildSet(jwk))
        assertSame TestKeys.A128GCM, locator.locate(jweHeader('dir', 'a'))
    }

    // ---------------------------------------------------------------------
    // Legal sign/verify and encrypt/decrypt combinations still work
    // ---------------------------------------------------------------------

    @Test
    void testSignVerifyKeyUsedForVerify() {
        def jwk = buildJwk('sig', TestKeys.HS256, [Jwks.OP.SIGN, Jwks.OP.VERIFY])
        def locator = Jwks.setLocator(buildSet(jwk))
        assertSame TestKeys.HS256, locator.locate(jwsHeader('sig'))
    }

    @Test
    void testEncryptDecryptKeyUsedForDirectDecrypt() {
        def jwk = buildJwk('enc', TestKeys.A128GCM, [Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT])
        def locator = Jwks.setLocator(buildSet(jwk))
        // 'dir' is a direct key-management algorithm -> requires 'decrypt'
        assertSame TestKeys.A128GCM, locator.locate(jweHeader('dir', 'enc'))
    }

    @Test
    void testWrapUnwrapKeyUsedForKeyUnwrap() {
        def jwk = buildJwk('kek', TestKeys.A128KW, [Jwks.OP.WRAP_KEY, Jwks.OP.UNWRAP_KEY])
        def locator = Jwks.setLocator(buildSet(jwk))
        // 'A128KW' wraps the CEK -> requires 'unwrapKey'
        assertSame TestKeys.A128KW, locator.locate(jweHeader('A128KW', 'kek'))
    }

    // ---------------------------------------------------------------------
    // The headline vulnerability: encrypt/decrypt key must not verify
    // ---------------------------------------------------------------------

    @Test
    void testEncryptDecryptKeyRejectedForVerify() {
        def jwk = buildJwk('enc-only', TestKeys.HS256, [Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT])
        def locator = Jwks.setLocator(buildSet(jwk))
        try {
            locator.locate(jwsHeader('enc-only'))
            fail()
        } catch (InvalidKeyException expected) {
            // error must name the real key and the rejected operation, not a generic failure:
            String msg = expected.getMessage()
            assertTrue msg, msg.contains('enc-only')
            assertTrue msg, msg.contains('verify')
        }
    }

    @Test
    void testSignVerifyKeyRejectedForDecrypt() {
        def jwk = buildJwk('sig-only', TestKeys.A128GCM, [Jwks.OP.SIGN, Jwks.OP.VERIFY])
        def locator = Jwks.setLocator(buildSet(jwk))
        try {
            locator.locate(jweHeader('dir', 'sig-only'))
            fail()
        } catch (InvalidKeyException expected) {
            String msg = expected.getMessage()
            assertTrue msg, msg.contains('sig-only')
            assertTrue msg, msg.contains('decrypt')
        }
    }

    @Test
    void testEncryptDecryptKeyRejectedForUnwrap() {
        def jwk = buildJwk('enc-only', TestKeys.A128KW, [Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT])
        def locator = Jwks.setLocator(buildSet(jwk))
        try {
            locator.locate(jweHeader('A128KW', 'enc-only'))
            fail()
        } catch (InvalidKeyException expected) {
            String msg = expected.getMessage()
            assertTrue msg, msg.contains('enc-only')
            assertTrue msg, msg.contains('unwrapKey')
        }
    }

    // ---------------------------------------------------------------------
    // Set ordering / no-kid selection
    // ---------------------------------------------------------------------

    @Test
    void testNoKidSelectsFirstAuthorizedInOrder() {
        def unauthorized = buildJwk('a', TestKeys.HS256, [Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT])
        def firstGood = Jwts.SIG.HS384.key().build()
        def secondGood = Jwts.SIG.HS512.key().build()
        def first = buildJwk('b', firstGood, [Jwks.OP.SIGN, Jwks.OP.VERIFY])
        def second = buildJwk('c', secondGood, [Jwks.OP.SIGN, Jwks.OP.VERIFY])

        // when every candidate is authorized, set order is honored:
        def locator = Jwks.setLocator(buildSet(first, second))
        assertSame firstGood, locator.locate(jwsHeader(null))

        // an unauthorized leading key is skipped and the first authorized key is returned:
        locator = Jwks.setLocator(buildSet(unauthorized, first, second))
        assertSame firstGood, locator.locate(jwsHeader(null))

        // only an unauthorized key present -> operation-specific rejection, not a generic crypto failure:
        def onlyUnauthorized = Jwks.setLocator(buildSet(unauthorized))
        try {
            onlyUnauthorized.locate(jwsHeader(null))
            fail()
        } catch (InvalidKeyException expected) {
            assertTrue expected.getMessage().contains('verify')
        }
    }

    @Test
    void testNoKidSkipsUnauthorizedAndReturnsAuthorizedKey() {
        def goodKey = Jwts.SIG.HS384.key().build()
        def bad = buildJwk('a', TestKeys.HS256, [Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT])
        def good = buildJwk('b', goodKey, [Jwks.OP.SIGN, Jwks.OP.VERIFY])
        def locator = Jwks.setLocator(buildSet(bad, good))
        assertSame goodKey, locator.locate(jwsHeader(null))
    }

    @Test
    void testNoAuthorizedKeyWithoutKidNamesOperation() {
        def jwk = buildJwk('enc-only', TestKeys.HS256, [Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT])
        def locator = Jwks.setLocator(buildSet(jwk))
        try {
            locator.locate(jwsHeader(null))
            fail()
        } catch (InvalidKeyException expected) {
            String msg = expected.getMessage()
            assertTrue msg, msg.contains('verify')
            assertTrue msg, msg.contains('JWK Set')
        }
    }

    @Test
    void testUnknownKidReportsKidAndOperation() {
        def jwk = buildJwk('a', TestKeys.HS256, [Jwks.OP.SIGN, Jwks.OP.VERIFY])
        def locator = Jwks.setLocator(buildSet(jwk))
        try {
            locator.locate(jwsHeader('does-not-exist'))
            fail()
        } catch (InvalidKeyException expected) {
            String msg = expected.getMessage()
            assertTrue msg, msg.contains('does-not-exist')
            assertTrue msg, msg.contains('verify')
        }
    }

    // ---------------------------------------------------------------------
    // Rotating sets: a supplier is consulted per lookup and no operation is
    // cached across sets
    // ---------------------------------------------------------------------

    @Test
    void testSupplierIsConsultedOnEveryLookup() {
        int invocations = 0
        def locator = Jwks.setLocator(new java.util.function.Supplier<JwkSet>() {
            @Override
            JwkSet get() {
                invocations++
                return buildSet(buildJwk('a', TestKeys.HS256, [Jwks.OP.SIGN, Jwks.OP.VERIFY]))
            }
        })
        locator.locate(jwsHeader('a'))
        locator.locate(jwsHeader('a'))
        assertEquals 2, invocations
    }

    @Test
    void testRotatedSetDoesNotCarryOperationToNewKey() {
        // First set: an encrypt/decrypt key under kid 'shared'.
        def oldSet = buildSet(buildJwk('shared', TestKeys.HS256, [Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT]))
        // Rotated set: same kid, now a sign/verify key with different material.
        def newKey = Jwts.SIG.HS384.key().build()
        def newSet = buildSet(buildJwk('shared', newKey, [Jwks.OP.SIGN, Jwks.OP.VERIFY]))

        def current = oldSet
        def locator = Jwks.setLocator(new java.util.function.Supplier<JwkSet>() {
            @Override
            JwkSet get() {
                return current
            }
        })

        // verify against the old (encrypt-only) set must be rejected:
        try {
            locator.locate(jwsHeader('shared'))
            fail()
        } catch (InvalidKeyException expected) {
            assertTrue expected.getMessage().contains('verify')
        }

        // rotate the set; the new key is authorized for verify and must be returned
        current = newSet
        assertSame newKey, locator.locate(jwsHeader('shared'))
    }

    @Test
    void testNullSetRejected() {
        try {
            Jwks.setLocator((JwkSet) null)
            fail()
        } catch (IllegalArgumentException expected) {
            // io.jsonwebtoken.lang.Assert rejects null arguments
            assertTrue expected.getMessage().contains('JwkSet')
        }
    }
}
