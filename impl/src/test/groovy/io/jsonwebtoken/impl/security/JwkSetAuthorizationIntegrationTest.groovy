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
import io.jsonwebtoken.Header
import io.jsonwebtoken.Locator
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.JwkSet
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import java.security.Key

import static org.junit.Assert.*

/**
 * End-to-end verification that the {@link io.jsonwebtoken.JwtParser} enforces JWK {@code key_ops} as part of the
 * same authorization transaction for both public JWS and JWE parsing entry points.
 */
class JwkSetAuthorizationIntegrationTest {

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

    // ------------------------------------------------------------------
    // JWS
    // ------------------------------------------------------------------

    @Test
    void testJwsVerifySucceedsWithVerifyAuthorizedKey() {
        def jwk = buildJwk('sig', TestKeys.HS256, [Jwks.OP.SIGN, Jwks.OP.VERIFY])
        def jws = Jwts.builder().subject('joe').header().keyId('sig').and().signWith(TestKeys.HS256).compact()
        def parsed = Jwts.parser().keyLocator(Jwks.setLocator(buildSet(jwk))).build()
                .parseSignedClaims(jws)
        assertEquals 'joe', parsed.getPayload().getSubject()
    }

    @Test
    void testJwsVerifySucceedsWithLegacyKeyWithoutOps() {
        def jwk = buildJwk('legacy', TestKeys.HS256, null)
        def jws = Jwts.builder().subject('joe').header().keyId('legacy').and().signWith(TestKeys.HS256).compact()
        def parsed = Jwts.parser().keyLocator(Jwks.setLocator(buildSet(jwk))).build()
                .parseSignedClaims(jws)
        assertEquals 'joe', parsed.getPayload().getSubject()
    }

    @Test
    void testJwsVerifyRejectsEncryptDecryptKey() {
        // the headline vulnerability: an encrypt/decrypt-only key must never verify a signature
        def jwk = buildJwk('enc-only', TestKeys.HS256, [Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT])
        def jws = Jwts.builder().subject('joe').header().keyId('enc-only').and().signWith(TestKeys.HS256).compact()
        try {
            Jwts.parser().keyLocator(Jwks.setLocator(buildSet(jwk))).build().parseSignedClaims(jws)
            fail()
        } catch (InvalidKeyException expected) {
            String msg = expected.getMessage()
            assertTrue msg, msg.contains('enc-only')
            assertTrue msg, msg.contains('verify')
        }
    }

    @Test
    void testJwsVerifyStillPerformsRealSignatureCheckForAuthorizedKey() {
        def jwk = buildJwk('sig', TestKeys.HS256, [Jwks.OP.SIGN, Jwks.OP.VERIFY])
        def otherKey = Jwts.SIG.HS256.key().build()
        def jws = Jwts.builder().subject('joe').header().keyId('sig').and().signWith(otherKey).compact()
        try {
            Jwts.parser().keyLocator(Jwks.setLocator(buildSet(jwk))).build().parseSignedClaims(jws)
            fail()
        } catch (io.jsonwebtoken.security.SignatureException expected) {
            // authorization passed, but the actual signature verification still runs and correctly fails
            assertNotNull expected.getMessage()
        }
    }

    // ------------------------------------------------------------------
    // JWE
    // ------------------------------------------------------------------

    @Test
    void testJweDirectDecryptSucceedsWithDecryptAuthorizedKey() {
        def jwk = buildJwk('dir-key', TestKeys.A128GCM, [Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT])
        def jwe = Jwts.builder().subject('joe')
                .header().keyId('dir-key').and()
                .encryptWith(TestKeys.A128GCM, Jwts.KEY.DIRECT, Jwts.ENC.A128GCM).compact()
        def parsed = Jwts.parser().keyLocator(Jwks.setLocator(buildSet(jwk))).build()
                .parseEncryptedClaims(jwe)
        assertEquals 'joe', parsed.getPayload().getSubject()
    }

    @Test
    void testJweKeyWrapSucceedsWithUnwrapAuthorizedKey() {
        def jwk = buildJwk('kek', TestKeys.A128KW, [Jwks.OP.WRAP_KEY, Jwks.OP.UNWRAP_KEY])
        def jwe = Jwts.builder().subject('joe')
                .header().keyId('kek').and()
                .encryptWith(TestKeys.A128KW, Jwts.KEY.A128KW, Jwts.ENC.A128GCM).compact()
        def parsed = Jwts.parser().keyLocator(Jwks.setLocator(buildSet(jwk))).build()
                .parseEncryptedClaims(jwe)
        assertEquals 'joe', parsed.getPayload().getSubject()
    }

    @Test
    void testJweDecryptRejectsSignVerifyKey() {
        def jwk = buildJwk('sig-only', TestKeys.A128GCM, [Jwks.OP.SIGN, Jwks.OP.VERIFY])
        def jwe = Jwts.builder().subject('joe')
                .header().keyId('sig-only').and()
                .encryptWith(TestKeys.A128GCM, Jwts.KEY.DIRECT, Jwts.ENC.A128GCM).compact()
        try {
            Jwts.parser().keyLocator(Jwks.setLocator(buildSet(jwk))).build().parseEncryptedClaims(jwe)
            fail()
        } catch (InvalidKeyException expected) {
            String msg = expected.getMessage()
            assertTrue msg, msg.contains('sig-only')
            assertTrue msg, msg.contains('decrypt')
        }
    }

    @Test
    void testJweUnwrapRejectsEncryptDecryptKey() {
        def jwk = buildJwk('enc-only', TestKeys.A128KW, [Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT])
        def jwe = Jwts.builder().subject('joe')
                .header().keyId('enc-only').and()
                .encryptWith(TestKeys.A128KW, Jwts.KEY.A128KW, Jwts.ENC.A128GCM).compact()
        try {
            Jwts.parser().keyLocator(Jwks.setLocator(buildSet(jwk))).build().parseEncryptedClaims(jwe)
            fail()
        } catch (InvalidKeyException expected) {
            String msg = expected.getMessage()
            assertTrue msg, msg.contains('enc-only')
            assertTrue msg, msg.contains('unwrapKey')
        }
    }

    @Test
    void testJweDecryptSucceedsWithLegacyKeyWithoutOps() {
        def jwk = buildJwk('legacy', TestKeys.A128GCM, null)
        def jwe = Jwts.builder().subject('joe')
                .header().keyId('legacy').and()
                .encryptWith(TestKeys.A128GCM, Jwts.KEY.DIRECT, Jwts.ENC.A128GCM).compact()
        def parsed = Jwts.parser().keyLocator(Jwks.setLocator(buildSet(jwk))).build()
                .parseEncryptedClaims(jwe)
        assertEquals 'joe', parsed.getPayload().getSubject()
    }

    @Test
    void testCustomLocatorReturningPlainKeyRetainsLegacyBehavior() {
        // Plain Keys have no JWK metadata, so custom locators returning them keep working unchanged:
        def jws = Jwts.builder().subject('joe').signWith(TestKeys.HS256).compact()
        def customLocator = new Locator<Key>() {
            @Override
            Key locate(Header header) {
                return TestKeys.HS256
            }
        }
        def parsed = Jwts.parser().keyLocator(customLocator).build().parseSignedClaims(jws)
        assertEquals 'joe', parsed.getPayload().getSubject()
    }

    @Test
    void testBuiltInLocatorAndParserEnforceTheSameTransaction() {
        // The locator's rejection and the parser's post-location guard share one authorization rule:
        // an encrypt/decrypt-only JWK can never reach the JWS verification crypto.
        def jwk = buildJwk('enc-only', TestKeys.HS256, [Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT])
        def jws = Jwts.builder().subject('joe').header().keyId('enc-only').and().signWith(TestKeys.HS256).compact()
        try {
            Jwts.parser().keyLocator(Jwks.setLocator(buildSet(jwk))).build().parseSignedClaims(jws)
            fail()
        } catch (InvalidKeyException expected) {
            String msg = expected.getMessage()
            // single, specific authorization error (not a SignatureException or generic JCA failure):
            assertTrue msg, msg.contains('enc-only')
            assertTrue msg, msg.contains('verify')
        }
    }
}
