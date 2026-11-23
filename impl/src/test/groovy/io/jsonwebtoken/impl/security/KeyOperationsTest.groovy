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

import io.jsonwebtoken.JweHeader
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import java.security.Key

import static org.junit.Assert.*

class KeyOperationsTest {

    private static JwsHeader jwsHeader() {
        return Jwts.header().add('alg', Jwts.SIG.HS256.id).build() as JwsHeader
    }

    private static JweHeader jweHeader(String alg) {
        return Jwts.header().add('alg', alg).add('enc', Jwts.ENC.A128GCM.id).build() as JweHeader
    }

    private static Jwk<?> buildJwk(def key, def ops) {
        def b = Jwks.builder().key(key)
        if (ops) {
            b.operations().add(ops as Collection).and()
        }
        return b.build()
    }

    @Test
    void testJwsRequiresVerify() {
        assertSame DefaultKeyOperation.VERIFY, KeyOperations.required(jwsHeader())
    }

    @Test
    void testDirectJweAlgorithmsRequireDecrypt() {
        assertSame DefaultKeyOperation.DECRYPT, KeyOperations.required(jweHeader('dir'))
        assertSame DefaultKeyOperation.DECRYPT, KeyOperations.required(jweHeader('ECDH-ES'))
    }

    @Test
    void testKeyWrappingJweAlgorithmsRequireUnwrap() {
        ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256', 'A128KW', 'A256KW', 'A128GCMKW',
         'PBES2-HS256+A128KW', 'ECDH-ES+A128KW'].each { alg ->
            assertSame DefaultKeyOperation.UNWRAP, KeyOperations.required(jweHeader(alg))
        }
    }

    @Test
    void testLegacyJwkWithoutOperationsIsAlwaysAuthorized() {
        def jwk = buildJwk(TestKeys.HS256, null)
        assertTrue KeyOperations.isAuthorized(jwk, DefaultKeyOperation.VERIFY)
        assertTrue KeyOperations.isAuthorized(jwk, DefaultKeyOperation.DECRYPT)
        assertTrue KeyOperations.isAuthorized(jwk, DefaultKeyOperation.UNWRAP)
        // and it must not throw:
        KeyOperations.assertAuthorized(jwk, DefaultKeyOperation.VERIFY)
    }

    @Test
    void testAssertAuthorizedNamesKeyAndOperation() {
        def jwk = Jwks.builder().key(TestKeys.HS256).id('kid-xyz')
                .operations().add([Jwks.OP.ENCRYPT, Jwks.OP.DECRYPT] as Collection).and().build()
        try {
            KeyOperations.assertAuthorized(jwk, DefaultKeyOperation.VERIFY)
            fail()
        } catch (InvalidKeyException expected) {
            String msg = expected.getMessage()
            assertTrue msg, msg.contains('kid-xyz')
            assertTrue msg, msg.contains('verify')
            assertTrue msg, msg.contains('encrypt')
        }
    }

    @Test
    void testPlainKeyIsPassedThrough() {
        // a plain java.security.Key has no JWK metadata, so it must not be rejected:
        KeyOperations.assertKeyAuthorized(TestKeys.HS256, DefaultKeyOperation.VERIFY)
    }
}
