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

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SigningKeyResolverAdapter
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.DefaultJwsHeader
import io.jsonwebtoken.security.JwkSet
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.KeySelection
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import java.security.Key

import static org.junit.Assert.*

@SuppressWarnings('GrDeprecatedAPIUsage')
class JwkSetLocatorTest {

    private static JwkSet jwkSet(TestKeys.Bundle bundle, String kid) {
        def jwk = Jwks.builder().key(bundle.pair.public).id(kid).build()
        return Jwks.set().add(jwk).build()
    }

    private static JwkSet jwkSet(TestKeys.Bundle bundle) {
        def jwk = Jwks.builder().key(bundle.pair.public).build()
        return Jwks.set().add(jwk).build()
    }

    private static String token(TestKeys.Bundle bundle, String kid, String subject) {
        def builder = Jwts.builder()
        if (kid != null) {
            builder.header().keyId(kid).and()
        }
        return builder.subject(subject).signWith(bundle.pair.private).compact()
    }

    @Test
    void testRefreshKeepsExistingSelectionOnItsGeneration() {
        def firstSet = jwkSet(TestKeys.RS256, 'shared')
        def locator = Jwks.locator(firstSet)
        def header = new DefaultJwsHeader([alg: 'RS256', kid: 'shared'])

        KeySelection first = locator.select(header)
        assertEquals 1L, first.generation
        assertEquals 'shared', first.keyId
        assertEquals first.jwk.thumbprint().toString(), first.fingerprint
        def firstJwk = first.jwk

        try {
            locator.refresh(null)
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals 1L, locator.generation
        }

        try {
            locator.refresh(new DefaultJwkSet(DefaultJwkSet.KEYS, [keys: []]))
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals 1L, locator.generation
        }

        def secondSet = jwkSet(TestKeys.RS384, 'shared')
        locator.refresh(secondSet)
        assertEquals 2L, locator.generation
        assertEquals 1L, first.generation
        assertSame firstJwk, first.jwk

        KeySelection second = locator.select(header)
        assertEquals 2L, second.generation
        assertEquals 'shared', second.keyId
        assertNotEquals first.fingerprint, second.fingerprint
    }

    @Test
    void testJwsEvidenceUsesTheKeyThatVerifiedTheToken() {
        def locator = Jwks.locator(jwkSet(TestKeys.RS256, 'shared'))
        def parser = Jwts.parser().keyLocator(locator).build()

        String firstToken = token(TestKeys.RS256, 'shared', 'first')
        Jws<Claims> first = parser.parseSignedClaims(firstToken)
        assertEquals 'first', first.payload.subject
        assertEquals 'RS256', first.keySelection.algorithm
        assertEquals first.jwk.thumbprint().toString(), first.keyFingerprint
        assertEquals 1L, first.keyGeneration

        locator.refresh(jwkSet(TestKeys.RS384, 'shared'))
        String secondToken = token(TestKeys.RS384, 'shared', 'second')
        Jws<Claims> second = parser.parseSignedClaims(secondToken)
        assertEquals 'second', second.payload.subject
        assertEquals 'RS384', second.keySelection.algorithm
        assertEquals second.jwk.thumbprint().toString(), second.keyFingerprint
        assertEquals 2L, second.keyGeneration
        assertEquals 1L, first.keyGeneration
        assertNotEquals first.keyFingerprint, second.keyFingerprint

        try {
            parser.parseSignedClaims(firstToken)
            fail()
        } catch (SignatureException expected) {
            assertNotNull expected.message
        }
    }

    @Test
    void testAnotherKidCannotSupplyTheVerificationKey() {
        def firstJwk = Jwks.builder().key(TestKeys.RS256.pair.public).id('k1').build()
        def secondJwk = Jwks.builder().key(TestKeys.RS384.pair.public).id('k2').build()
        def locator = Jwks.locator(Jwks.set().add(firstJwk).add(secondJwk).build())
        def parser = Jwts.parser().keyLocator(locator).build()

        String tokenIdOneSignedByIdTwo = token(TestKeys.RS384, 'k1', 'wrong-key')
        try {
            parser.parseSignedClaims(tokenIdOneSignedByIdTwo)
            fail()
        } catch (SignatureException expected) {
            assertNotNull expected.message
        }

        String tokenIdOneSignedByIdOne = token(TestKeys.RS256, 'k1', 'right-key')
        Jws<Claims> jws = parser.parseSignedClaims(tokenIdOneSignedByIdOne)
        assertEquals 'right-key', jws.payload.subject
        assertEquals 'k1', jws.keySelection.keyId
        assertEquals firstJwk.thumbprint().toString(), jws.keyFingerprint
    }

    @Test
    void testUniqueKeyWithoutKidStillWorks() {
        def locator = Jwks.locator(jwkSet(TestKeys.RS256))
        def parser = Jwts.parser().keyLocator(locator).build()
        Jws<Claims> jws = parser.parseSignedClaims(token(TestKeys.RS256, null, 'no-kid'))
        assertEquals 'no-kid', jws.payload.subject
        assertNull jws.header.keyId
        assertNull jws.keySelection.keyId

        def ambiguous = Jwks.set()
                .add(Jwks.builder().key(TestKeys.RS256.pair.public).id('one').build())
                .add(Jwks.builder().key(TestKeys.RS384.pair.public).id('two').build())
                .build()
        def ambiguousParser = Jwts.parser().keyLocator(Jwks.locator(ambiguous)).build()
        try {
            ambiguousParser.parseSignedClaims(token(TestKeys.RS256, null, 'ambiguous'))
            fail()
        } catch (UnsupportedJwtException expected) {
            assertNotNull expected.message
        }
    }

    @Test
    void testUniqueKeyWithoutKidSupportsRsEsAndEdDsa() {
        [TestKeys.RS256, TestKeys.PS256, TestKeys.ES256, TestKeys.Ed25519].each { bundle ->
            def parser = Jwts.parser().keyLocator(Jwks.locator(jwkSet(bundle))).build()
            Jws<Claims> jws = parser.parseSignedClaims(token(bundle, null, bundle.alg.id))
            assertEquals bundle.alg.id, jws.payload.subject
            assertEquals bundle.alg.id, jws.keySelection.algorithm
            assertNull jws.header.keyId
            assertEquals 1L, jws.keyGeneration
        }
    }

    @Test
    void testUniqueKeyWithoutKidSupportsSignedContent() {
        def parser = Jwts.parser().keyLocator(Jwks.locator(jwkSet(TestKeys.RS256))).build()
        String compact = Jwts.builder().content('plain content'.bytes).signWith(TestKeys.RS256.pair.private).compact()

        Jws<byte[]> jws = parser.parseSignedContent(compact)
        assertArrayEquals 'plain content'.bytes, jws.payload
        assertNull jws.header.keyId
        assertEquals 1L, jws.keyGeneration
    }

    @Test
    void testDuplicateKidWithDistinctKeysIsAmbiguous() {
        def jwkSet = Jwks.set()
                .add(Jwks.builder().key(TestKeys.RS256.pair.public).id('shared').build())
                .add(Jwks.builder().key(TestKeys.RS384.pair.public).id('shared').build())
                .build()
        def locator = Jwks.locator(jwkSet)
        def parser = Jwts.parser().keyLocator(locator).build()

        try {
            parser.parseSignedClaims(token(TestKeys.RS256, 'shared', 'ambiguous'))
            fail()
        } catch (UnsupportedJwtException expected) {
            assertTrue expected.message.contains('multiple distinct keys')
        }
    }

    @Test
    void testKidCaseDoesNotChangeSelectedKeyIdentity() {
        def jwk = Jwks.builder().key(TestKeys.RS256.pair.public).id('CaseSensitiveKid').build()
        def parser = Jwts.parser().keyLocator(Jwks.locator(Jwks.set().add(jwk).build())).build()
        Jws<Claims> jws = parser.parseSignedClaims(token(TestKeys.RS256, 'casesensitivekid', 'case'))
        assertEquals 'case', jws.payload.subject
        assertEquals jwk.thumbprint().toString(), jws.keyFingerprint
    }

    @Test
    void testRsEsEdDsaAndExplicitResolverRemainSupported() {
        [TestKeys.RS256, TestKeys.PS256, TestKeys.ES256, TestKeys.Ed25519].each { bundle ->
            def jwk = Jwks.builder().key(bundle.pair.public).id('only').build()
            def parser = Jwts.parser().keyLocator(Jwks.locator(Jwks.set().add(jwk).build())).build()
            Jws<Claims> jws = parser.parseSignedClaims(token(bundle, 'only', 'algorithm'))
            assertEquals 'algorithm', jws.payload.subject
            assertEquals jwk.thumbprint().toString(), jws.keyFingerprint
            assertEquals 1L, jws.keyGeneration
        }

        Key key = TestKeys.HS256
        def parser = Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
            @Override
            Key resolveSigningKey(JwsHeader header, Claims claims) {
                return key
            }
        }).build()
        String token = Jwts.builder().subject('resolver').signWith(key).compact()
        Jws<Claims> jws = parser.parseSignedClaims(token)
        assertEquals 'resolver', jws.payload.subject
        assertNull jws.jwk
        assertNotNull jws.keyFingerprint
        assertEquals 0L, jws.keyGeneration
    }

    @Test
    void testExplicitResolverTakesPrecedenceOverJwkSetLocator() {
        Key key = TestKeys.HS256
        def unusedJwkSet = jwkSet(TestKeys.RS256, 'rs')
        def parser = Jwts.parser()
                .keyLocator(Jwks.locator(unusedJwkSet))
                .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                    @Override
                    Key resolveSigningKey(JwsHeader header, Claims claims) {
                        return key
                    }
                }).build()
        String token = Jwts.builder().subject('explicit-resolver').signWith(key).compact()

        Jws<Claims> jws = parser.parseSignedClaims(token)
        assertEquals 'explicit-resolver', jws.payload.subject
        assertNull jws.jwk
        assertEquals 0L, jws.keyGeneration
    }
}
