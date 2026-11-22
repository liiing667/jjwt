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
package io.jsonwebtoken.impl

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.AbstractSerializer
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.security.KeyPairBuilderSupplier
import io.jsonwebtoken.security.MacAlgorithm
import org.junit.Test

import java.util.concurrent.atomic.AtomicBoolean

import static org.junit.Assert.*

class DefaultJwtBuilderReuseTest {

    @Test
    void testAdjacentTenantIssuanceIsFrozenAtCompactStart() {

        def aead = Jwts.SIG.HS256
        def keyA = aead.key().build()
        def keyB = Jwts.SIG.HS512.key().build()

        def builder = new DefaultJwtBuilder()
        def delegate = Services.get(Serializer)
        def mutated = new AtomicBoolean(false)

        // Simulate another tenant configuring the shared builder while the first issuance is between its snapshot
        // and its cryptographic operation.  The first token must retain tenant A, kid A, HS256 and key A.
        def serializer = new AbstractSerializer() {
            @Override
            protected void doSerialize(Object value, OutputStream out) throws Exception {
                def map = value as Map<String, ?>
                if (map.containsKey('alg') && mutated.compareAndSet(false, true)) {
                    builder.header().keyId('tenant-b').and()
                            .claim('tenant', 'tenant-b')
                            .signWith(keyB, Jwts.SIG.HS512)
                }
                delegate.serialize(map, out)
            }
        }

        builder.serializeToJsonWith(serializer)
                .header().keyId('tenant-a').and()
                .claim('tenant', 'tenant-a')
                .signWith(keyA, aead)

        String first = builder.compact()
        String second = builder.compact()

        // Parse after the second issuance to ensure the first consumer view is not affected by the builder's current
        // tenant, kid or key generation.
        def firstJws = Jwts.parser().verifyWith(keyA).build().parseSignedClaims(first)
        assertEquals('tenant-a', firstJws.getPayload().get('tenant'))
        assertEquals('tenant-a', firstJws.getHeader().getKeyId())
        assertEquals('HS256', firstJws.getHeader().getAlgorithm())
        assertFalse(builder.header().containsKey('alg')) // generation-specific alg must not leak into the template

        def secondJws = Jwts.parser().verifyWith(keyB).build().parseSignedClaims(second)

        assertEquals('tenant-b', secondJws.getPayload().get('tenant'))
        assertEquals('tenant-b', secondJws.getHeader().getKeyId())
        assertEquals('HS512', secondJws.getHeader().getAlgorithm())
    }

    @Test
    void testFailedRetryDoesNotPolluteNextIssuance() {

        def keyA = Jwts.SIG.HS256.key().build()
        def keyB = Jwts.SIG.HS512.key().build()
        def builder = new DefaultJwtBuilder()

        builder.header().keyId('tenant-a').and()
                .claim('tenant', 'tenant-a')
                .signWith(keyA, Jwts.SIG.HS256)
        String first = builder.compact()

        // Force a failure while the second issuance is being serialized.
        def failing = new AbstractSerializer() {
            @Override
            protected void doSerialize(Object value, OutputStream out) throws Exception {
                throw new IOException('expected serialization failure')
            }
        }
        builder.serializeToJsonWith(failing)
                .header().keyId('tenant-b').and()
                .claim('tenant', 'tenant-b')
                .signWith(keyB, Jwts.SIG.HS512)

        try {
            builder.compact()
            fail('the second issuance should have failed')
        } catch (Exception expected) {
            // expected
        }
        assertFalse(builder.header().containsKey('alg')) // a failed issuance must not leave generated header state

        // A retry with a working serializer must produce only tenant B state.
        builder.serializeToJsonWith(Services.get(Serializer))
        String second = builder.compact()

        def firstJws = Jwts.parser().verifyWith(keyA).build().parseSignedClaims(first)
        assertEquals('tenant-a', firstJws.getPayload().get('tenant'))
        assertEquals('tenant-a', firstJws.getHeader().getKeyId())

        def secondJws = Jwts.parser().verifyWith(keyB).build().parseSignedClaims(second)
        assertEquals('tenant-b', secondJws.getPayload().get('tenant'))
        assertEquals('tenant-b', secondJws.getHeader().getKeyId())
        assertEquals('HS512', secondJws.getHeader().getAlgorithm())
    }

    @Test
    void testParserReadBackForHmacRsaEcEdDsaAndEmptyClaims() {

        [Jwts.SIG.HS256, Jwts.SIG.RS256, Jwts.SIG.ES256, Jwts.SIG.EdDSA].each { alg ->

            def signingKey
            def verificationKey
            if (alg instanceof MacAlgorithm) {
                signingKey = alg.key().build()
                verificationKey = signingKey
            } else if (alg instanceof KeyPairBuilderSupplier) {
                def pair = alg.keyPair().build()
                signingKey = pair.private
                verificationKey = pair.public
            } else {
                fail("Unhandled algorithm: ${alg.id}")
            }

            def parser = Jwts.parser().verifyWith(verificationKey).build()
            String token = Jwts.builder()
                    .header().keyId("kid-${alg.id}").and()
                    .claim('tenant', "tenant-${alg.id}")
                    .signWith(signingKey, alg)
                    .compact()

            def jws = parser.parseSignedClaims(token)
            assertEquals("tenant-${alg.id}", jws.getPayload().get('tenant'))
            assertEquals("kid-${alg.id}", jws.getHeader().getKeyId())
            assertEquals(alg.id, jws.getHeader().getAlgorithm())

            String emptyClaims = Jwts.builder().signWith(signingKey, alg).compact()
            def empty = parser.parseSignedContent(emptyClaims)
            assertEquals(0, empty.getPayload().length)
            assertNull(empty.getHeader().getKeyId())
        }
    }
}
