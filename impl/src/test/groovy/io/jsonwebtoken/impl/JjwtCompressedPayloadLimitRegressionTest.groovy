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

import io.jsonwebtoken.CompressionCodec
import io.jsonwebtoken.CompressionException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.compression.GzipCompressionAlgorithm
import io.jsonwebtoken.impl.io.Streams
import org.junit.Test

import javax.crypto.SecretKey
import java.nio.charset.StandardCharsets

import static org.junit.Assert.assertArrayEquals
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotNull
import static org.junit.Assert.assertSame
import static org.junit.Assert.assertTrue
import static org.junit.Assert.fail

class JjwtCompressedPayloadLimitRegressionTest {

    private static byte[] oversizedPayload() {
        return new byte[((int) Streams.MAX_DECOMPRESSED_PAYLOAD_SIZE) + 1]
    }

    private static void assertRejectedTwice(String algorithmId, Closure parse) {
        String first = null
        for (int i = 0; i < 2; i++) {
            try {
                parse()
                fail()
            } catch (CompressionException e) {
                assertTrue(e.message.contains("algorithm '" + algorithmId + "'"))
                assertTrue(e.message.contains(Streams.MAX_DECOMPRESSED_PAYLOAD_SIZE.toString()))
                String failure = e.class.name + ':' + e.message
                if (first == null) {
                    first = failure
                } else {
                    assertEquals(first, failure)
                }
            }
        }
        assertNotNull(first)
    }

    @Test
    void testJwsEntriesRejectOversizedDecompressionConsistently() {
        SecretKey key = Jwts.SIG.HS256.key().build()
        def parser = Jwts.parser().verifyWith(key).build()

        for (def zip : [Jwts.ZIP.DEF, Jwts.ZIP.GZIP]) {
            String jws = Jwts.builder()
                    .content(oversizedPayload())
                    .compressWith(zip)
                    .signWith(key, Jwts.SIG.HS256)
                    .compact()
            assertRejectedTwice(zip.id) { parser.parseSignedClaims(jws) }
            assertRejectedTwice(zip.id) { parser.parseSignedContent(jws) }
        }
    }

    @Test
    void testJweEntriesRejectOversizedDecompressionConsistently() {
        SecretKey key = Jwts.ENC.A256GCM.key().build()
        def parser = Jwts.parser().decryptWith(key).build()

        for (def zip : [Jwts.ZIP.DEF, Jwts.ZIP.GZIP]) {
            String jwe = Jwts.builder()
                    .content(oversizedPayload())
                    .compressWith(zip)
                    .encryptWith(key, Jwts.ENC.A256GCM)
                    .compact()
            assertRejectedTwice(zip.id) { parser.parseEncryptedClaims(jwe) }
            assertRejectedTwice(zip.id) { parser.parseEncryptedContent(jwe) }
        }
    }

    @Test
    void testSmallCompressedJwsAndJwePayloadsStillWork() {
        byte[] content = 'small compressed payload'.getBytes(StandardCharsets.UTF_8)
        SecretKey sigKey = Jwts.SIG.HS256.key().build()
        SecretKey encKey = Jwts.ENC.A256GCM.key().build()

        for (def zip : [Jwts.ZIP.DEF, Jwts.ZIP.GZIP]) {
            String jws = Jwts.builder()
                    .content(content)
                    .compressWith(zip)
                    .signWith(sigKey, Jwts.SIG.HS256)
                    .compact()
            def parsedJws = Jwts.parser().verifyWith(sigKey).build().parseSignedContent(jws)
            assertArrayEquals(content, parsedJws.getPayload())
            assertSame(parsedJws.getPayload(), parsedJws.getPayload())

            String jwsClaims = Jwts.builder()
                    .claim('foo', 'bar')
                    .compressWith(zip)
                    .signWith(sigKey, Jwts.SIG.HS256)
                    .compact()
            assertEquals('bar', Jwts.parser().verifyWith(sigKey).build()
                    .parseSignedClaims(jwsClaims).getPayload().get('foo'))

            String jwe = Jwts.builder()
                    .content(content)
                    .compressWith(zip)
                    .encryptWith(encKey, Jwts.ENC.A256GCM)
                    .compact()
            def parsedJwe = Jwts.parser().decryptWith(encKey).build().parseEncryptedContent(jwe)
            assertArrayEquals(content, parsedJwe.getPayload())
            assertSame(parsedJwe.getPayload(), parsedJwe.getPayload())

            String jweClaims = Jwts.builder()
                    .claim('foo', 'bar')
                    .compressWith(zip)
                    .encryptWith(encKey, Jwts.ENC.A256GCM)
                    .compact()
            assertEquals('bar', Jwts.parser().decryptWith(encKey).build()
                    .parseEncryptedClaims(jweClaims).getPayload().get('foo'))
        }
    }

    @Test
    void testCustomCompressionAlgorithmStillWorks() {
        def codec = new GzipCompressionAlgorithm() {
            @Override
            String getId() {
                return 'CUSTOM'
            }
        }
        byte[] content = 'custom codec payload'.getBytes(StandardCharsets.UTF_8)
        SecretKey key = Jwts.SIG.HS256.key().build()
        String jws = Jwts.builder()
                .content(content)
                .compressWith(codec)
                .signWith(key, Jwts.SIG.HS256)
                .compact()

        def parsed = Jwts.parser()
                .zip().add(codec).and()
                .verifyWith(key)
                .build()
                .parseSignedContent(jws)
        assertArrayEquals(content, parsed.getPayload())
    }

    @Test
    void testEmptyAndUncompressedPayloadsStillWork() {
        SecretKey key = Jwts.SIG.HS256.key().build()
        def parser = Jwts.parser().verifyWith(key).build()

        String empty = Jwts.builder().signWith(key, Jwts.SIG.HS256).compact()
        assertArrayEquals(new byte[0], parser.parseSignedContent(empty).getPayload())

        String claims = Jwts.builder().claim('foo', 'bar').signWith(key, Jwts.SIG.HS256).compact()
        assertEquals('bar', parser.parseSignedClaims(claims).getPayload().get('foo'))
    }

    @Test
    void testPayloadFailureIsStickyOnTheSamePayloadIdentity() {
        def codec = (CompressionCodec) Jwts.ZIP.GZIP
        Payload payload = new Payload(codec.compress(oversizedPayload()), null)

        CompressionException first = null
        try {
            payload.decompress(Jwts.ZIP.GZIP)
            fail()
        } catch (CompressionException e) {
            first = e
        }
        assertNotNull(first)

        try {
            payload.getBytes()
            fail()
        } catch (CompressionException e) {
            assertSame(first, e)
        }
        try {
            payload.decompress(Jwts.ZIP.GZIP)
            fail()
        } catch (CompressionException e) {
            assertSame(first, e)
        }
    }

    @Test
    void testSuccessfulDecompressionRetainsPayloadIdentity() {
        byte[] content = 'identity-preserving payload'.getBytes(StandardCharsets.UTF_8)
        def codec = (CompressionCodec) Jwts.ZIP.GZIP
        Payload payload = new Payload(codec.compress(content), null)

        assertSame(payload, payload.decompress(Jwts.ZIP.GZIP))
        assertArrayEquals(content, payload.getBytes())
        assertSame(payload.getBytes(), payload.getBytes())
    }

    @Test
    void testCompressionCodecItselfBoundsDecompression() {
        for (def codec : [Jwts.ZIP.DEF, Jwts.ZIP.GZIP]) {
            byte[] compressed = ((CompressionCodec) codec).compress(oversizedPayload())
            try {
                ((CompressionCodec) codec).decompress(compressed)
                fail()
            } catch (CompressionException e) {
                assertTrue(e.message.contains("algorithm '" + codec.id + "'"))
                assertTrue(e.message.contains(Streams.MAX_DECOMPRESSED_PAYLOAD_SIZE.toString()))
            }
        }
    }
}
