/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken

import io.jsonwebtoken.impl.DefaultJwsHeader
import io.jsonwebtoken.impl.DefaultJwtParser
import io.jsonwebtoken.impl.io.Streams
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import java.security.Key

import static org.junit.Assert.*

/**
 * Test cases for https://datatracker.ietf.org/doc/html/rfc7797 functionality.
 */
class RFC7797Test {

    @Test
    void testJwe() {
        try {
            Jwts.builder().content('hello').encryptWith(TestKeys.A128GCM, Jwts.ENC.A128GCM)
                    .encodePayload(false) // not allowed with JWE
                    .compact()
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'Payload encoding may not be disabled for JWEs, only JWSs.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void testUnprotectedJwt() {
        try {
            Jwts.builder().content('hello')
                    .encodePayload(false) // not allowed with JWT
                    .compact()
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'Payload encoding may not be disabled for unprotected JWTs, only JWSs.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void parseSignedContentBytes() {

        def key = TestKeys.HS256

        byte[] content = Strings.utf8('$.02') // https://datatracker.ietf.org/doc/html/rfc7797#section-4.2

        String s = Jwts.builder().signWith(key).content(content).encodePayload(false).compact()

        // Verify with 3 types of sources: byte array and two different kinds of InputStreams:
        InputStream asByteInputStream = Streams.of(content)
        InputStream asBufferedInputStream = new BufferedInputStream(Streams.of(content))

        for (def payload : [content, asByteInputStream, asBufferedInputStream]) {
            def parser = Jwts.parser().verifyWith(key).build()
            def jws
            if (payload instanceof byte[]) {
                jws = parser.parseSignedContent(s, (byte[]) payload)
            } else {
                jws = parser.parseSignedContent(s, (InputStream) payload)
            }
            // The parser materializes the unencoded payload bytes in a single read transaction, so the
            // returned JWS payload must always be exactly the bytes that were verified, regardless of the
            // supplied source type:
            assertArrayEquals content, jws.getPayload()
        }
    }

    @Test
    void parseSignedClaimsBytes() {

        def key = TestKeys.HS256

        def claims = Jwts.claims().subject('me').build()

        ByteArrayOutputStream out = new ByteArrayOutputStream()
        Services.get(Serializer).serialize(claims, out)
        byte[] content = out.toByteArray()

        String s = Jwts.builder().signWith(key).content(content).encodePayload(false).compact()

        // But verify with 3 types of sources: string, byte array, and two different kinds of InputStreams:
        InputStream asByteInputStream = Streams.of(content)
        InputStream asBufferedInputStream = new BufferedInputStream(Streams.of(content))

        for (def payload : [content, asByteInputStream, asBufferedInputStream]) {
            def parser = Jwts.parser().verifyWith(key).build()
            def jws
            if (payload instanceof byte[]) {
                jws = parser.parseSignedClaims(s, (byte[]) payload)
            } else {
                jws = parser.parseSignedClaims(s, (InputStream) payload)
            }
            assertEquals claims, jws.getPayload()
        }
    }

    @Test
    void parseSignedContentByteArrayInputStream() {

        def key = TestKeys.HS256

        byte[] content = Strings.utf8('$.02') // https://datatracker.ietf.org/doc/html/rfc7797#section-4.2
        InputStream contentStream = Streams.of(content)

        String s = Jwts.builder().signWith(key).content(contentStream).encodePayload(false).compact()

        // Verify with 3 types of sources: byte array and two different kinds of InputStreams:
        InputStream asByteInputStream =Streams.of(content)
        InputStream asBufferedInputStream = new BufferedInputStream(Streams.of(content))

        for (def payload : [content, asByteInputStream, asBufferedInputStream]) {
            def parser = Jwts.parser().verifyWith(key).build()
            def jws
            if (payload instanceof byte[]) {
                jws = parser.parseSignedContent(s, (byte[]) payload)
            } else {
                jws = parser.parseSignedContent(s, (InputStream) payload)
            }
            // Materialized in a single read transaction, the verified JWS payload is always the exact
            // supplied bytes regardless of source type:
            assertArrayEquals content, jws.getPayload()
        }
    }

    @Test
    void payloadStreamThatDoesNotSupportMark() {
        def key = TestKeys.HS256
        String s = 'Hello-JJWT' // compact token bodies may not contain whitespace or period characters
        byte[] data = Strings.utf8(s)
        InputStream stream = new ByteArrayInputStream(data) {
            @Override
            boolean markSupported() {
                return false
            }

            @Override
            void mark(int readAheadLimit) {
                throw new UnsupportedOperationException("Not supported.")
            }
        }

        // compact/sign shouldn't fail, should still compute signature:
        String compact = Jwts.builder().content(stream).signWith(key).encodePayload(false).compact()

        // signature still verified, and the attached (non-detached) token must carry the exact signed bytes
        // even though the source stream cannot be rewound via mark/reset:
        def jwt = Jwts.parser().verifyWith(key).build().parseSignedContent(compact, data)
        assertEquals 'HS256', jwt.header.getAlgorithm()
        assertEquals s, Strings.utf8(jwt.getPayload())

        // the compact string itself must embed the full raw payload between its two delimiters:
        def parts = compact.split('\\.')
        assertEquals 3, parts.length
        assertEquals s, parts[1]

        // and normal (non-detached) parsing without an externally supplied payload must succeed over the
        // very same bytes, proving signature input and attached payload share one read transaction:
        def parsed = Jwts.parser().verifyWith(key).critical().add(DefaultJwsHeader.B64.id).and().build()
                .parseSignedContent(compact)
        assertArrayEquals data, parsed.getPayload()
    }

    @Test
    void testClaimsPayload() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('{"sub":"me"}')

        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key).build().parseSignedClaims(s, payload)

        assertEquals 'me', jws.getPayload().getSubject()
    }

    /**
     * Asserts that, even if the parser builder is not explicitly called with .critical("b64") to indicate B64 payloads
     * are supported, that a call to .parse*Jws(String, unencodedPayload) still works.  Just the fact that the
     * overloaded method is called explicitly means they want B64 payload support, so it should still 'just work'
     * even if .critical isn't configured.
     */
    @Test
    void critUnspecifiedOnParserBuilder() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('{"sub":"me"}')

        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key) // .critical("b64") is not called, should still work:
                .build().parseSignedClaims(s, payload)

        assertEquals 'me', jws.getPayload().getSubject()
    }

    @Test
    void testEmptyBytesPayload() {
        try {
            Jwts.builder().content(Bytes.EMPTY).encodePayload(false).signWith(TestKeys.HS256).compact()
            fail()
        } catch (IllegalStateException expected) {
            String msg = "'b64' Unencoded payload option has been specified, but payload is empty."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testEmptyInputStreamPayload() {
        // an InputStream that immediately reaches EOF must be treated exactly like an empty byte[] payload:
        InputStream emptyStream = new ByteArrayInputStream(Bytes.EMPTY) {
            @Override
            boolean markSupported() {
                return false
            }
        }
        try {
            Jwts.builder().content(emptyStream).encodePayload(false).signWith(TestKeys.HS256).compact()
            fail()
        } catch (IllegalStateException expected) {
            String msg = "'b64' Unencoded payload option has been specified, but payload is empty."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testParseContentWithEmptyBytesPayload() {
        try {
            Jwts.parser().verifyWith(TestKeys.HS256).build().parseSignedContent('whatever', Bytes.EMPTY) // <-- empty
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'unencodedPayload argument cannot be null or empty.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void testParseClaimsWithEmptyBytesPayload() {
        try {
            Jwts.parser().verifyWith(TestKeys.HS256).build().parseSignedClaims('whatever', Bytes.EMPTY) // <-- empty
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'unencodedPayload argument cannot be null or empty.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void testParseContentWithoutPayload() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('$.02') // https://datatracker.ietf.org/doc/html/rfc7797#section-4.2

        // s is an unencoded-payload JWS
        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()
        def expectedHeader = [alg: 'HS256', b64: false, crit: ['b64']]

        // try to parse it as a 'normal' JWS (without supplying the payload):
        try {
            Jwts.parser().verifyWith(key).critical().add(DefaultJwsHeader.B64.id).and().build()
                    .parseSignedContent(s) // <-- no payload supplied
            fail()
        } catch (io.jsonwebtoken.security.SignatureException expected) {
            String msg = String.format(DefaultJwtParser.B64_MISSING_PAYLOAD, expectedHeader)
            assertEquals msg, expected.message
        }
    }

    @Test
    void testParseClaimsWithoutPayload() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('$.02') // https://datatracker.ietf.org/doc/html/rfc7797#section-4.2

        // s is an unencoded-payload JWS
        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def expectedHeader = [alg: 'HS256', b64: false, crit: ['b64']]

        // try to parse it as a 'normal' JWS (without supplying the payload):
        try {
            Jwts.parser().verifyWith(key).critical().add(DefaultJwsHeader.B64.id).and().build()
                    .parseSignedClaims(s) // <-- no payload supplied
            fail()
        } catch (io.jsonwebtoken.security.SignatureException expected) {
            String msg = String.format(DefaultJwtParser.B64_MISSING_PAYLOAD, expectedHeader)
            assertEquals msg, expected.message
        }
    }

    /**
     * Asserts that, as long as a non-detached unencoded payload does not have period characters in it, it can
     * be parsed 'normally' via normal JWS signature verification logic.  It does this by using the the payload's
     * UTF-8 bytes instead of relying on a user-supplied unencodedPayload byte array.
     */
    @Test
    void testNonDetachedContent() {

        def key = TestKeys.HS256

        String payload = 'foo'

        // create a non-detached unencoded JWS:
        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key).critical().add(DefaultJwsHeader.B64.id).and().build()
                .parseSignedContent(s) // <--- parse normally, without calling parseSignedContent(s, unencodedPayload)

        assertArrayEquals Strings.utf8(payload), jws.getPayload()
    }

    @Test
    void testNonDetachedClaims() {

        def key = TestKeys.HS256

        // create a non-detached unencoded JWS:
        String s = Jwts.builder().signWith(key).subject('me').encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key).critical().add(DefaultJwsHeader.B64.id).and().build()
                .parseSignedClaims(s) // <--- parse normally, without calling parseSignedClaims(s, unencodedPayload)

        assertEquals 'me', jws.getPayload().getSubject()
    }

    @Test
    void testDecompression() {

        def key = TestKeys.HS256

        byte[] content = Strings.utf8('hello world')

        for (def zip : Jwts.ZIP.get().values()) {

            ByteArrayOutputStream out = new ByteArrayOutputStream()
            OutputStream cos = zip.compress(out); cos.write(content); cos.close()
            def compressed = out.toByteArray()

            // create a detached unencoded JWS that is compressed:
            String s = Jwts.builder().signWith(key).content(content).encodePayload(false)
                    .compressWith(zip)
                    .compact()

            // But verify with 3 types of sources: byte array, and two different kinds of InputStreams:
            InputStream asByteInputStream = Streams.of(compressed)
            InputStream asBufferedInputStream = new BufferedInputStream(Streams.of(compressed))

            for (def payload : [compressed, asByteInputStream, asBufferedInputStream]) {
                def parser = Jwts.parser().verifyWith(key).build()
                def jws
                if (payload instanceof byte[]) {
                    jws = parser.parseSignedContent(s, (byte[]) payload)
                } else {
                    jws = parser.parseSignedContent(s, (InputStream) payload)
                }
                // The unencoded payload is materialized once before verification and decompression, so the
                // returned JWS content is always the exact decompressed signed bytes:
                assertArrayEquals content, jws.getPayload()
            }
        }
    }

    /**
     * Safe decompression of an unencoded payload using a SigningKeyResolver (SKR) is not possible because the SKR
     * only verifies signatures after payloads are enabled, and signatures need to be verified before the payload
     * is trusted.  And decompressing an unsecured payload is a security risk.
     */
    @SuppressWarnings('GrDeprecatedAPIUsage')
    @Test
    void testDecompressionWhenSigningKeyResolverIsUsed() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('hello world')

        def zip = Jwts.ZIP.DEF

        // create a detached unencoded JWS that is compressed:
        String s = Jwts.builder().content(payload).encodePayload(false)
                .compressWith(zip).signWith(key).compact()

        // now try to parse a compressed unencoded using a signing key resolver:
        try {
            Jwts.parser()
                    .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                        @Override
                        Key resolveSigningKey(JwsHeader header, byte[] content) {
                            return key
                        }
                    })
                    .build()
                    .parseSignedContent(s, payload)
            fail()
        } catch (UnsupportedJwtException expected) {
            String msg = String.format(DefaultJwtParser.B64_DECOMPRESSION_MSG, zip.id)
            assertEquals msg, expected.message
        }
    }

    /**
     * An InputStream that re-opens/re-reads its underlying source on each {@code read} cycle and whose
     * contents can change between reads.  Before the single-transaction fix, the builder signed the first
     * read's bytes and then emitted whatever a second read returned (potentially empty or appended-to),
     * producing a token whose attached payload did not match its signature input.
     */
    private static class ReusableMutableInputStream extends InputStream {
        private final byte[][] snapshots
        private final boolean supportsMark
        private int snapshotIndex = 0
        private int pos = 0

        ReusableMutableInputStream(byte[]... snapshots) {
            this(false, snapshots)
        }

        ReusableMutableInputStream(boolean supportsMark, byte[]... snapshots) {
            this.supportsMark = supportsMark
            this.snapshots = snapshots
        }

        private byte[] current() {
            if (snapshotIndex >= snapshots.length) return snapshots[snapshots.length - 1]
            return snapshots[snapshotIndex]
        }

        @Override
        int read() {
            byte[] data = current()
            if (pos >= data.length) return -1
            return data[pos++] & 0xff
        }

        @Override
        int read(byte[] b, int off, int len) {
            byte[] data = current()
            if (pos >= data.length) return -1
            int n = Math.min(len, data.length - pos)
            System.arraycopy(data, pos, b, off, n)
            pos += n
            return n
        }

        @Override
        boolean markSupported() {
            return supportsMark
        }

        @Override
        void reset() {
            // simulate a stream that can be retried but serves changed bytes on subsequent reads:
            snapshotIndex++
            pos = 0
        }
    }

    /**
     * Simulates a short/partial read followed by EOF on the first read session, while a later re-read would
     * expose more bytes.  The signed token must reflect only the bytes actually present in the single read
     * transaction and must never silently mix bytes from a second read.
     */
    private static class ShortReadInputStream extends InputStream {
        private final int firstReadLimit
        private final byte[] data
        private int pos = 0
        private boolean firstRead = true

        ShortReadInputStream(byte[] data, int firstReadLimit) {
            this.data = data
            this.firstReadLimit = firstReadLimit
        }

        @Override
        int read(byte[] b, int off, int len) {
            if (pos >= data.length) return -1
            int effective = len
            if (firstRead) {
                effective = Math.min(len, firstReadLimit)
                firstRead = false
            }
            int n = Math.min(effective, data.length - pos)
            System.arraycopy(data, pos, b, off, n)
            pos += n
            return n
        }

        @Override
        int read() {
            if (pos >= data.length) return -1
            return data[pos++] & 0xff
        }

        @Override
        boolean markSupported() {
            return false
        }
    }

    @Test
    void builderReReadableStreamWithAppendedBytesKeepsOneSignedPayload() {

        def key = TestKeys.HS256
        // compact-token-safe content (no whitespace/periods):
        byte[] original = Strings.utf8('dollar-02')
        byte[] appended = Strings.utf8('dollar-02-extra-trailing-bytes')

        def stream = new ReusableMutableInputStream(original, appended)
        String compact = Jwts.builder().signWith(key).content(stream).encodePayload(false).compact()

        // the stream was consumed within a single transaction; the compact token must carry the original
        // bytes verbatim, never the appended bytes from a second read:
        def parts = compact.split('\\.')
        assertEquals Strings.utf8(original), parts[1]

        // verification against the original bytes succeeds:
        def jws = Jwts.parser().verifyWith(key).build().parseSignedContent(compact, original)
        assertArrayEquals original, jws.getPayload()

        // and the appended bytes must verify NOTHING for this token:
        try {
            Jwts.parser().verifyWith(key).build().parseSignedContent(compact, appended)
            fail('Signature verification must fail for bytes not present in the signing transaction.')
        } catch (io.jsonwebtoken.security.SignatureException expected) {
            // expected
        }

        // attached (non-detached) parsing must also use exactly the bytes embedded in the token:
        def parsed = Jwts.parser().verifyWith(key).critical().add(DefaultJwsHeader.B64.id).and().build()
                .parseSignedContent(compact)
        assertArrayEquals original, parsed.getPayload()
    }

    @Test
    void builderShortReadStreamStillProducesSelfConsistentToken() {

        def key = TestKeys.HS256
        byte[] data = Strings.utf8('short-read-payload')

        // first read() returns only 3 bytes, the rest only on subsequent reads of the same transaction:
        def stream = new ShortReadInputStream(data, 3)
        String compact = Jwts.builder().signWith(key).content(stream).encodePayload(false).compact()

        def parts = compact.split('\\.')
        assertEquals Strings.utf8(data), parts[1]

        def jws = Jwts.parser().verifyWith(key).build().parseSignedContent(compact, data)
        assertArrayEquals data, jws.getPayload()
    }

    @Test
    void builderMarkSupportingStreamWithChangedReReadKeepsSignedPayload() {

        def key = TestKeys.HS256
        byte[] first = Strings.utf8('first-transaction')
        byte[] second = Strings.utf8('second-transaction-appended')

        // A mark-supporting stream whose reset() re-opens a source that now serves different bytes.
        // The legacy implementation signed the first read's bytes, reset, and then copied the second read's
        // bytes into the attached token, yielding a token whose body did not match its signature input:
        def stream = new ReusableMutableInputStream(true, first, second)
        String compact = Jwts.builder().signWith(key).content(stream).encodePayload(false).compact()
        def parts = compact.split('\\.')
        assertEquals Strings.utf8(first), parts[1]

        def jws = Jwts.parser().verifyWith(key).build().parseSignedContent(compact, first)
        assertArrayEquals first, jws.getPayload()
        try {
            Jwts.parser().verifyWith(key).build().parseSignedContent(compact, second)
            fail('Appended bytes from a re-read must never verify against the original signature.')
        } catch (io.jsonwebtoken.security.SignatureException expected) {
            // expected
        }
    }

    @Test
    void parserReReadableStreamAlwaysReturnsVerifiedBytes() {

        def key = TestKeys.HS256
        byte[] original = Strings.utf8('dollar-02')
        byte[] appended = Strings.utf8('dollar-02-appended')

        String compact = Jwts.builder().signWith(key).content(original).encodePayload(false).compact()

        // A stream that would hand different bytes on a second read must not allow the returned JWS body
        // to diverge from the bytes that were verified:
        def stream = new ReusableMutableInputStream(original, appended)
        def jws = Jwts.parser().verifyWith(key).build().parseSignedContent(compact, stream)
        assertArrayEquals original, jws.getPayload()

        // and the reverse: verification must fail when the first-transaction bytes themselves don't match:
        def other = new ReusableMutableInputStream(appended, original)
        try {
            Jwts.parser().verifyWith(key).build().parseSignedContent(compact, other)
            fail('Verification must not succeed when the single-read bytes do not match the signature.')
        } catch (io.jsonwebtoken.security.SignatureException expected) {
            // expected
        }
    }

    @Test
    void parserReReadableStreamClaimsAlwaysReturnVerifiedClaims() {

        def key = TestKeys.HS256

        def claims = Jwts.claims().subject('me').build()
        ByteArrayOutputStream out = new ByteArrayOutputStream()
        Services.get(Serializer).serialize(claims, out)
        byte[] content = out.toByteArray()

        String compact = Jwts.builder().signWith(key).content(content).encodePayload(false).compact()

        byte[] tampered = new byte[content.length]
        System.arraycopy(content, 0, tampered, 0, content.length)
        tampered[content.length - 1] = (byte) (tampered[content.length - 1] ^ 0x01)

        def stream = new ReusableMutableInputStream(tampered, content)
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(compact, stream)
            fail('Claims must not be returned when the materialized payload fails signature verification.')
        } catch (io.jsonwebtoken.security.SignatureException expected) {
            // expected
        }
    }

    @Test
    void binaryAndCrlfPayloadRoundTrip() {

        def key = TestKeys.HS256
        // binary content including all byte values, CRLF, NULs and 0xff:
        byte[] content = new byte[512]
        new Random(0x7797).nextBytes(content)
        content[0] = (byte) '\r'
        content[1] = (byte) '\n'
        content[3] = 0x00
        content[511] = (byte) 0xff

        // A compact token body may not contain whitespace, so CRLF/binary content must travel as a detached
        // payload.  Compression also produces a detached token (raw compressed bytes are never embedded), and
        // exercises the parser's verify-before-decompress single-transaction path:
        def zip = Jwts.ZIP.GZIP
        ByteArrayOutputStream compressedOut = new ByteArrayOutputStream()
        OutputStream cos = zip.compress(compressedOut); cos.write(content); cos.close()
        byte[] compressed = compressedOut.toByteArray()

        String detached = Jwts.builder().signWith(key).content(new ByteArrayInputStream(content))
                .encodePayload(false).compressWith(zip).compact()
        def detachedParts = detached.split('\\.', -1)
        assertEquals '', detachedParts[1] // detached: no payload embedded in the compact string

        def jws = Jwts.parser().verifyWith(key).build()
                .parseSignedContent(detached, new ByteArrayInputStream(compressed))
        assertArrayEquals content, jws.getPayload()

        // a single flipped byte anywhere in the binary content must fail verification:
        byte[] tampered = compressed.clone()
        tampered[256 % tampered.length] = (byte) (tampered[256 % tampered.length] ^ 0x01)
        try {
            Jwts.parser().verifyWith(key).build()
                    .parseSignedContent(detached, new ByteArrayInputStream(tampered))
            fail('Binary payload integrity must be enforced across the full byte range.')
        } catch (io.jsonwebtoken.security.SignatureException expected) {
            // expected
        }

        // attached flow for binary-valued bytes restricted to the compact token's legal ASCII body range
        // (the compact serializer is character-based, so arbitrary high bytes are reserved for detached use):
        def legal = ('A'..'Z') + ('a'..'z') + ('0'..'9') + ['-', '_', '~', '!', '$', '&', '*', '=', ';', '@']
        byte[] attachable = new byte[256]
        Random rng = new Random(0x7798)
        for (int i = 0; i < attachable.length; i++) {
            attachable[i] = (byte) (char) legal[rng.nextInt(legal.size())]
        }
        String attached = Jwts.builder().signWith(key).content(attachable).encodePayload(false).compact()
        def parts = attached.split('\\.', -1)
        assertEquals Strings.utf8(attachable), parts[1]
        def parsed = Jwts.parser().verifyWith(key).critical().add(DefaultJwsHeader.B64.id).and().build()
                .parseSignedContent(attached)
        assertArrayEquals attachable, parsed.getPayload()
    }
}
