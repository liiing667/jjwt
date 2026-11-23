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

import io.jsonwebtoken.Header
import io.jsonwebtoken.JweHeader
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Locator
import io.jsonwebtoken.security.AeadAlgorithm
import io.jsonwebtoken.security.AeadRequest
import io.jsonwebtoken.security.AeadResult
import io.jsonwebtoken.security.DecryptAeadRequest
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.Password
import io.jsonwebtoken.security.SecretKeyBuilder
import org.junit.Test

import javax.crypto.SecretKey
import java.security.Key
import java.security.PrivateKey
import java.security.PublicKey

import static org.junit.Assert.*

class JweTransactionTest {

    @Test
    void testFailedKeySwitchRetryKeepsHeaderKeyAndClaimsFromCurrentJwe() {

        def enc = Jwts.ENC.A128GCM
        def firstPair = Jwts.SIG.ES256.keyPair().build()
        def secondPair = Jwts.SIG.ES256.keyPair().build()

        String firstToken = Jwts.builder()
                .header().keyId('shared').and()
                .subject('first')
                .encryptWith(firstPair.public as PublicKey, Jwts.KEY.ECDH_ES, enc)
                .compact()

        String secondToken = Jwts.builder()
                .header().keyId('shared').and()
                .subject('second')
                .encryptWith(secondPair.public as PublicKey, Jwts.KEY.ECDH_ES, enc)
                .compact()

        def locator = new Locator<Key>() {
            Key current
            JweHeader seen

            @Override
            Key locate(Header header) {
                this.seen = header as JweHeader
                return current
            }
        }

        def parser = Jwts.parser().keyLocator(locator).build()

        // The first attempt is from the old key generation and must fail; it must not cache the first header.
        locator.current = secondPair.private
        try {
            parser.parseEncryptedClaims(firstToken)
            fail('the first key generation must not decrypt the new token')
        } catch (io.jsonwebtoken.JwtException expected) {
            // expected
        }
        JweHeader firstHeader = locator.seen

        // Retry with the new key generation.  The result must use the second token's header, not the failed one.
        locator.current = secondPair.private
        def jwe = parser.parseEncryptedClaims(secondToken)

        assertEquals 'second', jwe.payload.subject
        assertEquals 'shared', jwe.header.keyId
        assertSame jwe.header, locator.seen
        assertEquals jwe.header.ephemeralPublicKey, locator.seen.ephemeralPublicKey
        assertNotEquals firstHeader.ephemeralPublicKey, jwe.header.ephemeralPublicKey
    }

    @Test
    void testRsaEcAesPbes2ZipAndCompactCompatibility() {

        def enc = Jwts.ENC.A128GCM
        def directKey = enc.key().build()

        String directToken = Jwts.builder().subject('direct').encryptWith(directKey, enc).compact()
        assertEquals 'direct', parseClaims(directToken, directKey).payload.subject

        def rsaPair = Jwts.SIG.RS256.keyPair().build()
        String rsaToken = Jwts.builder().subject('rsa')
                .encryptWith(rsaPair.public as PublicKey, Jwts.KEY.RSA_OAEP_256, enc).compact()
        assertEquals 'rsa', parseClaims(rsaToken, rsaPair.private).payload.subject

        Password password = Keys.password('correct horse battery staple'.toCharArray())
        String pbes2Token = Jwts.builder()
                .header().pbes2Count(1000).and()
                .subject('pbes2')
                .encryptWith(password, enc)
                .compact()
        assertEquals 'pbes2', parseClaims(pbes2Token, password).payload.subject

        String zipToken = Jwts.builder().subject('zip').compressWith(Jwts.ZIP.DEF)
                .encryptWith(directKey, enc).compact()
        assertEquals 'zip', parseClaims(zipToken, directKey).payload.subject

        byte[] content = [1, 2, 3] as byte[]
        String contentToken = Jwts.builder().content(content).encryptWith(directKey, enc).compact()
        assertArrayEquals content, Jwts.parser().decryptWith(directKey).build()
                .parseEncryptedContent(contentToken).payload
    }

    @Test
    void testDefaultJweHeaderSnapshotsMutableValues() {

        byte[] apu = [1, 2, 3] as byte[]
        JweHeader header = new DefaultJweHeader([enc: 'A128GCM', apu: apu])

        apu[0] = 9

        assertArrayEquals([1, 2, 3] as byte[], header.getAgreementPartyUInfo())
    }

    @Test
    void testDefaultJweSnapshotsHeaderIvAndTag() {

        def source = new DefaultJwtHeaderBuilder()
        source.put('alg', 'dir')
        source.put('enc', 'A128GCM')
        def header = new DefaultMutableJweHeader(source)
        def claims = Jwts.claims().subject('snapshot').build()
        byte[] iv = new byte[16]
        byte[] tag = new byte[16]

        def jwe = new DefaultJwe(header, claims, iv, tag)
        source.put('enc', 'A256GCM')
        iv[0] = 9
        tag[0] = 9

        assertEquals 'A128GCM', jwe.header.encryptionAlgorithm
        assertArrayEquals(new byte[16], jwe.initializationVector)
        assertArrayEquals(new byte[16], jwe.digest)
    }

    @Test
    void testFailedEcdhAttemptDoesNotLeakEpkIntoRetry() {

        def enc = Jwts.ENC.A128GCM
        def pair = Jwts.SIG.ES256.keyPair().build()
        def failOnce = new FailOnceAead(enc)
        def builder = Jwts.builder().subject('retry')

        try {
            builder.encryptWith(pair.public as PublicKey, Jwts.KEY.ECDH_ES, failOnce).compact()
            fail('the first encryption attempt must fail')
        } catch (io.jsonwebtoken.security.SecurityException expected) {
            // expected
        }

        def directKey = enc.key().build()
        String token = builder.encryptWith(directKey, enc).compact()
        def jwe = Jwts.parser().decryptWith(directKey).build().parseEncryptedClaims(token)

        assertEquals 'retry', jwe.payload.subject
        assertNull jwe.header.ephemeralPublicKey
        assertFalse jwe.header.containsKey('epk')
    }

    private static def parseClaims(String compact, SecretKey key) {
        return Jwts.parser().decryptWith(key).build().parseEncryptedClaims(compact)
    }

    private static def parseClaims(String compact, PrivateKey key) {
        return Jwts.parser().decryptWith(key).build().parseEncryptedClaims(compact)
    }

    private static class FailOnceAead implements AeadAlgorithm {

        final AeadAlgorithm delegate
        int attempts

        FailOnceAead(AeadAlgorithm delegate) {
            this.delegate = delegate
        }

        @Override
        String getId() {
            return delegate.id
        }

        @Override
        int getKeyBitLength() {
            return delegate.keyBitLength
        }

        @Override
        SecretKeyBuilder key() {
            return delegate.key()
        }

        @Override
        void encrypt(AeadRequest request, AeadResult result) {
            if (++attempts == 1) {
                throw new io.jsonwebtoken.security.SecurityException('expected first failure')
            }
            delegate.encrypt(request, result)
        }

        @Override
        void decrypt(DecryptAeadRequest request, OutputStream out) {
            delegate.decrypt(request, out)
        }
    }
}
