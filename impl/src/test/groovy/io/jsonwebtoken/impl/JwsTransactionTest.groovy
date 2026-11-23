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
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Locator
import io.jsonwebtoken.security.SecureDigestAlgorithm
import io.jsonwebtoken.security.SecureRequest
import io.jsonwebtoken.security.SecurityException
import io.jsonwebtoken.security.VerifySecureDigestRequest
import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.Key
import java.security.PrivateKey
import java.security.PublicKey

import static org.junit.Assert.*

class JwsTransactionTest {

    @Test
    void testFailedKeySwitchRetryKeepsHeaderKeyAndClaimsFromCurrentJws() {

        def firstPair = Jwts.SIG.RS256.keyPair().build()
        def secondPair = Jwts.SIG.RS256.keyPair().build()

        String firstToken = Jwts.builder()
                .header().keyId('shared').and()
                .subject('first')
                .signWith(firstPair.private as PrivateKey, Jwts.SIG.RS256)
                .compact()

        String secondToken = Jwts.builder()
                .header().keyId('shared').and()
                .subject('second')
                .signWith(secondPair.private as PrivateKey, Jwts.SIG.RS256)
                .compact()

        def locator = new Locator<Key>() {
            Key current
            JwsHeader seen

            @Override
            Key locate(Header header) {
                this.seen = header as JwsHeader
                return current
            }
        }

        def parser = Jwts.parser().keyLocator(locator).build()

        // The first attempt is from the old key generation and must fail; it must not cache the first header.
        locator.current = firstPair.public
        try {
            parser.parseSignedClaims(secondToken)
            fail('the first key generation must not verify the new token')
        } catch (io.jsonwebtoken.JwtException expected) {
            // expected
        }
        JwsHeader firstHeader = locator.seen

        // Retry with the new key generation.  The result must use the second token's header, not the failed one.
        locator.current = secondPair.public
        def jws = parser.parseSignedClaims(secondToken)

        assertEquals 'second', jws.payload.subject
        assertEquals 'shared', jws.header.keyId
        assertSame jws.header, locator.seen
        assertNotSame firstHeader, jws.header
        assertEquals secondToken.substring(secondToken.lastIndexOf('.') + 1), jws.getSignature()
    }

    @Test
    void testHeaderAlgorithmAndLocatedKeyMismatchIsRejected() {

        // Token header declares RS256, but the token was actually signed with an EC key (ES256):
        def ecPair = Jwts.SIG.ES256.keyPair().build()
        String es256Token = Jwts.builder().subject('ec').signWith(ecPair.private as PrivateKey, Jwts.SIG.ES256).compact()
        // Rewrite the header to claim RS256, keeping the ES256 signature:
        int i = es256Token.indexOf('.')
        String rs256Header = io.jsonwebtoken.io.Encoders.BASE64URL.encode('{"alg":"RS256"}'.getBytes('UTF-8'))
        String mismatched = rs256Header + es256Token.substring(i)

        def locator = new Locator<Key>() {
            @Override
            Key locate(Header header) {
                return ecPair.public // locator returns an EC key for an RS256 header
            }
        }
        def parser = Jwts.parser().keyLocator(locator).build()

        // The parser must not fall back to the key's algorithm (ES256) to verify; it must reject:
        try {
            parser.parseSignedClaims(mismatched)
            fail('an RS256 header with an EC verification key must not verify')
        } catch (io.jsonwebtoken.JwtException expected) {
            // expected
        }

        // Retrying the same token must also fail; no state from the failed attempt may leak into the retry:
        try {
            parser.parseSignedClaims(mismatched)
            fail('a retry of an algorithm/key mismatch must not verify either')
        } catch (io.jsonwebtoken.JwtException expected) {
            // expected
        }

        // Sanity check: the unmodified ES256 token still verifies with the same parser and locator:
        def jws = parser.parseSignedClaims(es256Token)
        assertEquals 'ec', jws.payload.subject
        assertEquals 'ES256', jws.header.algorithm
    }

    @Test
    void testRegistryRetryDoesNotSwapAlgorithms() {

        // A stateful registry that returns a different algorithm instance on retry must not be able to make the
        // parser verify with one algorithm and mark the token verified with another:
        def key = Jwts.SIG.HS256.key().build()
        String token = Jwts.builder().subject('registry').signWith(key, Jwts.SIG.HS256).compact()

        def failOnce = new FailOnceVerify(Jwts.SIG.HS256)
        def parser = Jwts.parser().verifyWith(key).sig().add(failOnce).and().build()

        try {
            parser.parseSignedClaims(token)
            fail('the first verification attempt must fail')
        } catch (SecurityException expected) {
            // expected
        }

        def jws = parser.parseSignedClaims(token)
        assertEquals 'registry', jws.payload.subject
        assertEquals 'HS256', jws.header.algorithm
        assertEquals 2, failOnce.attempts
    }

    @Test
    void testHmacRsaEcAndEdDsaCompatibility() {

        SecretKey hmacKey = Jwts.SIG.HS256.key().build()
        String hmacToken = Jwts.builder().subject('hmac').signWith(hmacKey).compact()
        assertEquals 'hmac', Jwts.parser().verifyWith(hmacKey).build().parseSignedClaims(hmacToken).payload.subject

        def rsaPair = Jwts.SIG.RS256.keyPair().build()
        String rsaToken = Jwts.builder().subject('rsa').signWith(rsaPair.private as PrivateKey, Jwts.SIG.RS256).compact()
        assertEquals 'rsa', Jwts.parser().verifyWith(rsaPair.public as PublicKey).build()
                .parseSignedClaims(rsaToken).payload.subject

        def ecPair = Jwts.SIG.ES256.keyPair().build()
        String ecToken = Jwts.builder().subject('ec').signWith(ecPair.private as PrivateKey, Jwts.SIG.ES256).compact()
        assertEquals 'ec', Jwts.parser().verifyWith(ecPair.public as PublicKey).build()
                .parseSignedClaims(ecToken).payload.subject

        def edPair = Jwts.SIG.EdDSA.keyPair().build()
        String edToken = Jwts.builder().subject('ed').signWith(edPair.private as PrivateKey, Jwts.SIG.EdDSA).compact()
        assertEquals 'ed', Jwts.parser().verifyWith(edPair.public as PublicKey).build()
                .parseSignedClaims(edToken).payload.subject
    }

    @Test
    void testMinimumKeyLengthsStillEnforced() {

        // 16 bytes = 128 bits, too small for HS256 (requires >= 256 bits):
        SecretKey weak = new SecretKeySpec(new byte[16], 'HmacSHA256')
        try {
            Jwts.builder().subject('weak').signWith(weak, Jwts.SIG.HS256).compact()
            fail('a key smaller than the HS256 minimum must be rejected')
        } catch (io.jsonwebtoken.security.WeakKeyException expected) {
            // expected
        }

        SecretKey strong = Jwts.SIG.HS256.key().build()
        String token = Jwts.builder().subject('strong').signWith(strong, Jwts.SIG.HS256).compact()
        assertEquals 'strong', Jwts.parser().verifyWith(strong).build().parseSignedClaims(token).payload.subject
    }

    @Test
    void testExplicitUnsecuredModePreserved() {

        String unsecured = Jwts.builder().subject('none').compact()

        // Disabled by default:
        try {
            Jwts.parser().build().parseUnsecuredClaims(unsecured)
            fail('unsecured JWTs must be rejected unless explicitly enabled')
        } catch (io.jsonwebtoken.UnsupportedJwtException expected) {
            // expected
        }

        // Explicitly enabled:
        def jwt = Jwts.parser().unsecured().build().parseUnsecuredClaims(unsecured)
        assertEquals 'none', jwt.payload.subject
        assertEquals 'none', jwt.header.algorithm
    }

    @Test
    void testDefaultJwsHeaderSnapshotsMutableValues() {

        byte[] thumbprint = [1, 2, 3] as byte[]
        JwsHeader header = new DefaultJwsHeader([alg: 'HS256', 'x5t': thumbprint])

        thumbprint[0] = 9

        assertArrayEquals([1, 2, 3] as byte[], header.getX509Sha1Thumbprint())
    }

    @Test
    void testDefaultJwsSnapshotsHeaderAndSignature() {

        def source = new DefaultJwtHeaderBuilder()
        source.put('alg', 'HS256')
        def header = new DefaultJwsHeader(source)
        def claims = Jwts.claims().subject('snapshot').build()
        byte[] sig = new byte[32]
        String b64UrlSig = io.jsonwebtoken.io.Encoders.BASE64URL.encode(sig)

        def jws = new DefaultJws(header, claims, sig, b64UrlSig)
        sig[0] = 9

        assertEquals 'HS256', jws.header.algorithm
        assertArrayEquals(new byte[32], jws.digest)
        assertEquals b64UrlSig, jws.signature
    }

    private static class FailOnceVerify implements SecureDigestAlgorithm<SecretKey, SecretKey> {

        final SecureDigestAlgorithm<SecretKey, SecretKey> delegate
        int attempts

        FailOnceVerify(SecureDigestAlgorithm<SecretKey, SecretKey> delegate) {
            this.delegate = delegate
        }

        @Override
        String getId() {
            return delegate.id
        }

        @Override
        byte[] digest(SecureRequest<InputStream, SecretKey> request) {
            return delegate.digest(request)
        }

        @Override
        boolean verify(VerifySecureDigestRequest<SecretKey> request) {
            if (++attempts == 1) {
                throw new SecurityException('expected first failure')
            }
            return delegate.verify(request)
        }
    }
}
