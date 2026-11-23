/*
 * Copyright (C) 2026 jsonwebtoken.io
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
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.ProtectedHeader
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.io.Streams
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Deserializer
import org.junit.Test

import static org.junit.Assert.*

/**
 * Asserts that a critical header set, the parser's supported capabilities, the header data, and the final Jwt are all
 * evaluated as one transaction.  In particular, migrating or rebuilding a header must never silently remove a critical
 * name that the parser does not support.
 */
class CritMigrationTransactionTest {

    private static Map<String, ?> headerMap(String jwt) {
        def tokenized = new JwtTokenizer().tokenize(Streams.reader(jwt))
        byte[] bytes = Decoders.BASE64URL.decode(tokenized.getProtected())
        def deserializer = Services.get(Deserializer)
        return deserializer.deserialize(Streams.reader(bytes)) as Map<String, ?>
    }

    @Test
    void testHeaderBuilderMigrationRetainsEveryCriticalName() {

        // 'unsupported' intentionally has no corresponding header value: the migration must not silently discard it,
        // because doing so would make the migrated header look as though the extension was handled.
        def crit = ['b64', 'unsupported'] as Set<String>
        def map = [alg: 'HS256', b64: false, crit: crit]

        ProtectedHeader header = Jwts.header().add(map).build() as ProtectedHeader

        assertEquals crit, header.getCritical()
    }

    @Test
    void testJwtBuilderMigrationRetainsUnsupportedCriticalName() {

        def key = TestKeys.HS256
        def crit = ['b64', 'unsupported'] as Set<String>
        def map = [alg: 'HS256', b64: false, crit: crit]

        String jws = Jwts.builder()
                .setHeader(map)
                .subject('me')
                .encodePayload(false)
                .signWith(key)
                .compact()

        // The migrated token must still carry every critical name:
        assertEquals crit, (headerMap(jws).get('crit') as Set)

        try {
            Jwts.parser().critical().add('b64').and().verifyWith(key).build().parseSignedClaims(jws)
            fail()
        } catch (MalformedJwtException expected) {
            // 'unsupported' has no associated header parameter, so it is malformed rather than accepted.
            assertTrue expected.message.contains("unsupported")
        }
    }

    @Test
    void testUnsecuredMigrationRetainsCriticalHeader() {

        def crit = ['unsupported'] as Set<String>
        String jwt = Jwts.builder()
                .header().add('crit', crit).and()
                .subject('me')
                .compact()

        // The unsecured compact form must not drop 'crit' during header migration:
        assertEquals crit, (headerMap(jwt).get('crit') as Set)

        try {
            Jwts.parser().unsecured().critical().add('unsupported').and().build().parseUnsecuredClaims(jwt)
            fail()
        } catch (MalformedJwtException expected) {
            // Unsecured JWTs may not use 'crit' at all, regardless of configured support.
            assertTrue expected.message.contains('crit')
        }
    }

    @Test
    void testUnsupportedCriticalHeaderWithValueIsRejected() {

        def key = TestKeys.HS256
        def crit = ['b64', 'unsupported'] as Set<String>
        def map = [alg: 'HS256', b64: false, crit: crit, unsupported: true]

        String jws = Jwts.builder()
                .setHeader(map)
                .subject('me')
                .encodePayload(false)
                .signWith(key)
                .compact()

        try {
            Jwts.parser().critical().add('b64').and().verifyWith(key).build().parseSignedClaims(jws)
            fail()
        } catch (UnsupportedJwtException expected) {
            assertTrue expected.message.contains('unsupported')
        }
    }

    @Test
    void testExplicitlySupportedCriticalHeaderStillWorks() {

        def key = TestKeys.HS256
        def crit = ['b64'] as Set<String>
        def map = [alg: 'HS256', b64: false, crit: crit]

        String jws = Jwts.builder()
                .setHeader(map)
                .subject('me')
                .encodePayload(false)
                .signWith(key)
                .compact()

        def jwt = Jwts.parser().critical().add('b64').and().verifyWith(key).build().parseSignedClaims(jws)

        assertEquals 'me', jwt.getPayload().getSubject()
        assertEquals crit, jwt.getHeader().getCritical()
    }

    @Test
    void testFinalJwtCriticalSetIsImmutable() {

        def key = TestKeys.HS256
        def crit = ['b64'] as Set<String>
        def map = [alg: 'HS256', b64: false, crit: crit]

        String jws = Jwts.builder()
                .setHeader(map)
                .subject('me')
                .encodePayload(false)
                .signWith(key)
                .compact()

        def jwt = Jwts.parser().critical().add('b64').and().verifyWith(key).build().parseSignedClaims(jws)

        try {
            jwt.getHeader().getCritical().add('late-addition')
            fail()
        } catch (UnsupportedOperationException expected) {
            // expected: the final Jwt shares the validated critical set, it cannot be mutated afterwards
        }

        try {
            (jwt.getHeader().get('crit') as Set).add('late-addition')
            fail()
        } catch (UnsupportedOperationException expected) {
            // expected: the header data backing the critical set is immutable as well
        }
    }

    @Test
    void testParserSupportIsFrozenAtBuildTime() {

        def key = TestKeys.HS256
        def crit = ['b64'] as Set<String>
        def map = [alg: 'HS256', b64: false, crit: crit]

        String jws = Jwts.builder()
                .setHeader(map)
                .subject('me')
                .encodePayload(false)
                .signWith(key)
                .compact()

        def builder = Jwts.parser().critical().add('b64').and().verifyWith(key)
        def parser = builder.build()

        // The already-built parser keeps the capability snapshot it was built with:
        builder.critical().clear()

        def jwt = parser.parseSignedClaims(jws)
        assertEquals 'me', jwt.getPayload().getSubject()
        assertEquals crit, jwt.getHeader().getCritical()
    }

    @Test
    void testBuilderRetryCannotSilentlyDropNewCriticalRequirement() {

        def key = TestKeys.HS256
        def builder = Jwts.builder()
        builder.header().add('b64', false).add('crit', ['b64'] as Set).and()
        builder.subject('me').encodePayload(false).signWith(key)

        String first = builder.compact()
        assertEquals 'me',
                Jwts.parser().critical().add('b64').and().verifyWith(key).build()
                        .parseSignedClaims(first).getPayload().getSubject()

        // Simulate a retry that adds another critical extension after the first issuance.  It must not be discarded
        // just because no corresponding header parameter was supplied; the retried token must fail closed instead.
        builder.header().critical().add('unsupported').and()
        String retried = builder.compact()

        assertEquals(['b64', 'unsupported'] as Set, (headerMap(retried).get('crit') as Set))

        try {
            Jwts.parser().critical().add('b64').and().verifyWith(key).build().parseSignedClaims(retried)
            fail()
        } catch (MalformedJwtException expected) {
            assertTrue expected.message.contains('unsupported')
        }
    }
}
