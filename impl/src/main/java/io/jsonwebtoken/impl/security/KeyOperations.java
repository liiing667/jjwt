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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.KeyOperation;

import java.security.Key;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Internal utility that binds a JWK's declared {@link KeyOperation key_ops} to the actual cryptographic
 * operation being performed (JWS verification or JWE decryption/key unwrap). All key-selection code paths
 * (the built-in {@link DefaultJwkSetLocator} and {@link io.jsonwebtoken.impl.DefaultJwtParser} regardless of
 * whether a JWS or JWE is being processed) delegate here so that authorization is evaluated as one consistent
 * transaction.
 *
 * @since 0.14.0
 */
public final class KeyOperations {

    private KeyOperations() {
    }

    /** Operation required when verifying a JWS MAC or digital signature. */
    public static final KeyOperation VERIFY = DefaultKeyOperation.VERIFY;

    /** Operation required when directly decrypting JWE content with the located key. */
    public static final KeyOperation DECRYPT = DefaultKeyOperation.DECRYPT;

    /** Operation required when the located key unwraps (decrypts) the JWE Content Encryption Key. */
    public static final KeyOperation UNWRAP = DefaultKeyOperation.UNWRAP;

    /**
     * JWE &quot;alg&quot; identifiers whose key management mode is direct (the located key directly derives or
     * represents the Content Encryption Key and no encrypted key value is produced). Every other standard JWE
     * key management algorithm encrypts/wraps the CEK and therefore requires {@code unwrapKey}.
     */
    private static final Set<String> DIRECT_JWE_ALGS =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList("dir", "ECDH-ES")));

    /**
     * Returns {@code true} if a JWE with the specified {@code alg} key-management algorithm identifier uses
     * the located key directly (no encrypted CEK), {@code false} if the located key unwraps an encrypted CEK.
     *
     * @param jweAlg the JWE {@code alg} header value
     * @return {@code true} for direct key-management algorithms, {@code false} otherwise
     */
    public static boolean isDirectKeyManagement(String jweAlg) {
        return jweAlg != null && DIRECT_JWE_ALGS.contains(jweAlg);
    }

    /**
     * Returns the key operation required to process the specified protected header: {@link #VERIFY} for a JWS,
     * and {@link #DECRYPT} or {@link #UNWRAP} for a JWE depending on the JWE key-management mode implied by
     * its {@code alg} header.
     *
     * @param header the encountered JWS or JWE header
     * @return the single key operation that a located key must be authorized for
     */
    public static KeyOperation required(ProtectedHeader header) {
        Assert.notNull(header, "ProtectedHeader cannot be null.");
        if (header instanceof JwsHeader) {
            return VERIFY;
        }
        if (header instanceof JweHeader) {
            String alg = header.getAlgorithm();
            return isDirectKeyManagement(alg) ? DECRYPT : UNWRAP;
        }
        throw new InvalidKeyException("Unrecognized ProtectedHeader type: " + header.getClass().getName());
    }

    /**
     * Returns {@code true} if the specified JWK may be used for the requested operation, {@code false}
     * otherwise. A JWK that does not declare any {@code key_ops} is treated as unrestricted and remains
     * usable for every operation (RFC 7517 backwards-compatible behavior).
     *
     * @param jwk      the candidate JWK
     * @param required the operation the JWK must be authorized for
     * @return {@code true} if the JWK is authorized for {@code required}
     */
    public static boolean isAuthorized(Jwk<?> jwk, KeyOperation required) {
        Assert.notNull(jwk, "Jwk cannot be null.");
        Assert.notNull(required, "Required KeyOperation cannot be null.");
        Set<KeyOperation> ops = jwk.getOperations();
        return ops == null || ops.isEmpty() || ops.contains(required);
    }

    private static String keyId(Jwk<?> jwk) {
        String id = jwk.getId();
        return Strings.hasText(id) ? "'" + id + "'" : "without a 'kid' value";
    }

    /**
     * Asserts that the specified JWK is authorized for the requested operation, throwing an
     * {@link InvalidKeyException} that names both the offending key and the rejected operation otherwise.
     *
     * @param jwk      the candidate JWK
     * @param required the operation the JWK must be authorized for
     * @throws InvalidKeyException if the JWK declares operations that do not include {@code required}
     */
    public static void assertAuthorized(Jwk<?> jwk, KeyOperation required) {
        if (!isAuthorized(jwk, required)) {
            String msg = "JWK " + keyId(jwk) + " declares key operation(s) " + jwk.getOperations() +
                    " and is not authorized for the required '" + required.getId() + "' operation.";
            throw new InvalidKeyException(msg);
        }
    }

    /**
     * If the specified key is a {@link Jwk}, asserts that it is authorized for the requested operation. Plain
     * {@link Key} instances returned by custom {@link io.jsonwebtoken.Locator} implementations carry no JWK
     * operation metadata and are therefore left to the parser's existing key-type checks.
     *
     * @param key      the key returned by a locator, possibly a {@link Jwk}
     * @param required the operation the key must be authorized for
     * @throws InvalidKeyException if the key is a JWK not authorized for {@code required}
     */
    public static void assertKeyAuthorized(Key key, KeyOperation required) {
        if (key instanceof Jwk) {
            assertAuthorized((Jwk<?>) key, required);
        }
    }
}
