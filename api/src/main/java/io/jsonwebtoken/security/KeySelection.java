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
package io.jsonwebtoken.security;

import io.jsonwebtoken.Header;

import java.security.Key;

/**
 * The key selected for a single JWT parse operation, including the key generation and fingerprint observed when the
 * key was selected.  A {@code KeySelection} is immutable and remains associated with the token and JWT claims parsed
 * by that same operation even if a key locator is refreshed later.
 *
 * @since 0.14.0
 */
public interface KeySelection {

    /**
     * Returns the protected header of the JWT for which the key was selected.
     *
     * @return the protected header of the JWT for which the key was selected.
     */
    Header getHeader();

    /**
     * Returns the algorithm identifier actually used with the selected key.
     *
     * @return the algorithm identifier actually used with the selected key.
     */
    String getAlgorithm();

    /**
     * Returns the selected JWK's key id, or the JWT header's key id when a raw key was selected.
     *
     * @return the selected key id, or {@code null} if neither the JWK nor JWT header contains one.
     */
    String getKeyId();

    /**
     * Returns the selected JWK, or {@code null} when the key did not come from a JWK Set.
     *
     * @return the selected JWK, or {@code null} when the key did not come from a JWK Set.
     */
    Jwk<?> getJwk();

    /**
     * Returns the selected Java key.
     *
     * @return the selected Java key.
     */
    Key getKey();

    /**
     * Returns a stable SHA-256 fingerprint of the selected key.  JWK selections use the RFC 7638 JWK Thumbprint value,
     * and raw JCA keys use a SHA-256 digest of the encoded key.
     *
     * @return a stable SHA-256 fingerprint of the selected key.
     */
    String getFingerprint();

    /**
     * Returns the key generation observed when the key was selected, or {@code 0} when the key did not come from a
     * versioned key locator.
     *
     * @return the key generation observed when the key was selected, or {@code 0} when the key did not come from a
     * versioned key locator.
     */
    long getGeneration();
}
