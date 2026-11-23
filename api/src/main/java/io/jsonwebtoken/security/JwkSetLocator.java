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
import io.jsonwebtoken.Locator;

import java.security.Key;

/**
 * A versioned {@link Locator} that selects JWS verification keys from a {@link JwkSet}.  Each call to
 * {@link #refresh(JwkSet)} installs a complete new key generation atomically.  A selection already in progress keeps
 * using the generation from which it started, and a token parse always publishes the JWK, algorithm and generation
 * that actually verified the token.
 *
 * <p>Keys are matched by the JWT {@code kid} header.  A JWK Set containing exactly one usable verification key may be
 * used for tokens without a {@code kid} header.  If multiple usable keys are present, a missing {@code kid} is
 * ambiguous and parsing fails.</p>
 *
 * @since 0.14.0
 */
public interface JwkSetLocator extends Locator<Key> {

    /**
     * Returns the currently installed JWK Set generation.
     *
     * @return the currently installed JWK Set generation.
     */
    JwkSet getJwkSet();

    /**
     * Returns the current generation number.  The first installed JWK Set is generation {@code 1}, and the value
     * increases by one after every successful {@link #refresh(JwkSet)} call.
     *
     * @return the current generation number.
     */
    long getGeneration();

    /**
     * Atomically replaces the current JWK Set with a complete new generation.  If the argument is invalid, the
     * existing generation remains available and unchanged.
     *
     * @param jwkSet the complete new JWK Set generation
     * @return this locator for method chaining
     */
    JwkSetLocator refresh(JwkSet jwkSet);

    /**
     * Selects a key and returns the complete selection evidence for the specified JWT header.
     *
     * @param header the JWT header used to select the key
     * @return the complete key selection evidence
     * @throws io.jsonwebtoken.UnsupportedJwtException if no unambiguous verification key is available
     */
    KeySelection select(Header header);
}
