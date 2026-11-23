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

import io.jsonwebtoken.Locator;

import java.security.Key;
import java.util.function.Supplier;

/**
 * A {@link Locator} that resolves the {@link Key} needed to verify a JWS signature or decrypt a JWE from the
 * {@link Jwk JWK}s contained within one or more {@link JwkSet}s.
 *
 * <p><b>Operation-aware authorization</b></p>
 *
 * <p>Unlike a hand-written {@code Locator} that typically ignores a JWK's
 * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">{@code key_ops}</a> parameter, a
 * {@code JwkSetLocator} treats each key lookup as a single authorization transaction that binds together:</p>
 * <ol>
 *     <li>the {@link Jwk#getOperations() operations} declared by the candidate JWK,</li>
 *     <li>the actual cryptographic operation being performed (JWS {@code verify} or JWE
 *     {@code decrypt}/{@code unwrapKey}), and</li>
 *     <li>the {@link Key} ultimately returned for that operation.</li>
 * </ol>
 * <p>A JWK that declares operations is returned only if it explicitly allows the operation required by the
 * encountered JWS or JWE. For example, a JWK declaring only {@link Jwks.OP#ENCRYPT encrypt} /
 * {@link Jwks.OP#DECRYPT decrypt} will never be returned to verify a JWS signature, and a JWK declaring only
 * {@link Jwks.OP#SIGN sign} / {@link Jwks.OP#VERIFY verify} will never be returned to decrypt a JWE. JWKs that do
 * not declare any {@code key_ops} remain fully backwards-compatible and are considered authorized for any
 * operation.</p>
 *
 * <p>When no located JWK is authorized for the required operation, an {@link InvalidKeyException} is thrown that
 * identifies the offending key (via its {@link Jwk#getId() key ID} when present) and the operation that was
 * rejected, instead of a generic cryptographic failure.</p>
 *
 * <p><b>Refreshing / rotating JWK Sets</b></p>
 *
 * <p>The {@link Jwks#setLocator(Supplier)} factory accepts a {@link Supplier} that is invoked on every
 * {@link #locate(io.jsonwebtoken.Header) lookup}. This allows applications to refresh or rotate JWK Sets (for
 * example by re-fetching a remote JWK Set) without ever caching stale key material or reusing a previously
 * granted operation against a different key.</p>
 *
 * @see Jwks#setLocator(JwkSet)
 * @see Jwks#setLocator(Supplier)
 * @since 0.14.0
 */
public interface JwkSetLocator extends Locator<Key> {
}
