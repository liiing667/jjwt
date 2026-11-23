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

import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.JwkSetLocator;
import io.jsonwebtoken.security.KeyOperation;

import java.security.Key;
import java.util.function.Supplier;

/**
 * Operation-aware {@link JwkSetLocator} implementation. Every {@link #locate(Header) lookup} is executed as a
 * single authorization transaction: the required cryptographic operation is derived from the encountered
 * header, the current JWK Set is obtained, candidate JWKs are matched by {@code kid} (when present) and then
 * filtered by the JWK's declared {@link KeyOperation key_ops}, and only an authorized JWK's {@link Key} is
 * returned.
 *
 * <p>No resolved key or granted operation is cached between lookups, so rotating/refreshing the underlying
 * JWK Set via the supplier can never leave a stale operation bound to a different key.</p>
 *
 * @since 0.14.0
 */
public class DefaultJwkSetLocator extends LocatorAdapter<Key> implements JwkSetLocator {

    private final Supplier<JwkSet> setSupplier;

    public DefaultJwkSetLocator(JwkSet set) {
        this(new ConstantSupplier(Assert.notNull(set, "JwkSet cannot be null.")));
    }

    public DefaultJwkSetLocator(Supplier<JwkSet> setSupplier) {
        this.setSupplier = Assert.notNull(setSupplier, "JwkSet supplier cannot be null.");
    }

    /**
     * Reflection-invoked factory used by {@code io.jsonwebtoken.security.Jwks#setLocator(JwkSet)}.
     */
    @SuppressWarnings("unused")
    public static JwkSetLocator of(JwkSet set) {
        return new DefaultJwkSetLocator(set);
    }

    /**
     * Reflection-invoked factory used by {@code io.jsonwebtoken.security.Jwks#setLocator(Supplier)}.
     */
    @SuppressWarnings("unused")
    public static JwkSetLocator of(Supplier<JwkSet> supplier) {
        return new DefaultJwkSetLocator(supplier);
    }

    private JwkSet currentSet() {
        JwkSet set = this.setSupplier.get();
        return Assert.notNull(set, "Located JwkSet cannot be null.");
    }

    @Override
    protected Key locate(JwsHeader header) {
        return locate(header, KeyOperations.required(header));
    }

    @Override
    protected Key locate(JweHeader header) {
        // Direct key-management algorithms (dir, ECDH-ES) use 'decrypt'; all others unwrap the CEK:
        KeyOperation required = KeyOperations.required(header);
        return locate(header, required);
    }

    private Key locate(ProtectedHeader header, KeyOperation required) {

        String kid = header.getKeyId();
        boolean kidPresent = Strings.hasText(kid);

        // Phase 1 - key selection over the current (possibly freshly refreshed) JWK Set, preserving set order:
        Jwk<?> selected = null;     // identity-pinned selection (kid match or first key without kid)
        Jwk<?> authorized = null;   // first candidate explicitly allowed for the required operation

        for (Jwk<?> jwk : currentSet()) {

            boolean candidate = !kidPresent || kid.equals(jwk.getId());
            if (!candidate) {
                continue; // never substitute a key with a different 'kid'
            }

            if (selected == null) {
                selected = jwk; // first matching JWK in set order wins identity selection
            }
            if (authorized == null && KeyOperations.isAuthorized(jwk, required)) {
                authorized = jwk;
            }
        }

        // Phase 2 - operation authorization, bound to the selected identity:
        if (kidPresent) {
            // The 'kid' pins the exact key: never fall through to another key's granted operation.
            if (selected == null) {
                throw notAuthorized(header, required, true, kid);
            }
            KeyOperations.assertAuthorized(selected, required); // names the real key + operation on failure
            return selected.toKey();
        }

        // No 'kid': choose the first operation-authorized candidate; unrestricted (no key_ops) legacy
        // JWKs remain fully supported.
        if (authorized != null) {
            return authorized.toKey();
        }
        throw notAuthorized(header, required, false, kid);
    }

    private static InvalidKeyException notAuthorized(ProtectedHeader header, KeyOperation required,
                                                     boolean kidPresent, String kid) {
        StringBuilder sb = new StringBuilder("Unable to locate a key authorized for '")
                .append(required.getId()).append("' for JWT header: ").append(header).append('.');
        if (kidPresent) {
            sb.append(" No JWK with key ID '").append(kid)
                    .append("' is present in the JWK Set, or the matching JWK does not declare the required '")
                    .append(required.getId()).append("' operation.");
        } else {
            sb.append(" No JWK in the JWK Set declares the required '").append(required.getId())
                    .append("' operation.");
        }
        return new InvalidKeyException(sb.toString());
    }

    /**
     * Minimal internal supplier that always returns the same immutable set, used when a {@link JwkSet} is
     * supplied directly.
     */
    private static final class ConstantSupplier implements Supplier<JwkSet> {
        private final JwkSet set;

        private ConstantSupplier(JwkSet set) {
            this.set = set;
        }

        @Override
        public JwkSet get() {
            return this.set;
        }
    }
}
