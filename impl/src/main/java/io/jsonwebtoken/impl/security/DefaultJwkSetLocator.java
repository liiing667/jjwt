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
import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.AsymmetricJwk;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.JwkSetLocator;
import io.jsonwebtoken.security.KeyOperation;
import io.jsonwebtoken.security.KeySelection;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class DefaultJwkSetLocator implements JwkSetLocator {

    private final Object refreshLock = new Object();

    private volatile Generation current;

    public DefaultJwkSetLocator(JwkSet jwkSet) {
        this.current = new Generation(1L, jwkSet, null);
    }

    @Override
    public JwkSet getJwkSet() {
        return this.current.jwkSet;
    }

    @Override
    public long getGeneration() {
        return this.current.id;
    }

    @Override
    public JwkSetLocator refresh(JwkSet jwkSet) {
        Assert.notNull(jwkSet, "JWK Set cannot be null.");
        synchronized (this.refreshLock) {
            Generation previous = this.current;
            this.current = new Generation(previous.id + 1, jwkSet, previous);
        }
        return this;
    }

    @Override
    public Key locate(Header header) {
        try {
            return select(header).getKey();
        } catch (UnsupportedJwtException e) {
            return null;
        }
    }

    @Override
    public KeySelection select(Header header) {
        final Generation generation = this.current; // capture the complete key generation for this selection
        return generation.select(header);
    }

    private static final class Generation {

        private final long id;
        private final JwkSet jwkSet;
        private final List<Jwk<?>> all;
        private final Map<String, List<Jwk<?>>> byKid;
        private final Map<String, Jwk<?>> firstByKid;
        private final Map<String, List<Jwk<?>>> byLowerKid;
        private final Set<String> preferredFingerprints;

        private Generation(long id, JwkSet jwkSet, Generation previous) {
            Assert.notNull(jwkSet, "JWK Set cannot be null.");
            Set<Jwk<?>> keys = jwkSet.getKeys();
            Assert.notEmpty(keys, "JWK Set keys cannot be null or empty.");
            this.id = id;
            this.jwkSet = jwkSet;
            this.all = new ArrayList<>(keys);
            this.byKid = new LinkedHashMap<>();
            this.firstByKid = new LinkedHashMap<>();
            this.byLowerKid = new LinkedHashMap<>();
            this.preferredFingerprints = new HashSet<>();

            for (Jwk<?> jwk : keys) {
                String kid = Strings.clean(jwk.getId());
                if (!Strings.hasText(kid)) {
                    continue;
                }
                index(this.byKid, kid, jwk);
                index(this.byLowerKid, kid.toLowerCase(Locale.ENGLISH), jwk);
                if (!this.firstByKid.containsKey(kid)) {
                    this.firstByKid.put(kid, jwk);
                }
                Jwk<?> previousJwk = previous != null ? previous.firstByKid.get(kid) : null;
                if (previousJwk != null && !sameKey(previousJwk, jwk)) {
                    this.preferredFingerprints.add(jwk.thumbprint().toString());
                }
            }
        }

        private static void index(Map<String, List<Jwk<?>>> map, String key, Jwk<?> jwk) {
            List<Jwk<?>> keys = map.get(key);
            if (keys == null) {
                keys = new ArrayList<>();
                map.put(key, keys);
            }
            keys.add(jwk);
        }

        private static boolean sameKey(Jwk<?> a, Jwk<?> b) {
            return a.thumbprint().toString().equals(b.thumbprint().toString());
        }

        private KeySelection select(Header header) {
            Assert.notNull(header, "Header cannot be null.");
            String kid = Strings.clean(keyId(header));
            String alg = Strings.clean(header.getAlgorithm());
            if (!Strings.hasText(alg)) {
                throw new UnsupportedJwtException("JWS header algorithm cannot be null or empty.");
            }

            List<Jwk<?>> candidates;
            if (Strings.hasText(kid)) {
                candidates = this.byKid.get(kid);
                if (Collections.isEmpty(candidates)) {
                    candidates = this.byLowerKid.get(kid.toLowerCase(Locale.ENGLISH));
                }
            } else {
                candidates = this.all;
            }

            if (Collections.isEmpty(candidates)) {
                throw missing(kid, alg);
            }

            List<Jwk<?>> usable = new ArrayList<>();
            for (Jwk<?> candidate : candidates) {
                if (usable(candidate, alg)) {
                    usable.add(candidate);
                }
            }
            if (Collections.isEmpty(usable)) {
                throw missing(kid, alg);
            }

            if (usable.size() > 1) {
                // Two JWKs may represent the same key material. Treat those as one selectable key, but never
                // guess between different keys for the same header identity.
                List<Jwk<?>> distinct = new ArrayList<>();
                Set<String> fingerprints = new HashSet<>();
                for (Jwk<?> candidate : usable) {
                    String fingerprint = candidate.thumbprint().toString();
                    if (fingerprints.add(fingerprint)) {
                        distinct.add(candidate);
                    }
                }
                if (distinct.size() > 1) {
                    throw ambiguous(kid, alg);
                }
                usable = distinct;
            }

            Jwk<?> selected = select(usable);
            return new DefaultKeySelection(header, alg, selected, selected.toKey(), this.id);
        }

        private Jwk<?> select(List<Jwk<?>> candidates) {
            for (Jwk<?> candidate : candidates) {
                if (this.preferredFingerprints.contains(candidate.thumbprint().toString())) {
                    return candidate;
                }
            }
            // JWK Sets preserve insertion order, so the last key is the newest entry when a rotation keeps both keys.
            return candidates.get(candidates.size() - 1);
        }

        private UnsupportedJwtException missing(String kid, String alg) {
            String id = Strings.hasText(kid) ? "kid '" + kid + "'" : "a missing 'kid' (Key ID) value";
            String msg = "Unable to locate a unique JWS verification key for " + id + " and algorithm '" + alg +
                    "' in JWK Set generation " + this.id + ".";
            return new UnsupportedJwtException(msg);
        }

        private UnsupportedJwtException ambiguous(String kid, String alg) {
            String id = Strings.hasText(kid) ? "kid '" + kid + "'" : "a missing 'kid' (Key ID) value";
            String msg = "Unable to select a unique JWS verification key for " + id + " and algorithm '" + alg +
                    "' in JWK Set generation " + this.id + ": multiple distinct keys match the JWS header.";
            return new UnsupportedJwtException(msg);
        }

        private static boolean usable(Jwk<?> jwk, String alg) {
            Key key;
            try {
                key = jwk.toKey();
            } catch (RuntimeException e) {
                return false;
            }
            if (key == null || key instanceof PrivateKey) {
                return false;
            }
            if (!(key instanceof PublicKey) && !(key instanceof SecretKey)) {
                return false;
            }

            String jwkAlg = Strings.clean(jwk.getAlgorithm());
            if (Strings.hasText(jwkAlg) && !jwkAlg.equals(alg) && !jwkAlg.equalsIgnoreCase(alg)) {
                return false;
            }

            if (jwk instanceof AsymmetricJwk) {
                String use = Strings.clean(((AsymmetricJwk<?>) jwk).getPublicKeyUse());
                if (Strings.hasText(use) && !"sig".equals(use)) {
                    return false;
                }
            }

            Set<KeyOperation> operations = jwk.getOperations();
            if (!Collections.isEmpty(operations) && !containsVerify(operations)) {
                return false;
            }

            return supports(alg, key);
        }

        private static boolean containsVerify(Set<KeyOperation> operations) {
            for (KeyOperation operation : operations) {
                if (operation != null && "verify".equals(operation.getId())) {
                    return true;
                }
            }
            return false;
        }

        private static boolean supports(String alg, Key key) {
            if (alg.startsWith("HS")) {
                return key instanceof SecretKey;
            }
            if (alg.startsWith("RS") || alg.startsWith("PS")) {
                return key instanceof RSAPublicKey;
            }
            if (alg.startsWith("ES")) {
                return key instanceof ECPublicKey;
            }
            if (alg.startsWith("Ed")) {
                EdwardsCurve curve = EdwardsCurve.findByKey(key);
                return key instanceof PublicKey && curve != null && curve.isSignatureCurve();
            }
            return true;
        }

        private static String keyId(Header header) {
            if (header instanceof ProtectedHeader) {
                return ((ProtectedHeader) header).getKeyId();
            }
            Object kid = header.get("kid");
            return kid != null ? kid.toString() : null;
        }
    }
}
