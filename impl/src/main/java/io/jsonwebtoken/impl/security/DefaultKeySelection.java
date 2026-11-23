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
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.KeySelection;

import java.security.Key;

public class DefaultKeySelection implements KeySelection {

    private final Header header;
    private final String algorithm;
    private final Jwk<?> jwk;
    private final Key key;
    private final String fingerprint;
    private final long generation;

    public DefaultKeySelection(Header header, String algorithm, Jwk<?> jwk, Key key, long generation) {
        this(header, algorithm, jwk, key,
                jwk != null ? jwk.thumbprint().toString() : KeyFingerprints.compute(key), generation);
    }

    DefaultKeySelection(Header header, String algorithm, Jwk<?> jwk, Key key, String fingerprint, long generation) {
        this.header = Assert.notNull(header, "Header cannot be null.");
        this.algorithm = Assert.hasText(algorithm, "Algorithm cannot be null or empty.");
        this.jwk = jwk;
        this.key = Assert.notNull(key, "Key cannot be null.");
        this.fingerprint = Assert.hasText(fingerprint, "Fingerprint cannot be null or empty.");
        this.generation = generation;
    }

    @Override
    public Header getHeader() {
        return this.header;
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public String getKeyId() {
        if (this.jwk != null) {
            String id = Strings.clean(this.jwk.getId());
            if (Strings.hasText(id)) {
                return id;
            }
        }
        return keyId(this.header);
    }

    @Override
    public Jwk<?> getJwk() {
        return this.jwk;
    }

    @Override
    public Key getKey() {
        return this.key;
    }

    @Override
    public String getFingerprint() {
        return this.fingerprint;
    }

    @Override
    public long getGeneration() {
        return this.generation;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof DefaultKeySelection)) {
            return false;
        }
        DefaultKeySelection other = (DefaultKeySelection) obj;
        return this.generation == other.generation &&
                Objects.nullSafeEquals(this.header, other.header) &&
                Objects.nullSafeEquals(this.algorithm, other.algorithm) &&
                Objects.nullSafeEquals(this.jwk, other.jwk) &&
                Objects.nullSafeEquals(this.key, other.key) &&
                Objects.nullSafeEquals(this.fingerprint, other.fingerprint);
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(new Object[]{this.header, this.algorithm, this.jwk, this.key,
                this.fingerprint, this.generation});
    }

    @Override
    public String toString() {
        return "kid=" + getKeyId() + ",alg=" + this.algorithm + ",fingerprint=" + this.fingerprint +
                ",generation=" + this.generation;
    }

    private static String keyId(Header header) {
        if (header instanceof ProtectedHeader) {
            return ((ProtectedHeader) header).getKeyId();
        }
        Object kid = header.get("kid");
        return kid != null ? kid.toString() : null;
    }
}
