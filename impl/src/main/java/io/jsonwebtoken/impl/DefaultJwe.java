/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwtVisitor;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;

import java.security.MessageDigest;

public class DefaultJwe<P> extends DefaultProtectedJwt<JweHeader, P> implements Jwe<P> {

    private static final String DIGEST_NAME = "tag";

    private final byte[] iv;

    public DefaultJwe(JweHeader header, P payload, byte[] iv, byte[] aadTag) {
        super(snapshot(header), payload, copy(aadTag, "Digest byte array cannot be null or empty."), DIGEST_NAME);
        this.iv = copy(iv, "Initialization vector cannot be null or empty.");
    }

    private static JweHeader snapshot(JweHeader header) {
        Assert.notNull(header, "header cannot be null.");
        // DefaultJweHeader is immutable.  Other JweHeader implementations may be backed by mutable builders, so
        // retain an immutable copy to prevent a later mutation from changing an already-returned JWE.
        return header instanceof DefaultJweHeader ? header : new DefaultJweHeader(header);
    }

    private static byte[] copy(byte[] value, String message) {
        return Assert.notEmpty(value, message).clone();
    }

    @Override
    public byte[] getInitializationVector() {
        return this.iv.clone();
    }

    @Override
    protected StringBuilder toStringBuilder() {
        return super.toStringBuilder().append(",iv=").append(Encoders.BASE64URL.encode(this.iv));
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof Jwe) {
            Jwe<?> jwe = (Jwe<?>) obj;
            return super.equals(jwe) && MessageDigest.isEqual(this.iv, jwe.getInitializationVector());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(getHeader(), getPayload(), this.iv, this.digest);
    }

    @Override
    public <T> T accept(JwtVisitor<T> v) {
        return v.visit(this);
    }
}
