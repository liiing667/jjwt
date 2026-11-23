/*
 * Copyright (C) 2014 jsonwebtoken.io
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

import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtVisitor;
import io.jsonwebtoken.lang.Assert;

public class DefaultJws<P> extends DefaultProtectedJwt<JwsHeader, P> implements Jws<P> {

    private static final String DIGEST_NAME = "signature";

    private final String signature;

    public DefaultJws(JwsHeader header, P payload, byte[] signature, String b64UrlSig) {
        super(snapshot(header), payload, copy(signature), DIGEST_NAME);
        this.signature = Assert.hasText(b64UrlSig, "JWS signature cannot be null or empty.");
    }

    private static JwsHeader snapshot(JwsHeader header) {
        Assert.notNull(header, "header cannot be null.");
        // DefaultJwsHeader is immutable.  Other JwsHeader implementations may be backed by mutable builders, so
        // retain an immutable copy to prevent a later mutation from changing an already-returned JWS.
        return header instanceof DefaultJwsHeader ? header : new DefaultJwsHeader(header);
    }

    private static byte[] copy(byte[] signature) {
        return Assert.notEmpty(signature, "Signature byte array cannot be null or empty.").clone();
    }

    @Override
    public String getSignature() {
        return this.signature;
    }

    @Override
    public <T> T accept(JwtVisitor<T> v) {
        return v.visit(this);
    }
}
