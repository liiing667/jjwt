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

import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

final class KeyFingerprints {

    private static final String ALGORITHM = "SHA-256";

    private KeyFingerprints() {
    }

    static String compute(Key key) {
        Assert.notNull(key, "Key cannot be null.");
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            String identity = key.getClass().getName() + ":" + key.getAlgorithm();
            encoded = identity.getBytes(StandardCharsets.UTF_8);
        }
        try {
            byte[] digest = MessageDigest.getInstance(ALGORITHM).digest(encoded);
            return Encoders.BASE64URL.encode(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM does not support the required " + ALGORITHM + " digest.", e);
        }
    }
}
