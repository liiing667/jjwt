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
package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.lang.Assert;

import java.io.ByteArrayOutputStream;

/**
 * A {@link ByteArrayOutputStream} that fails closed instead of retaining more than a fixed number of bytes.  It is
 * used by decompression paths that must materialize their result in a byte array (for example, the legacy DEFLATE
 * compatibility path).
 *
 * @since 0.14.0
 */
public final class LimitedByteArrayOutputStream extends ByteArrayOutputStream {

    private final long limit;
    private final String algorithmId;

    public LimitedByteArrayOutputStream(int initialSize, long limit, String algorithmId) {
        super(initialSize);
        Assert.isTrue(limit >= 0, "limit cannot be negative.");
        this.limit = limit;
        this.algorithmId = algorithmId;
    }

    private void check(long len) {
        if ((long) this.count + len > this.limit) {
            throw Streams.decompressionLimitExceeded(this.algorithmId, this.limit);
        }
    }

    @Override
    public synchronized void write(int b) {
        check(1);
        super.write(b);
    }

    @Override
    public synchronized void write(byte[] b, int off, int len) {
        check(len);
        super.write(b, off, len);
    }

    @Override
    public synchronized void write(byte[] b) {
        check(b.length);
        super.write(b, 0, b.length);
    }
}
