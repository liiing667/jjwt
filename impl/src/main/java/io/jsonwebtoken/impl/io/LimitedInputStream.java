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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * An {@link InputStream} that fails closed once a fixed number of decompressed bytes have been read.  The limit is
 * cumulative for the life of the stream: rewinding or re-reading data cannot reset the budget, and the stream never
 * exposes bytes beyond the configured limit.
 *
 * @since 0.14.0
 */
public final class LimitedInputStream extends FilterInputStream {

    private final long limit;
    private final String algorithmId;
    private long count;

    public LimitedInputStream(InputStream in, long limit, String algorithmId) {
        super(Assert.notNull(in, "InputStream cannot be null."));
        Assert.isTrue(limit >= 0, "limit cannot be negative.");
        this.limit = limit;
        this.algorithmId = algorithmId;
    }

    public long getLimit() {
        return this.limit;
    }

    public long getCount() {
        return this.count;
    }

    public String getAlgorithmId() {
        return this.algorithmId;
    }

    private void add(long n) {
        if (n <= 0) return;
        long next = this.count + n;
        if (next > this.limit) {
            this.count = next;
            throw Streams.decompressionLimitExceeded(this.algorithmId, this.limit);
        }
        this.count = next;
    }

    @Override
    public int read() throws IOException {
        int b = super.read();
        if (b != Streams.EOF) add(1);
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (len == 0) return 0;
        long remaining = this.limit - this.count;
        if (remaining < 0) {
            throw Streams.decompressionLimitExceeded(this.algorithmId, this.limit);
        }
        // Read at most one byte beyond the budget so we can distinguish an exact-size payload from an over-limit one:
        long max = remaining < (long) len ? remaining + 1 : (long) len;
        int n = super.read(b, off, (int) max);
        if (n > 0) {
            add(n);
        }
        return n;
    }

    @Override
    public long skip(long n) throws IOException {
        if (n <= 0) return 0;
        long remaining = this.limit - this.count;
        if (remaining < 0) {
            throw Streams.decompressionLimitExceeded(this.algorithmId, this.limit);
        }
        long max = remaining < n ? remaining + 1 : n;
        long skipped = super.skip(max);
        if (skipped > 0) {
            add(skipped);
        }
        return skipped;
    }
}
