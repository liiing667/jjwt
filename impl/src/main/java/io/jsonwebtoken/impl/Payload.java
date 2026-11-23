/*
 * Copyright © 2023 jsonwebtoken.io
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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.CompressionException;
import io.jsonwebtoken.impl.compression.DeflateCompressionAlgorithm;
import io.jsonwebtoken.impl.io.Streams;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

class Payload {

    static final Payload EMPTY = new Payload(Bytes.EMPTY, null);

    private CharSequence string;
    private byte[] bytes;
    private final Claims claims;
    private InputStream inputStream;
    private boolean inputStreamEmpty;
    private final String contentType;
    private CompressionAlgorithm zip;
    private boolean claimsExpected;

    /**
     * {@code true} once decompression (or the decision that decompression is not applicable) has been committed for
     * this payload.  The decoded bytes and failure state below are the authoritative result for every consumer of this
     * same {@code Payload} instance.
     */
    private boolean decompressed;
    private byte[] decompressedBytes = Bytes.EMPTY;
    private CompressionAlgorithm decompressionAlgorithm;
    private CompressionException decompressionFailure;

    Payload(Claims claims) {
        this(claims, null, null, null, null);
    }

    Payload(CharSequence content, String contentType) {
        this(null, content, null, null, contentType);
    }

    Payload(byte[] content, String contentType) {
        this(null, null, content, null, contentType);
    }

    Payload(InputStream inputStream, String contentType) {
        this(null, null, null, inputStream, contentType);
    }

    private Payload(Claims claims, CharSequence string, byte[] bytes, InputStream inputStream, String contentType) {
        this.claims = claims;
        this.string = Strings.clean(string);
        this.contentType = Strings.clean(contentType);
        InputStream in = inputStream;
        byte[] data = Bytes.nullSafe(bytes);
        if (Strings.hasText(this.string)) {
            data = Strings.utf8(this.string);
        }
        this.bytes = data;
        if (in == null && !Bytes.isEmpty(this.bytes)) {
            in = Streams.of(data);
        }
        this.inputStreamEmpty = in == null;
        this.inputStream = this.inputStreamEmpty ? Streams.of(Bytes.EMPTY) : in;
    }

    boolean isClaims() {
        return !Collections.isEmpty(this.claims);
    }

    Claims getRequiredClaims() {
        return Assert.notEmpty(this.claims, "Claims cannot be null or empty when calling this method.");
    }

    boolean isString() {
        return Strings.hasText(this.string);
    }

    String getContentType() {
        return this.contentType;
    }

    public void setZip(CompressionAlgorithm zip) {
        this.zip = zip;
    }

    boolean isCompressed() {
        return this.zip != null;
    }

    public void setClaimsExpected(boolean claimsExpected) {
        this.claimsExpected = claimsExpected;
    }

    private void assertDecompressionSucceeded() {
        if (this.decompressionFailure != null) {
            throw this.decompressionFailure;
        }
    }

    /**
     * Replaces this payload's source bytes after decryption while retaining the same payload identity.  All subsequent
     * decompression, verification and consumer operations observe this exact object and its new content.
     *
     * @param content the decrypted JWE plaintext (still compressed if a {@code zip} header is present)
     * @return this payload
     */
    Payload replaceContent(byte[] content) {
        Assert.state(!isClaims(), "Claims payloads cannot be replaced.");
        this.string = null;
        this.bytes = Bytes.nullSafe(content);
        this.inputStreamEmpty = Bytes.isEmpty(this.bytes);
        this.inputStream = this.inputStreamEmpty ? Streams.of(Bytes.EMPTY) : Streams.of(this.bytes);
        this.decompressed = false;
        this.decompressedBytes = Bytes.EMPTY;
        this.decompressionAlgorithm = null;
        this.decompressionFailure = null;
        return this;
    }

    /**
     * Returns {@code true} if the payload may be fully consumed and retained in memory, {@code false} if empty,
     * already extracted, or a potentially too-large InputStream.
     *
     * @return {@code true} if the payload may be fully consumed and retained in memory, {@code false} if empty,
     * already extracted, or a potentially too-large InputStream.
     */
    boolean isConsumable() {
        assertDecompressionSucceeded();
        if (isClaims()) return false;
        if (isString()) return true;
        if (this.decompressed) {
            return !Bytes.isEmpty(this.decompressedBytes) || this.claimsExpected;
        }
        return !Bytes.isEmpty(this.bytes) || this.claimsExpected;
    }

    boolean isEmpty() {
        assertDecompressionSucceeded();
        if (isClaims() || isString()) return false;
        if (this.decompressed) {
            return Bytes.isEmpty(this.decompressedBytes);
        }
        return Bytes.isEmpty(this.bytes) && this.inputStreamEmpty;
    }

    public OutputStream compress(OutputStream out) {
        assertDecompressionSucceeded();
        return this.zip != null ? zip.compress(out) : out;
    }

    public Payload decompress(CompressionAlgorithm alg) {
        Assert.notNull(alg, "CompressionAlgorithm cannot be null.");
        if (this == EMPTY) {
            return this;
        }
        assertDecompressionSucceeded();
        if (this.decompressed) {
            if (this.decompressionAlgorithm != null && !sameAlgorithm(this.decompressionAlgorithm, alg)) {
                String msg = "Payload was already decompressed with algorithm '" +
                        this.decompressionAlgorithm.getId() + "'.";
                throw new IllegalStateException(msg);
            }
            return this;
        }
        this.decompressionAlgorithm = alg;
        boolean decompressedContent = !isString() && isConsumable();
        if (decompressedContent) {
            try {
                byte[] data;
                if (isLegacyDeflate(alg) && !Bytes.isEmpty(this.bytes)) { // backwards compatibility
                    data = ((CompressionCodec) alg).decompress(this.bytes);
                } else {
                    data = readDecompressed(alg);
                }
                if ((long) Bytes.length(data) > Streams.MAX_DECOMPRESSED_PAYLOAD_SIZE) {
                    throw Streams.decompressionLimitExceeded(alg.getId(),
                            Streams.MAX_DECOMPRESSED_PAYLOAD_SIZE);
                }
                this.decompressedBytes = Bytes.nullSafe(data);
            } catch (RuntimeException e) {
                CompressionException failure = decompressionFailure(alg, e);
                this.decompressionFailure = failure;
                throw failure;
            }
            this.decompressed = true;
        } else {
            this.decompressedBytes = Bytes.nullSafe(this.bytes);
            // A non-empty InputStream payload that cannot be safely materialized (for example a b64=false content
            // payload) remains untouched, matching its original streaming behavior:
            this.decompressed = !(Bytes.isEmpty(this.bytes) && !this.inputStreamEmpty);
        }
        // otherwise it's a String or b64/detached payload, in either case, we don't decompress since the caller is
        // providing the bytes necessary for signature verification as-is, and there's no conversion we need to perform
        return this;
    }

    private static boolean isLegacyDeflate(CompressionAlgorithm alg) {
        return alg instanceof CompressionCodec && alg.getClass() == DeflateCompressionAlgorithm.class;
    }

    private static boolean sameAlgorithm(CompressionAlgorithm a, CompressionAlgorithm b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        String aid = a.getId();
        return aid != null && aid.equals(b.getId());
    }

    private static CompressionException decompressionFailure(CompressionAlgorithm alg, RuntimeException cause) {
        String id = alg != null ? alg.getId() : null;
        String prefix = "Decompression failed for algorithm '" + (id != null ? id : "unknown") + "': ";
        if (cause instanceof CompressionException) {
            String msg = cause.getMessage();
            if (msg != null && msg.startsWith(prefix)) {
                return (CompressionException) cause;
            }
        }
        String msg = cause != null ? cause.getMessage() : null;
        if (!Strings.hasText(msg)) {
            msg = cause != null ? cause.getClass().getSimpleName() : "unknown decompression failure";
        }
        return new CompressionException(prefix + msg, cause);
    }

    private byte[] readDecompressed(CompressionAlgorithm alg) {
        InputStream in = null;
        try {
            in = alg.decompress(toInputStream());
            if (in == null) {
                String msg = "Decompression failed for algorithm '" + alg.getId() + "': null decompressed stream.";
                throw new CompressionException(msg);
            }
            in = Streams.limit(in, alg.getId());
            // Materialize the complete result here, before claims/content consumers run.  If this were left lazy, a
            // decompression read/limit failure could be caught and mistaken for malformed JSON, after which the
            // consumer might fall back to a partially-read stream.  Capturing the bytes up front makes the success or
            // failure result atomic for this payload identity.
            ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != Streams.EOF) {
                if (read > 0) {
                    out.write(buffer, 0, read);
                } else {
                    int b = in.read();
                    if (b == Streams.EOF) break;
                    out.write(b);
                }
            }
            return out.toByteArray();
        } catch (java.io.IOException e) {
            String msg = "Decompression failed for algorithm '" + alg.getId() +
                    "': unable to read decompressed payload.";
            throw new CompressionException(msg, e);
        } finally {
            try {
                Objects.nullSafeClose(in);
            } catch (RuntimeException ignored) {
                // Never let a close failure mask the decompression failure or the successfully captured bytes.
            }
        }
    }

    public byte[] getBytes() {
        assertDecompressionSucceeded();
        return this.decompressed ? this.decompressedBytes : this.bytes;
    }

    InputStream toInputStream() {
        // should only ever call this when claims don't exist:
        Assert.state(!isClaims(), "Claims exist, cannot convert to InputStream directly.");
        assertDecompressionSucceeded();
        if (this.decompressed) {
            return Streams.of(this.decompressedBytes);
        }
        return this.inputStream;
    }
}
