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
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.io.Streams;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;

import java.io.InputStream;
import java.io.OutputStream;

class Payload {

    static final Payload EMPTY = new Payload(Bytes.EMPTY, null);

    private final CharSequence string;
    private final byte[] bytes;
    private final Claims claims;
    private final InputStream inputStream;
    private final boolean inputStreamEmpty;
    private final String contentType;
    private CompressionAlgorithm zip;
    private boolean claimsExpected;
    /**
     * {@code true} once the payload's backing {@link InputStream} has been consumed within a single read
     * transaction and its exact bytes captured in {@link #bytes}.  After materialization, the stream is never
     * read again, so short reads, repeat reads or concurrent appends cannot substitute a different sequence
     * of bytes for the one associated with this payload (required for RFC 7797 {@code b64=false} JWSs).
     */
    private final boolean materialized;

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
        this(claims, string, bytes, inputStream, contentType, false);
    }

    private Payload(Claims claims, CharSequence string, byte[] bytes, InputStream inputStream, String contentType,
                    boolean materialized) {
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
        this.materialized = materialized;
    }

    /**
     * Returns {@code true} if this payload's exact bytes have already been captured during a single bounded
     * read transaction and must not be read from any (potentially re-readable or mutable) stream again.
     *
     * @return {@code true} if the payload bytes are already authoritative and fully held in memory.
     */
    boolean isMaterialized() {
        return this.materialized;
    }

    /**
     * Reads the payload's raw content exactly once within a single bounded transaction and returns a new
     * {@code Payload} whose signature input, detached representation and eventual JWS/claims consumer all
     * share the same immutable byte array.  The originating {@link InputStream} is never consulted again,
     * eliminating short-read, repeat-read and trailing-append ambiguity for RFC 7797 {@code b64=false} JWSs.
     *
     * @param name descriptive name used in any I/O failure message.
     * @return a materialized payload backed solely by the bytes read during this transaction.
     */
    Payload materialize(String name) {
        if (isMaterialized() || isClaims()) return this;
        byte[] data = this.bytes;
        if (isEmpty() || Bytes.isEmpty(data)) {
            InputStream in = toInputStream();
            data = Streams.bytes(in, "Unable to read " + name + " bytes.");
        }
        Payload payload = new Payload(this.claims, this.string, data, null, getContentType(), true);
        payload.setZip(this.zip);
        payload.setClaimsExpected(this.claimsExpected);
        return payload;
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

    /**
     * Returns {@code true} if the payload may be fully consumed and retained in memory, {@code false} if empty,
     * already extracted, or a potentially too-large InputStream.
     *
     * @return {@code true} if the payload may be fully consumed and retained in memory, {@code false} if empty,
     * already extracted, or a potentially too-large InputStream.
     */
    boolean isConsumable() {
        return !isClaims() && (isString() || !Bytes.isEmpty(this.bytes) || (inputStream != null && claimsExpected));
    }

    boolean isEmpty() {
        return !isClaims() && !isString() && Bytes.isEmpty(this.bytes) && this.inputStreamEmpty;
    }

    public OutputStream compress(OutputStream out) {
        return this.zip != null ? zip.compress(out) : out;
    }

    public Payload decompress(CompressionAlgorithm alg) {
        Assert.notNull(alg, "CompressionAlgorithm cannot be null.");
        Payload payload = this;
        if (!isString() && isConsumable()) {
            if (alg.equals(Jwts.ZIP.DEF) && !Bytes.isEmpty(this.bytes)) { // backwards compatibility
                byte[] data = ((CompressionCodec) alg).decompress(this.bytes);
                payload = new Payload(claims, string, data, null, getContentType());
            } else {
                InputStream in = toInputStream();
                in = alg.decompress(in);
                payload = new Payload(claims, string, bytes, in, getContentType());
            }
            payload.setClaimsExpected(claimsExpected);
        }
        // otherwise it's a String or b64/detached payload, in either case, we don't decompress since the caller is
        // providing the bytes necessary for signature verification as-is, and there's no conversion we need to perform
        return payload;
    }

    public byte[] getBytes() {
        return this.bytes;
    }

    InputStream toInputStream() {
        // should only ever call this when claims don't exist:
        Assert.state(!isClaims(), "Claims exist, cannot convert to InputStream directly.");
        return this.inputStream;
    }
}
