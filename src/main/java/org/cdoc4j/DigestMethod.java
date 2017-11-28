/**
 * Copyright (c) 2017 Martin Paljak
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.cdoc4j;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

public enum DigestMethod {
    SHA_256("http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256"),
    SHA_384("http://www.w3.org/2001/04/xmlenc#sha384", "SHA-384"),
    SHA_512("http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512");


    private final String uri;
    private final String name;


    DigestMethod(String uri, String name) {
        this.uri = uri;
        this.name = name;
    }

    public static DigestMethod fromURI(String uri) {
        for (DigestMethod e : values()) {
            if (e.uri.equals(uri))
                return e;
        }
        return null;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getAlgorithmURI() {
        return uri;
    }

    public Digest getDigest() {
        switch (this) {
            case SHA_256:
                return new SHA256Digest();
            case SHA_512:
                return new SHA512Digest();
            case SHA_384:
                return new SHA384Digest();
            default:
                throw new IllegalStateException("Unknown digest");
        }
    }
}