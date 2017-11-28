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

public enum EncryptionMethod {
    AES128_CBC("http://www.w3.org/2001/04/xmlenc#aes128-cbc", "AES-128 CBC", "AES/CBC/NoPadding"),
    AES256_GCM("http://www.w3.org/2009/xmlenc11#aes256-gcm", "AES-256 GCM", "AES/GCM/NoPadding");

    private final String uri;
    private final String name;
    private final String cipher;


    EncryptionMethod(String uri, String name, String cipher) {
        this.uri = uri;
        this.name = name;
        this.cipher = cipher;
    }

    public static EncryptionMethod fromURI(String uri) {
        for (EncryptionMethod e : values()) {
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

    public String getCipherName() {
        return cipher;
    }

    public int getKeyLength() {
        switch (this) {
            case AES128_CBC:
                return 16;
            case AES256_GCM:
                return 32;
            default:
                throw new IllegalStateException("Unknown EncryptionMethod");
        }
    }
}