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

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

public abstract class Recipient {
    private String name;
    private X509Certificate certificate;
    private byte[] cryptogram;

    protected Recipient() {
    }

    protected Recipient(X509Certificate cert, String name, byte[] cryptogram) {
        this.certificate = cert;
        this.name = name;
        this.cryptogram = Arrays.copyOf(cryptogram, cryptogram.length);
    }

    public abstract TYPE getType();

    public byte[] getCryptogram() {
        return Arrays.copyOf(cryptogram, cryptogram.length);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate cert) {
        this.certificate = cert;
    }

    public enum TYPE {
        RSA, EC
    }

    public final static class ECDHESRecipient extends Recipient {
        private final ECPublicKey pubkey; // Ephemeral key
        private final byte[] algorithmID;
        private final byte[] partyUInfo;
        private final byte[] partyVInfo;

        public ECDHESRecipient(X509Certificate cert, String name, ECPublicKey pubkey, byte[] cgram, byte[] algoid, byte[] partyu, byte[] partyv) {
            super(cert, name, cgram);
            this.pubkey = pubkey;
            this.algorithmID = Arrays.copyOf(algoid, algoid.length);;
            this.partyUInfo = Arrays.copyOf(partyu, partyu.length);;
            this.partyVInfo = Arrays.copyOf(partyv, partyv.length);;
        }

        public ECPublicKey getSenderPublicKey() {
            return pubkey;
        }

        public byte[] getAlgorithmID() {
            return Arrays.copyOf(algorithmID, algorithmID.length);
        }

        public byte[] getPartyUInfo() {
            return Arrays.copyOf(partyUInfo, partyUInfo.length);
        }

        public byte[] getPartyVInfo() {
            return Arrays.copyOf(partyVInfo, partyVInfo.length);
        }

        @Override
        public TYPE getType() {
            return TYPE.EC;
        }
    }

    public final static class RSARecipient extends Recipient {

        public RSARecipient(X509Certificate cert, String name, byte[] cgram) {
            super(cert, name, cgram);
        }

        @Override
        public TYPE getType() {
            return TYPE.RSA;
        }
    }
}
