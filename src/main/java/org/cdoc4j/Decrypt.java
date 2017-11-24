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

import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.KDFParameters;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;

public final class Decrypt {

    public static SecretKey getKey(KeyPair kp, Recipient r) throws GeneralSecurityException {
        return getKey(kp.getPrivate(), r);
    }

    public static SecretKey getKey(PrivateKey k, Recipient r) throws GeneralSecurityException {
        if (r.getType() == Recipient.TYPE.ECC && k.getAlgorithm().startsWith("EC")) {
            return getKey(k, (Recipient.ECDHESRecipient) r);
        } else if (r.getType() == Recipient.TYPE.RSA && k.getAlgorithm().equals("RSA")) {
            return getKey(k, (Recipient.RSARecipient) r);
        } else {
            throw new IllegalArgumentException("Unknown algorithm combination");
        }
    }

    public static SecretKey getKey(PrivateKey k, Recipient.ECDHESRecipient r) throws GeneralSecurityException {
        // Derive shared secred
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(k);
        ka.doPhase(r.getSenderPublicKey(), true);
        return getKey(ka.generateSecret(), r);
    }

    // Assumes AES-256
    public static SecretKey getKey(final byte[] shared_secret, Recipient.ECDHESRecipient r) throws GeneralSecurityException {
        // Derive unwrap key with KDF
        ConcatenationKDFGenerator ckdf = new ConcatenationKDFGenerator(new SHA384Digest()); // FIXME: parametrize
        ckdf.init(new KDFParameters(shared_secret, Legacy.concatenate(r.getAlgorithmID(), r.getPartyUInfo(), r.getPartyVInfo())));
        byte[] wrapkeybytes = new byte[32];
        ckdf.generateBytes(wrapkeybytes, 0, 32);
        SecretKeySpec wrapKey = new SecretKeySpec(wrapkeybytes, "AES");

        // Unwrap dek
        Cipher cipher = Cipher.getInstance("AESWrap");
        cipher.init(Cipher.UNWRAP_MODE, wrapKey);
        return (SecretKey) cipher.unwrap(r.getCryptogram(), "AES", Cipher.SECRET_KEY);
    }

    public static SecretKey getKey(PrivateKey k, Recipient.RSARecipient r) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, k);
        SecretKey dek = new SecretKeySpec(c.doFinal(r.getCryptogram()), "AES");
        return dek;
    }
}
