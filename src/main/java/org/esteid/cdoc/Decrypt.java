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
package org.esteid.cdoc;

import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.KDFParameters;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

public class Decrypt {
    public static final SecretKey getKey(KeyPair kp, Recipient r) throws GeneralSecurityException {
        if (r.getType() == Recipient.TYPE.ECC && kp.getPublic().getAlgorithm().startsWith("EC")) {
            return getKey(kp, (Recipient.ECDHESRecipient) r);
        } else if (r.getType() == Recipient.TYPE.RSA && kp.getPublic().getAlgorithm().equals("RSA")) {
            return getKey(kp, (Recipient.RSARecipient) r);
        } else {
            throw new IllegalArgumentException("Unknown algorithm combination");
        }
    }

    public static final SecretKey getKey(KeyPair kp, Recipient.ECDHESRecipient r) throws GeneralSecurityException {
        // Derive shared secred
        KeyAgreement key_agreement = KeyAgreement.getInstance("ECDH");
        key_agreement.init(kp.getPrivate());
        key_agreement.doPhase(r.getPublicKey(), true);
        byte[] sharedSecret = key_agreement.generateSecret();

        // Derive key unwrap key with KDF
        ConcatenationKDFGenerator ckdf = new ConcatenationKDFGenerator(new SHA256Digest());
        ckdf.init(new KDFParameters(sharedSecret, Legacy.concatenate(r.getAlgorithmID(), r.getPartyUInfo(), r.getPartyVInfo())));
        byte[] wrapkeybytes = new byte[32];
        ckdf.generateBytes(wrapkeybytes, 0, 32);
        SecretKeySpec wrapKey = new SecretKeySpec(wrapkeybytes, "AES");

        // Unwrap dek
        Cipher cipher = Cipher.getInstance("AESWrap");
        cipher.init(Cipher.UNWRAP_MODE, wrapKey);
        SecretKey dek = (SecretKey) cipher.unwrap(r.getCryptogram(), "AES", Cipher.SECRET_KEY);
        return dek;
    }

    public static final SecretKey getKey(KeyPair kp, Recipient.RSARecipient r) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        SecretKey dek = new SecretKeySpec(c.doFinal(r.getCryptogram()), "AES");
        return dek;
    }
}