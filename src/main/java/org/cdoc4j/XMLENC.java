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

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

// Construct XML-ENC structure
final class XMLENC {
    final static String ALGORITHM = "Algorithm";

    // Returns elements to be added to the CDOC XML, based on recipient type
    private static Element toRecipient(Document cdoc, CDOC.Version v, String name, X509Certificate cert, SecretKey dek, boolean includecert) throws GeneralSecurityException {
        if (cert.getPublicKey() instanceof ECPublicKey) {
            return toECRecipient(cdoc, v, name, cert, dek, includecert, DigestMethod.SHA_384);
        } else if (cert.getPublicKey() instanceof RSAPublicKey) {
            return toRSARecipient(cdoc, v, name, cert, dek, includecert);
        } else {
            throw new IllegalArgumentException("Unknown public key algorithm: " + cert.getPublicKey().getAlgorithm());
        }
    }

    private static Element toRSARecipient(Document cdoc, CDOC.Version v, String name, X509Certificate cert, SecretKey dek, boolean includecert) throws GeneralSecurityException {
        Element enckey = cdoc.createElement("xenc:EncryptedKey");
        enckey.setAttribute("Recipient", name);

        // Encryption method for transport key - currently fixed ;(
        Element kekmethod = cdoc.createElement("xenc:EncryptionMethod");
        kekmethod.setAttribute(ALGORITHM, "http://www.w3.org/2001/04/xmlenc#rsa-1_5");
        enckey.appendChild(kekmethod);

        if (!includecert) {
            // Certificate itself
            Element kinfo = cdoc.createElement("ds:KeyInfo");
            Element x509data = cdoc.createElement("ds:X509Data");
            kinfo.appendChild(x509data);
            Element x509cert = cdoc.createElement("ds:X509Certificate");
            x509cert.setTextContent(Base64.getEncoder().encodeToString(cert.getEncoded()));
            x509data.appendChild(x509cert);
            enckey.appendChild(kinfo);
        }

        // Add actual encrypted key value
        Element cipherdata = cdoc.createElement("xenc:CipherData");
        Element ciphervalue = cdoc.createElement("xenc:CipherValue");

        // Encrypt the dek for recipient
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        c.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
        ciphervalue.setTextContent(Base64.getEncoder().encodeToString(c.doFinal(dek.getEncoded())));
        cipherdata.appendChild(ciphervalue);
        enckey.appendChild(cipherdata);
        return enckey;
    }

    private static Element toECRecipient(Document cdoc, CDOC.Version v, String name, X509Certificate cert, SecretKey dek, boolean includecert, DigestMethod dm) throws GeneralSecurityException {
        ECPublicKey k = (ECPublicKey) cert.getPublicKey();

        // Generate ephemeral key.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(k.getParams());
        KeyPair keyPair = kpg.generateKeyPair();

        SubjectPublicKeyInfo partyVkey = SubjectPublicKeyInfo.getInstance(k.getEncoded());
        SubjectPublicKeyInfo partyUkey = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        // Construct XML
        Element enckey = cdoc.createElement("xenc:EncryptedKey");
        enckey.setAttribute("Recipient", name);

        // Encryption method for transport key - currently fixed ;(
        Element kekmethod = cdoc.createElement("xenc:EncryptionMethod");
        kekmethod.setAttribute(ALGORITHM, "http://www.w3.org/2001/04/xmlenc#kw-aes256");
        enckey.appendChild(kekmethod);

        // Certificate itself
        Element kinfo = cdoc.createElement("ds:KeyInfo");
        // AgreementMethod
        Element kam = cdoc.createElement("xenc:AgreementMethod");
        kam.setAttribute(ALGORITHM, "http://www.w3.org/2009/xmlenc11#ECDH-ES");
        //
        Element kdm = cdoc.createElement("xenc11:KeyDerivationMethod");
        kdm.setAttribute(ALGORITHM, "http://www.w3.org/2009/xmlenc11#ConcatKDF");


        // String curveName = "urn:oid:" + ASN1ObjectIdentifier.getInstance(subPubKeyInfo.getAlgorithm().getParameters()).toString();
        String curveName = "urn:oid:" + partyVkey.getAlgorithm().getParameters().toString();
        //System.out.println(curveName);

        // CRITICAL
        final byte[] algid;
        final byte[] uinfo;
        final byte[] vinfo;

        // This if assumes that EC is only possible with v11 and v20
        // Formatting conforms to hexBinary with zero padding
        if (v == CDOC.Version.CDOC_V1_1) {
            algid = "ENCDOC-XML|1.1".getBytes(StandardCharsets.US_ASCII);
            uinfo = partyUkey.getPublicKeyData().getBytes();
            vinfo = cert.getEncoded();
        } else if (v == CDOC.Version.CDOC_V2_0) {
            algid = "http://www.w3.org/2001/04/xmlenc#kw-aes256".getBytes(StandardCharsets.US_ASCII);
            uinfo = partyUkey.getPublicKeyData().getBytes();
            vinfo = partyVkey.getPublicKeyData().getBytes();
        } else {
            throw new IllegalStateException("Invalid document version for EC recipient");
        }

        Element ckdfp = cdoc.createElement("xenc11:ConcatKDFParams");
        ckdfp.setAttribute("AlgorithmID", Hex.toHexString(Legacy.concatenate(new byte[]{0x00}, algid)));
        ckdfp.setAttribute("PartyUInfo", Hex.toHexString(Legacy.concatenate(new byte[]{0x00}, uinfo)));
        ckdfp.setAttribute("PartyVInfo", Hex.toHexString(Legacy.concatenate(new byte[]{0x00}, vinfo)));
        Element xdm = cdoc.createElement("ds:DigestMethod");
        xdm.setAttribute(ALGORITHM, dm.getAlgorithmURI());
        ckdfp.appendChild(xdm);
        kdm.appendChild(ckdfp);
        kam.appendChild(kdm);
        // OriginatorKeyInfo
        Element oki = cdoc.createElement("xenc:OriginatorKeyInfo");
        Element kv = cdoc.createElement("ds:KeyValue");
        Element eckv = cdoc.createElement("dsig11:ECKeyValue");
        Element eckvnc = cdoc.createElement("dsig11:NamedCurve");
        eckvnc.setAttribute("URI", curveName);
        eckv.appendChild(eckvnc);
        Element ecpk = cdoc.createElement("dsig11:PublicKey");
        ecpk.setTextContent(Base64.getEncoder().encodeToString(partyUkey.getPublicKeyData().getBytes()));
        eckv.appendChild(ecpk);

        kv.appendChild(eckv);
        oki.appendChild(kv);
        kam.appendChild(oki);

        // RecipientKeyInfo
        if (!includecert) {
            Element rki = cdoc.createElement("xenc:RecipientKeyInfo");
            Element x509data = cdoc.createElement("ds:X509Data");
            kinfo.appendChild(x509data);
            Element x509cert = cdoc.createElement("ds:X509Certificate");
            x509cert.setTextContent(Base64.getEncoder().encodeToString(cert.getEncoded()));
            x509data.appendChild(x509cert);
            rki.appendChild(x509data);
            kam.appendChild(rki);
        }
        kinfo.appendChild(kam);
        enckey.appendChild(kinfo);

        // Shared agreement
        KeyAgreement key_agreement = KeyAgreement.getInstance("ECDH");
        key_agreement.init(keyPair.getPrivate());
        key_agreement.doPhase(cert.getPublicKey(), true);

        // Use the shared secret to wrap the actual key
        byte[] shared_secret = key_agreement.generateSecret();

        // Derive key wrap key with ckdf
        ConcatenationKDFGenerator ckdf = new ConcatenationKDFGenerator(dm.getDigest());
        ckdf.init(new KDFParameters(shared_secret, Legacy.concatenate(algid, uinfo, vinfo)));
        byte[] wrapkeybytes = new byte[32];
        ckdf.generateBytes(wrapkeybytes, 0, 32);

        SecretKeySpec wrapKey = new SecretKeySpec(wrapkeybytes, "AES");
        // Wrap the actual key with the derived key
        // coverity[RISKY_CRYPTO]
        Cipher c = Cipher.getInstance("AESWrap");
        c.init(Cipher.WRAP_MODE, wrapKey);
        byte[] cgram = c.wrap(dek);

        Element cipherdata = cdoc.createElement("xenc:CipherData");
        Element ciphervalue = cdoc.createElement("xenc:CipherValue");

        ciphervalue.setTextContent(Base64.getEncoder().encodeToString(cgram));

        cipherdata.appendChild(ciphervalue);
        enckey.appendChild(cipherdata);
        return enckey;
    }

    static Document makeRecipientsXML(CDOC.Version v, Collection<X509Certificate> recipients, SecretKey dek, boolean privacy) throws GeneralSecurityException {
        // Construct recipients.xml.
        Document cdoc = XML.getDocument();

        Element root = cdoc.createElement("xenc:EncryptedData");
        root.setAttribute("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#");
        root.setAttribute("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#");
        root.setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
        root.setAttribute("xmlns:dsig11", "http://www.w3.org/2009/xmldsig11#");

        if (v == CDOC.Version.CDOC_V1_0 || v == CDOC.Version.CDOC_V1_1) {
            root.setAttribute("MimeType", Legacy.DIGIDOC_XSD);
            root.appendChild(cdoc.createComment(" XXX: this MimeType above is not actually a mime type "));

        } else if (v == CDOC.Version.CDOC_V2_0) {
            root.setAttribute("MimeType", "application/zip");
        }
        cdoc.appendChild(root);

        // Data encryption.
        Element encmethod = cdoc.createElement("xenc:EncryptionMethod");
        if (v == CDOC.Version.CDOC_V1_0) {
            encmethod.setAttribute(ALGORITHM, EncryptionMethod.AES128_CBC.getAlgorithmURI());
        } else {
            encmethod.setAttribute(ALGORITHM, EncryptionMethod.AES256_GCM.getAlgorithmURI());
        }
        root.appendChild(encmethod);

        Element keyinfo = cdoc.createElement("ds:KeyInfo");
        root.appendChild(keyinfo);

        // Handle special case - pre-shared key
        if (v == CDOC.Version.CDOC_V2_0 && recipients.size() == 0) {
            Element keyname = cdoc.createElement("ds:KeyName");
            keyname.setTextContent("Pre-shared key");
            keyinfo.appendChild(keyname);
        } else {
            // One for every recipient, depending on algorithm
            for (X509Certificate crt : recipients) {
                Element enckey = toRecipient(cdoc, v, privacy ? "Undisclosed" : getCN(crt), crt, dek, privacy);
                keyinfo.appendChild(enckey);
            }
        }
        // For XML encapsulation, caller adds children
        return cdoc;
    }

    static ArrayList<Recipient> parseRecipientsXML(Document d) throws IOException, CertificateException {
        ArrayList<Recipient> result = new ArrayList<>();

        try {
            NodeList encryptedKeys = (NodeList) XML.xPath.evaluate("/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey", d, XPathConstants.NODESET);
            for (int i = 0; i < encryptedKeys.getLength(); i++) {
                Node n = encryptedKeys.item(i);
                String name = n.getAttributes().getNamedItem("Recipient").getTextContent();
                String algorithm = XML.xPath.evaluate("xenc:EncryptionMethod/@Algorithm", n);
                X509Certificate cert = null;
                if (algorithm.equals("http://www.w3.org/2001/04/xmlenc#rsa-1_5")) {
                    String certb64 = XML.xPath.evaluate("ds:KeyInfo/ds:X509Data/ds:X509Certificate", n);
                    if (!(certb64 == null || certb64.isEmpty())) {
                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(certb64)));
                    }
                    byte[] cgram = Base64.getMimeDecoder().decode(XML.xPath.evaluate("xenc:CipherData/xenc:CipherValue", n));
                    result.add(new Recipient.RSARecipient(cert, name, cgram));
                } else if (algorithm.equals("http://www.w3.org/2001/04/xmlenc#kw-aes256")) {
                    Node params = (Node) XML.xPath.evaluate("ds:KeyInfo/xenc:AgreementMethod/xenc11:KeyDerivationMethod/xenc11:ConcatKDFParams", n, XPathConstants.NODE);
                    byte a[] = Hex.decode(params.getAttributes().getNamedItem("AlgorithmID").getTextContent());
                    byte u[] = Hex.decode(params.getAttributes().getNamedItem("PartyUInfo").getTextContent());
                    byte v[] = Hex.decode(params.getAttributes().getNamedItem("PartyVInfo").getTextContent());
                    // Support only full octets
                    if (a[0] != 0 || u[0] != 0 || v[0] != 0) {
                        throw new IOException("Only full octets supported for AlgorithmID, PartyUInfo and PartyVInfo");
                    }
                    a = Arrays.copyOfRange(a, 1, a.length);
                    u = Arrays.copyOfRange(u, 1, u.length);
                    v = Arrays.copyOfRange(v, 1, v.length);

                    String kdf = params.getParentNode().getAttributes().getNamedItem("Algorithm").getTextContent();
                    if (!kdf.equals("http://www.w3.org/2009/xmlenc11#ConcatKDF"))
                        throw new IOException("Algorithm not supported: " + kdf);

                    String kea = params.getParentNode().getParentNode().getAttributes().getNamedItem("Algorithm").getTextContent();
                    if (!kea.equals("http://www.w3.org/2009/xmlenc11#ECDH-ES"))
                        throw new IOException("Algorithm not supported: " + kea);

                    String xsm = XML.xPath.evaluate("ds:DigestMethod/@Algorithm", params);
                    DigestMethod dm = DigestMethod.fromURI(xsm);

                    String certb64 = XML.xPath.evaluate("ds:KeyInfo/xenc:AgreementMethod/xenc:RecipientKeyInfo/ds:X509Data/ds:X509Certificate", n);
                    if (!(certb64 == null || certb64.isEmpty())) {
                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(certb64)));
                    }
                    byte[] cgram = Base64.getMimeDecoder().decode(XML.xPath.evaluate("xenc:CipherData/xenc:CipherValue", n));
                    // XXX: Assumes P384
                    Node key = (Node) XML.xPath.evaluate("ds:KeyInfo/xenc:AgreementMethod/xenc:OriginatorKeyInfo/ds:KeyValue/dsig11:ECKeyValue/dsig11:PublicKey", n, XPathConstants.NODE);

                    ECNamedCurveParameterSpec sp = ECNamedCurveTable.getParameterSpec("secp384r1");
                    if (sp == null) {
                        throw new IOException("Could not parse recipients.xml: unknown curve secp384r1");
                    }
                    ECParameterSpec secp384r1 = new ECNamedCurveSpec(sp.getName(), sp.getCurve(), sp.getG(), sp.getN(), sp.getH());
                    ECPoint point = ECPointUtil.decodePoint(secp384r1.getCurve(), Base64.getMimeDecoder().decode(key.getTextContent()));
                    KeyFactory eckf = KeyFactory.getInstance("EC");
                    ECPublicKey pk = (ECPublicKey) eckf.generatePublic(new ECPublicKeySpec(point, secp384r1));
                    Recipient.ECDHESRecipient r = new Recipient.ECDHESRecipient(cert, name, pk, dm, cgram, a, u, v);
                    result.add(r);
                } else {
                    throw new IOException("Unknown key encryption algorithm: " + algorithm);
                }
            }
        } catch (XPathExpressionException | GeneralSecurityException | NullPointerException e) {
            throw new IOException("Could not parse recipients.xml", e);
        }
        return result;
    }

    static Collection<Recipient> parseRecipientsXML(InputStream in) throws IOException, CertificateException {
        Document d = XML.stream2dom(in);
        if (!XML.validate_cdoc(XML.dom2bytes(d))) {
            throw new IOException("Input does not validate");
        }
        return parseRecipientsXML(d);
    }

    // Extract CN
    private static String getCN(X509Certificate c) throws CertificateParsingException {
        try {
            LdapName ldapDN = new LdapName(c.getSubjectX500Principal().getName());
            for (Rdn rdn : ldapDN.getRdns()) {
                if (rdn.getType().equals("CN"))
                    return rdn.getValue().toString();
            }
            // If the certificate does not have CN, make a hash of the certificate
            // This way we always return something if we have a valid certificate
            return Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()));
        } catch (NamingException | NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new CertificateParsingException("Could not fetch common name from certificate", e);
        }
    }
}
