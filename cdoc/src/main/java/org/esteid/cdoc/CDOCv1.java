package org.esteid.cdoc;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

// Generates CDOC v1.0 and v1.1 encrypted documents.
// Works on files.
public class CDOCv1 {
    private final static SecureRandom random;

    static {
        try {
            random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new Error("Need to have SecureRandom");
        }
    }

    public static void encrypt(VERSION v, File to, List<File> files, List<X509Certificate> recipients) throws GeneralSecurityException, NamingException, IOException {
        // Check
        if (v == VERSION.V1_0) {
            for (X509Certificate c : recipients) {
                if (!c.getPublicKey().getAlgorithm().equals("RSA"))
                    throw new IllegalArgumentException("Can do CDOC v1.0 only with RSA keys");
            }
        }

        // Make the AES key that will be used to encrypt the payload
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey dek = keygen.generateKey();

        // Construct the overall document.
        Document recipientsXML = makeRecipientsXML(recipients, dek);

        // Calculate payload
        byte[] data = makePayload(files);

        byte[] cgram;
        // Encrypt payload
        if (v == VERSION.V1_0) {
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            cgram = CDOCv1.encrypt_cbc(data, dek, iv);
        } else {
            byte[] iv = new byte[12];
            random.nextBytes(iv);
            cgram = CDOCv1.encrypt_gcm(data, dek, iv);
        }


        // Add payload
        Element cipherdata = recipientsXML.createElement("denc:CipherData");
        Element payload = recipientsXML.createElement("denc:CipherValue");
        payload.setTextContent(Base64.getEncoder().encodeToString(cgram));
        cipherdata.appendChild(payload);
        recipientsXML.getDocumentElement().appendChild(cipherdata);

        // XXX: Add comments or file will not have content
        Element props = recipientsXML.createElement("denc:EncryptionProperties");
        for (int i = 0; i < files.size(); i++) {
            Element prop = recipientsXML.createElement("denc:EncryptionProperty");
            prop.setAttribute("Name", "orig_file");
            prop.setTextContent("😳 - decrypt me!|1|application/octet-stream|D" + i);
            props.appendChild(prop);
        }
        recipientsXML.getDocumentElement().appendChild(props);

        // Dump to file
        XML.dom2stream(recipientsXML, Files.newOutputStream(to.toPath()));
    }

    public static Document makeRecipientsXML(Collection<X509Certificate> recipients, SecretKey dek) throws GeneralSecurityException, NamingException {
        // Construct recipients.xml.
        Document cdoc = XML.getDocument();

        Element root = cdoc.createElement("xenc:EncryptedData");
        root.setAttribute("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#");
        root.setAttribute("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#");
        root.setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
        root.setAttribute("xmlns:dsig11", "http://www.w3.org/2009/xmldsig11#");

        cdoc.appendChild(root);
        // optional MimeType FIXME

        // See update FIXME - use 256 gcm
        Element encmethod = cdoc.createElement("xenc:EncryptionMethod");
        encmethod.setAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#aes256-gcm");
        root.appendChild(encmethod);

        // Key infos
        Element keyinfo = cdoc.createElement("ds:KeyInfo");
        root.appendChild(keyinfo);

        // One for every recipient, dependent on tech
        for (X509Certificate crt : recipients) {
            Element enckey = toRecipient(cdoc, crt, dek);
            keyinfo.appendChild(enckey);
        }
        return cdoc;
    }


    public static byte[] encrypt_gcm(byte[] data, SecretKey key, byte[] iv) throws GeneralSecurityException {
        if (iv.length != 12)
            throw new IllegalArgumentException("IV must be 12 bytes (96 bits)");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec params = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] cgram = cipher.doFinal(data);
        return concatenate(iv, cgram);
    }

    public static byte[] encrypt_cbc(byte[] data, SecretKey key, byte[] iv) throws GeneralSecurityException {
        if (iv.length != 16)
            throw new IllegalArgumentException("IV must be 16 bytes (128 bits)");

        // XXX: Double padding
        byte[] pad = padpkcs7(padx923(data));

        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] cgram = c.doFinal(pad);
        return concatenate(iv, cgram);
    }

    // FIXME: wrong place, bad implementation
    private static byte[] padx923(byte[] text) {
        int length = text.length;
        int blocksize = 16;
        int totalLength = length;
        for (totalLength++; (totalLength % blocksize) != 0; totalLength++) ;
        int padlength = totalLength - length;
        byte[] result = new byte[totalLength];
        System.arraycopy(text, 0, result, 0, length);
        for (int i = 0; i < padlength; i++) {
            result[length + i] = (byte) 0x00;
        }
        result[result.length - 1] = (byte) padlength;
        return result;
    }

    private static byte[] padpkcs7(byte[] text) {
        int length = text.length;
        int blocksize = 16;
        int totalLength = length;
        for (totalLength++; (totalLength % blocksize) != 0; totalLength++) ;
        int padlength = totalLength - length;
        byte[] result = new byte[totalLength];
        System.arraycopy(text, 0, result, 0, length);
        for (int i = 0; i < padlength; i++) {
            result[length + i] = (byte) padlength;
        }
        return result;
    }

    static byte[] concatenate(byte[]... args) {
        int length = 0, pos = 0;
        for (byte[] arg : args) {
            length += arg.length;
        }
        byte[] result = new byte[length];
        for (byte[] arg : args) {
            System.arraycopy(arg, 0, result, pos, arg.length);
            pos += arg.length;
        }
        return result;
    }

    // Returns elements to be added to the CDOC XML, based on recipient type
    private static Element toRecipient(Document cdoc, X509Certificate cert, SecretKey dek) throws InvalidNameException, GeneralSecurityException {
        if (cert.getPublicKey() instanceof ECPublicKey) {
            return toECRecipient(cdoc, cert, dek);
        } else if (cert.getPublicKey() instanceof RSAPublicKey) {
            return toRSARecipient(cdoc, cert, dek);
        } else {
            throw new IllegalArgumentException("Unknown public key algorithm: " + cert.getPublicKey().getAlgorithm());
        }
    }

    public static Element toRSARecipient(Document cdoc, X509Certificate cert, SecretKey dek) throws InvalidNameException, GeneralSecurityException {
        Element enckey = cdoc.createElement("xenc:EncryptedKey");
        // Set a nice name
        enckey.setAttribute("Recipient", getCN(cert));

        // Encryption method for transport key - currently fixed ;(
        Element kekmethod = cdoc.createElement("xenc:EncryptionMethod");
        kekmethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#rsa-1_5");
        enckey.appendChild(kekmethod);

        // Certificate itself
        Element kinfo = cdoc.createElement("ds:KeyInfo");
        Element x509data = cdoc.createElement("ds:X509Data");
        kinfo.appendChild(x509data);
        Element x509cert = cdoc.createElement("ds:X509Certificate");
        x509cert.setTextContent(Base64.getEncoder().encodeToString(cert.getEncoded()));
        x509data.appendChild(x509cert);
        enckey.appendChild(kinfo);
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

    // FIXME: only does secp384 with AES-256
    public static Element toECRecipient(Document cdoc, X509Certificate cert, SecretKey dek) throws InvalidNameException, GeneralSecurityException {
        ECPublicKey k = (ECPublicKey) cert.getPublicKey();

        // Generate temporary key.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair keyPair = kpg.generateKeyPair();


        Element enckey = cdoc.createElement("xenc:EncryptedKey");
        // Set a nice name
        enckey.setAttribute("Recipient", getCN(cert));

        // Encryption method for transport key - currently fixed ;(
        Element kekmethod = cdoc.createElement("xenc:EncryptionMethod");
        kekmethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#kw-aes256");
        enckey.appendChild(kekmethod);

        // Certificate itself
        Element kinfo = cdoc.createElement("ds:KeyInfo");
        // AgreementMethod
        Element kam = cdoc.createElement("xenc:AgreementMethod");
        kam.setAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#ECDH-ES");
        //
        Element kdm = cdoc.createElement("xenc11:KeyDerivationMethod");
        kdm.setAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#ConcatKDF");
        //

        // Get the OID
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(k.getEncoded());
        SubjectPublicKeyInfo tempKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        //System.out.println(subPubKeyInfo.getAlgorithm().getParameters());

        //
        // String curveName = "urn:oid:" + ASN1ObjectIdentifier.getInstance(subPubKeyInfo.getAlgorithm().getParameters()).toString();
        String curveName = "urn:oid:" + subPubKeyInfo.getAlgorithm().getParameters().toString();
        //System.out.println(curveName);


        byte[] algid = new String("http://www.w3.org/2001/04/xmlenc#kw-aes256").getBytes(StandardCharsets.US_ASCII);
        byte[] uinfo = tempKeyInfo.getPublicKeyData().getBytes();
        byte[] vinfo = getCN(cert).getBytes(StandardCharsets.UTF_8);

        Element ckdfp = cdoc.createElement("xenc11:ConcatKDFParams");
        ckdfp.setAttribute("AlgorithmID", bytesToHex(algid));
        ckdfp.setAttribute("PartyUInfo", bytesToHex(uinfo));
        ckdfp.setAttribute("PartyVInfo", bytesToHex(vinfo));
        Element dm = cdoc.createElement("ds:DigestMethod");
        dm.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha384"); // FIXME: field size
        ckdfp.appendChild(dm);
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
        ecpk.setTextContent(Base64.getEncoder().encodeToString(tempKeyInfo.getPublicKeyData().getBytes()));
        eckv.appendChild(ecpk);

        kv.appendChild(eckv);
        oki.appendChild(kv);
        kam.appendChild(oki);

        // RecipientKeyInfo
        Element rki = cdoc.createElement("xenc:RecipientKeyInfo");
        Element x509data = cdoc.createElement("ds:X509Data");
        kinfo.appendChild(x509data);
        Element x509cert = cdoc.createElement("ds:X509Certificate");
        x509cert.setTextContent(Base64.getEncoder().encodeToString(cert.getEncoded()));
        x509data.appendChild(x509cert);
        rki.appendChild(x509data);
        kam.appendChild(rki);

        kinfo.appendChild(kam);
        enckey.appendChild(kinfo);

        // Add actual encrypted key value
        // Do key wrap

        // Key used for encryption
        //System.out.println("Encryption key: " + HexUtils.bin2hex(dek.getEncoded()));


        // Shared agreement
        KeyAgreement key_agreement = KeyAgreement.getInstance("ECDH");
        key_agreement.init(keyPair.getPrivate());
        key_agreement.doPhase(cert.getPublicKey(), true);
        // Use the shared secret to wrap the actual key
        byte[] shared_secret = key_agreement.generateSecret();
        //System.out.println("Shared secret (ECDH): " + HexUtils.bin2hex(shared_secret));


        // Derive key wrap key with ckdf
        ConcatenationKDFGenerator ckdf = new ConcatenationKDFGenerator(new SHA384Digest()); // FIXME: curve size
        ckdf.init(new KDFParameters(shared_secret, concatenate(algid, uinfo, vinfo)));
        byte[] wrapkeybytes = new byte[32];

        ckdf.generateBytes(wrapkeybytes, 0, 32);

        //System.out.println("Wrap key bytes: " + HexUtils.bin2hex(wrapkeybytes));
        SecretKeySpec wrapKey = new SecretKeySpec(wrapkeybytes, "AES");
        // Wrap the actual key with the derived key
        // Cipher c = Cipher.getInstance("AESWrap", "SunJCE");
        Cipher c = Cipher.getInstance("AESWrap");
        c.init(Cipher.WRAP_MODE, wrapKey);
        byte[] cgram = c.wrap(dek);

        Element cipherdata = cdoc.createElement("xenc:CipherData");
        Element ciphervalue = cdoc.createElement("xenc:CipherValue");

        // Do DH
        ciphervalue.setTextContent(Base64.getEncoder().encodeToString(cgram));

        cipherdata.appendChild(ciphervalue);
        enckey.appendChild(cipherdata);
        return enckey;
    }

    // Generates a minimalistic SignedDoc that is OK for qdigidoccrypto
    // XXX: this is braindead
    public static byte[] makePayload(List<File> files) throws IOException {
        Document payload = XML.getDocument();

        Element root = payload.createElement("SignedDoc");
        root.setAttribute("xmlns", "http://www.sk.ee/DigiDoc/v1.3.0#");
        root.setAttribute("format", "DIGIDOC-XML");
        root.setAttribute("version", "1.3");
        payload.appendChild(root);

        // Files
        int id = 0; // XXX
        for (File f : files) {
            Element datafile = payload.createElement("DataFile");
            datafile.setAttribute("ContentType", "EMBEDDED_BASE64");
            datafile.setAttribute("Filename", f.getName());
            datafile.setAttribute("MimeType", "application/octet-stream");
            datafile.setAttribute("Size", Long.toString(Files.size(f.toPath())));
            datafile.setAttribute("Id", "D" + id);
            datafile.setTextContent(Base64.getEncoder().encodeToString(Files.readAllBytes(f.toPath())));
            root.appendChild(datafile);
            id++;
        }
        return XML.dom2bytes(payload);
    }

    public static String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for (byte b : in) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    // Extract CN
    public static String getCN(X509Certificate c) throws InvalidNameException {
        LdapName ldapDN = new LdapName(c.getSubjectX500Principal().getName());
        for (Rdn rdn : ldapDN.getRdns()) {
            if (rdn.getType().equals("CN"))
                return rdn.getValue().toString();
        }
        return null;
    }

    public enum VERSION {
        V1_0, V1_1
    }

}
