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

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.CountingInputStream;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.xpath.XPathException;
import javax.xml.xpath.XPathExpressionException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

public final class CDOC implements AutoCloseable {
    public static final String MIMETYPE = "application/x-cdoc+zip";
    public static final String RECIPIENTS_XML = "META-INF/recipients.xml";
    public static final String PAYLOAD_ZIP = "payload.zip";
    public static final String GCM_CIPHER = "AES/GCM/NoPadding";
    public static final String CBC_CIPHER = "AES/CBC/NoPadding";


    final static SecureRandom random;

    static {
        try {
            // See DMI_RANDOM_USED_ONLY_ONCE for reasoning
            random = SecureRandom.getInstanceStrong();
            random.nextBytes(new byte[2]); // seed and discard first 16 bits
        } catch (NoSuchAlgorithmException e) {
            throw new Error("Need to have SecureRandom for encryption!");
        }
    }

    private final Logger log = LoggerFactory.getLogger(CDOC.class);
    public CountingInputStream counter;
    private Document xml;
    private transient SecretKey key;
    private ZipFile zf;
    private ZipInputStream zis;
    private ZipEntry currentEntry;
    private ArrayList<Recipient> recipients;
    private VERSION version;
    private transient Map<String, byte[]> files = null;
    private String algorithm;

    private CDOC(Document d, VERSION v, Collection<Recipient> recipients) {
        this.xml = d;
        this.recipients = new ArrayList<>(recipients);
        this.version = v;
        log.debug("Loaded CDOC with {} recipients", recipients.size());
    }

    public static String getLibraryVersion() {
        String version = "unknown-development";
        try (InputStream versionfile = CDOC.class.getResourceAsStream("pro_version.txt")) {
            if (versionfile != null) {
                try (BufferedReader vinfo = new BufferedReader(new InputStreamReader(versionfile, "UTF-8"))) {
                    version = vinfo.readLine();
                }
            }
        } catch (IOException e) {
            version = "unknown-error";
        }
        return version;
    }

    public static CDOCBuilder builder() {
        return new CDOCBuilder();
    }

    public static CDOC open(File f) throws IOException, CertificateException {
        try (PushbackInputStream cheater = new PushbackInputStream(new FileInputStream(f), 2)) {

            byte[] pk = new byte[2];
            if (cheater.read(pk, 0, pk.length) != pk.length)
                throw new IOException("Not enough bytes to read file magic!");
            cheater.unread(pk);
            if (pk[0] == 'P' && pk[1] == 'K') {
                ZipFile zf = new ZipFile(f);
                ZipEntry recipientsXML = zf.getEntry(RECIPIENTS_XML);
                if (recipientsXML == null) {
                    zf.close();
                    throw new IOException(RECIPIENTS_XML + " not found!");
                }
                try (InputStream rin = zf.getInputStream(recipientsXML)) {
                    Document d = XML.stream2dom(rin);
                    Collection<Recipient> recipients = XMLENC.parseRecipientsXML(d);
                    CDOC c = new CDOC(d, VERSION.CDOC_V2_0, recipients);
                    c.zf = zf;
                    return c;
                } catch (IOException e) {
                    zf.close();
                    throw new IOException(RECIPIENTS_XML + " reading failed!", e);
                }
            } else {
                return from(cheater);
            }
        }
    }

    private static CDOC fromXMLStream(InputStream in) throws IOException, CertificateException {
        Document d = XML.stream2dom(in);
        final VERSION v;
        try {
            String algorithm = XML.xPath.evaluate("/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm", d);
            if (algorithm.equals("http://www.w3.org/2009/xmlenc11#aes256-gcm")) {
                v = VERSION.CDOC_V1_1;
            } else {
                v = VERSION.CDOC_V1_0;
            }
        } catch (XPathExpressionException e) {
            throw new IOException("EncryptionMethod/@Algorithm not found", e);
        }
        Collection<Recipient> recipients = XMLENC.parseRecipientsXML(d);
        return new CDOC(d, v, recipients);
    }

    private static CDOC fromZIPStream(InputStream in) throws IOException, CertificateException {
        ZipInputStream zis = new ZipInputStream(in, StandardCharsets.UTF_8);
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            if (entry.isDirectory())
                continue;
            if (entry.getName().equals(RECIPIENTS_XML)) {
                Document d = XML.stream2dom(zis);
                ArrayList<Recipient> recipients = XMLENC.parseRecipientsXML(d);
                CDOC c = new CDOC(d, VERSION.CDOC_V2_0, recipients);
                c.zis = zis;
                c.currentEntry = entry;
                return c;
            }
        }

        throw new IOException(RECIPIENTS_XML + " not found!");
    }

    public static CDOC from(InputStream in) throws IOException, CertificateException {
        PushbackInputStream cheater = new PushbackInputStream(in, 2);
        byte[] pk = new byte[2];
        if (cheater.read(pk, 0, pk.length) != pk.length)
            throw new IOException("Not enough bytes to read file magic!");
        cheater.unread(pk);
        if (pk[0] == 'P' && pk[1] == 'K') {
            return fromZIPStream(cheater);
        } else {
            return fromXMLStream(cheater);
        }
    }

    public List<Recipient> getRecipients() {
        return Collections.unmodifiableList(recipients);
    }

    public String getAlgorithm() {
        if (algorithm == null) {
            try {
                algorithm = XML.xPath.evaluate("/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm", xml);
            } catch (XPathExpressionException e) {
                log.error("EncryptionMethod/@Algorithm not found: {} ", e.getMessage());
            }
        }
        return algorithm;
    }

    // Gets encrypted payload stream
    private InputStream getPayloadStream() throws IOException {
        if (version == VERSION.CDOC_V1_1 || version == VERSION.CDOC_V1_0) {
            return new ByteArrayInputStream(getPayloadBytes());
        } else if (version == VERSION.CDOC_V2_0) {
            if (zf != null) {
                ZipEntry payload = zf.getEntry(PAYLOAD_ZIP);
                if (payload == null)
                    throw new IOException(PAYLOAD_ZIP + " not found!");
                return zf.getInputStream(payload);
            } else {
                // XXX: This assumes the proper ordering of the container
                for (; currentEntry != null; currentEntry = zis.getNextEntry()) {
                    if (currentEntry.isDirectory())
                        continue;
                    if (currentEntry.getName().equals(PAYLOAD_ZIP)) {
                        return zis;
                    }
                }
                throw new IOException(PAYLOAD_ZIP + " not found!");
            }
        } else {
            throw new IllegalStateException("Unknown version: " + version);
        }
    }

    private byte[] getPayloadBytes() throws IOException {
        final byte[] result;
        if (version == VERSION.CDOC_V1_1 || version == VERSION.CDOC_V1_0) {
            try {
                String s = XML.xPath.evaluate("/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", xml);
                result = Base64.getMimeDecoder().decode(s);
            } catch (XPathException e) {
                throw new IOException("Could not extract payload", e);
            }
        } else if (version == VERSION.CDOC_V2_0) {
            result = IOUtils.toByteArray(getPayloadStream());
        } else {
            throw new IllegalStateException("Unknown version: " + version);
        }
        log.trace("getPayloadBytes size: {}", result.length);
        return result;
    }

    // Decrypt payload to stream
    public void decrypt(SecretKey dek, OutputStream to) throws IOException, GeneralSecurityException {
        try (InputStream in = getPayloadStream()) {
            if (version == VERSION.CDOC_V1_0) {
                byte[] iv = new byte[16];
                if (in.read(iv, 0, iv.length) != iv.length)
                    throw new IOException("Not enought bytes to read IV");
                Cipher cipher = Cipher.getInstance(CBC_CIPHER);
                cipher.init(Cipher.DECRYPT_MODE, dek, new IvParameterSpec(iv));
                ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
                try (javax.crypto.CipherOutputStream cout = new javax.crypto.CipherOutputStream(plaintext, cipher)) {
                    IOUtils.copy(in, cout);
                }
                byte[] pt = Legacy.unpad(plaintext.toByteArray());
                IOUtils.copy(new ByteArrayInputStream(pt), to);
            } else {
                byte[] iv = new byte[12];
                if (in.read(iv, 0, iv.length) != iv.length)
                    throw new IOException("Not enought bytes to read IV");
                log.trace("IV: {}", Hex.toHexString(iv));

                Cipher cipher = Cipher.getInstance(GCM_CIPHER);
                cipher.init(Cipher.DECRYPT_MODE, dek, new GCMParameterSpec(128, iv));

                // Decrypt to memory
                byte[] cryptogram = IOUtils.toByteArray(in);
                byte[] plaintext = cipher.doFinal(cryptogram);

                log.trace("Plaintext is {} bytes", plaintext.length);
                IOUtils.copy(new ByteArrayInputStream(plaintext), to);
            }
        }
    }

    public ZipInputStream getZipInputStream(SecretKey key) throws IOException, GeneralSecurityException {
        if (version != VERSION.CDOC_V2_0)
            throw new IllegalStateException("ZIP input stream is only available for CDOC 2.0");

        try (InputStream payload = getPayloadStream()) {
            //counter = new CountingInputStream(getPayloadStream());
            // was: payload = getPayloadStream()
            byte[] iv = new byte[12];
            if (payload.read(iv, 0, iv.length) != iv.length)
                throw new IOException("Not enought bytes to read IV");
            log.trace("IV: {}", Hex.toHexString(iv));
            Cipher cipher = Cipher.getInstance(GCM_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));

            // Decrypt to memory
            byte[] cryptogram = IOUtils.toByteArray(payload);
            byte[] plaintext = cipher.doFinal(cryptogram);

            log.trace("Plaintext is {} bytes", plaintext.length);
            return new ZipInputStream(new ByteArrayInputStream(plaintext));
        }
    }

    public Map<String, byte[]> getFiles(SecretKey dek) throws IOException, GeneralSecurityException {
        if (files == null) {
            if (version == VERSION.CDOC_V1_0 || version == VERSION.CDOC_V1_1) {
                ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
                decrypt(dek, plaintext);
                files = Legacy.extractPayload(plaintext.toByteArray());
            } else if (version == VERSION.CDOC_V2_0) {
                try (ZipInputStream zin = getZipInputStream(dek)) {
                    ZipEntry e;
                    files = new HashMap<>();
                    while ((e = zin.getNextEntry()) != null) {
                        log.trace("Extracting {}", e.getName());
                        files.put(e.getName(), IOUtils.toByteArray(zin));
                    }
                }
            } else
                throw new IllegalStateException("Unknown version");
        }
        return files;
    }

    public VERSION getVersion() {
        return version;
    }

    @Override
    public void close() throws IOException {
        if (zf != null)
            zf.close();
        if (zis != null)
            zis.close();
    }

    public enum VERSION {
        CDOC_V1_0, CDOC_V1_1, CDOC_V2_0
    }
}
