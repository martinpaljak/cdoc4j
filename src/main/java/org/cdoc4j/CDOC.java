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

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.CountingInputStream;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathException;
import javax.xml.xpath.XPathExpressionException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
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

    final static SecureRandom random;
    private final static Logger log = LoggerFactory.getLogger(CDOC.class);

    static {
        // See DMI_RANDOM_USED_ONLY_ONCE for reasoning
        random = new SecureRandom();
        random.nextBytes(new byte[2]); // seed if needed and discard first 16 bits
        log.info("Using {} from {} for random (IV, keys)", random.getAlgorithm(), random.getProvider());
    }

    public CountingInputStream counter;
    private Document xml;
    private transient SecretKey key;
    private ZipFile zf;
    private ZipInputStream zis;
    private ZipEntry currentEntry;
    private ArrayList<Recipient> recipients;
    private Version version;
    private transient Map<String, byte[]> files = null;
    private EncryptionMethod algorithm;
    private boolean singleFile = false;

    private CDOC(Document d, Version v, Collection<Recipient> recipients) {
        this.xml = d;
        this.recipients = new ArrayList<>(recipients);
        this.version = v;
        if (d.getDocumentElement().hasAttribute("MimeType") && !d.getDocumentElement().getAttribute("MimeType").equals(Legacy.DIGIDOC_XSD))
            singleFile = true;
        log.trace("Loaded CDOC with {} recipients", recipients.size());
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
                    CDOC c = new CDOC(d, Version.CDOC_V2_0, recipients);
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

    public static boolean isCDOC(File f) throws IOException {
        if (f.isFile() && f.getName().toLowerCase().endsWith(".cdoc"))
            return true;
        try (InputStream in = new FileInputStream(f)) {
            byte[] header = new byte[38 + MIMETYPE.length()];
            if (in.read(header, 0, header.length) >= header.length) {
                String pk = new String(header, 0, 2, StandardCharsets.US_ASCII.name());
                String mimetype = new String(header, 30, 8, StandardCharsets.US_ASCII.name());
                String realmime = new String(header, 38, MIMETYPE.length(), StandardCharsets.US_ASCII.name());
                return pk.equals("PK") && mimetype.equals("mimetype") && realmime.equals(MIMETYPE);
            }
        }
        return false;
    }

    private static CDOC fromXMLStream(InputStream in) throws IOException, CertificateException {
        Document d = XML.stream2dom(in);
        final Version v;
        try {
            EncryptionMethod algorithm = EncryptionMethod.fromURI(XML.xPath.evaluate("/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm", d));
            if (algorithm == null)
                throw new IOException("EncryptionMethod/@Algorithm not found");
            if (algorithm == EncryptionMethod.AES256_GCM) {
                v = Version.CDOC_V1_1;
            } else {
                v = Version.CDOC_V1_0;
            }
        } catch (XPathExpressionException e) {
            throw new IOException("Could not extract EncryptionMethod/@Algorithm", e);
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
                CDOC c = new CDOC(d, Version.CDOC_V2_0, recipients);
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

    public EncryptionMethod getAlgorithm() {
        if (algorithm == null) {
            try {
                algorithm = EncryptionMethod.fromURI(XML.xPath.evaluate("/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm", xml));
            } catch (XPathExpressionException e) {
                log.error("EncryptionMethod/@Algorithm not found: {} ", e.getMessage());
            }
        }
        return algorithm;
    }

    public String preSharedKey() {
        try {
            return XML.xPath.evaluate("/xenc:EncryptedData/ds:KeyInfo/ds:KeyName", xml);
        } catch (XPathExpressionException e) {
            log.error("KeyInfo/KeyName not found: {}", e.getMessage(), e);
        }
        return null;
    }

    // Gets encrypted payload stream
    private InputStream getPayloadStream() throws IOException {
        if (version == Version.CDOC_V1_1 || version == Version.CDOC_V1_0) {
            return new ByteArrayInputStream(getPayloadBytes());
        } else if (version == Version.CDOC_V2_0) {
            if (zf != null) {
                ZipEntry payload = zf.getEntry(PAYLOAD_ZIP);
                if (payload == null)
                    throw new IOException(PAYLOAD_ZIP + " not found!");
                return zf.getInputStream(payload);
            } else {
                // XXX: This assumes the "proper" ordering of the container
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
        if (version == Version.CDOC_V1_1 || version == Version.CDOC_V1_0) {
            try {
                String s = XML.xPath.evaluate("/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", xml);
                result = Base64.getMimeDecoder().decode(s);
            } catch (XPathException e) {
                throw new IOException("Could not extract payload", e);
            }
        } else if (version == Version.CDOC_V2_0) {
            result = IOUtils.toByteArray(getPayloadStream());
        } else {
            throw new IllegalStateException("Unknown version: " + version);
        }
        log.trace("getPayloadBytes size: {}", result.length);
        return result;
    }

    /**
     * Finds correct filename (cdoc version is 1.1), if cdoc contains only on file.
     * @return
     * @throws IOException
     */
    private String getPayloadFilename() throws IOException {
        String result = null;
        final String ENC_DATA_ENC_PROP_ENC_PROP = "/xenc:EncryptedData/xenc:EncryptionProperties/xenc:EncryptionProperty";
        if (version == Version.CDOC_V1_1 || version == Version.CDOC_V1_0) {
            try {
                NodeList encryptionProperty = (NodeList) XML.xPath.evaluate(ENC_DATA_ENC_PROP_ENC_PROP, xml, XPathConstants.NODESET);
                for (int i = 0; i < encryptionProperty.getLength(); i++) {
                    Node n = encryptionProperty.item(i);

                    String encPropName = n.getAttributes().getNamedItem("Name").getTextContent();
                    String encPropValue = n.getTextContent();
                    log.debug("Node name: " + encPropName + ", Node value: " + encPropValue);
                    if(encPropName.toLowerCase().equals("filename")){
                        result = encPropValue;
                        break;
                    }
                }
            } catch (XPathException e) {
                throw new IOException("Could not extract payload", e);
            }
        } else if (version == Version.CDOC_V2_0) {
            // FIXME: How to find correct filename if CDOC is 2.0?
            result = "unknown.bin";
        } else {
            throw new IllegalStateException("Unknown version: " + version);
        }
        log.info("getPayloadFilename: ", result);
        return result;
    }

    // Decrypt payload to stream
    public void decrypt(SecretKey dek, OutputStream to) throws IOException, GeneralSecurityException {
        try (InputStream in = getPayloadStream()) {
            if (version == Version.CDOC_V1_0) {
                byte[] iv = new byte[16];
                if (in.read(iv, 0, iv.length) != iv.length)
                    throw new IOException("Not enought bytes to read IV");
                Cipher cipher = Cipher.getInstance(getAlgorithm().getCipherName());
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

                Cipher cipher = Cipher.getInstance(getAlgorithm().getCipherName());
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
        if (version != Version.CDOC_V2_0)
            throw new IllegalStateException("ZIP input stream is only available for CDOC 2.0");

        try (InputStream payload = getPayloadStream()) {
            //counter = new CountingInputStream(getPayloadStream());
            // was: payload = getPayloadStream()
            byte[] iv = new byte[12];
            if (payload.read(iv, 0, iv.length) != iv.length)
                throw new IOException("Not enought bytes to read IV");
            log.trace("IV: {}", Hex.toHexString(iv));
            Cipher cipher = Cipher.getInstance(getAlgorithm().getCipherName());
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
            if (version == Version.CDOC_V1_0 || version == Version.CDOC_V1_1) {
                ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
                decrypt(dek, plaintext);
                if (singleFile) {
                    files = new HashMap<>();
                    String singlefileName = getPayloadFilename();
                    log.info("Single filename: " + singlefileName);
                    files.put(singlefileName, plaintext.toByteArray()); // FIXME: file name
                } else {
                    files = Legacy.extractPayload(plaintext.toByteArray());
                }
            } else if (version == Version.CDOC_V2_0) {
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

    public Version getVersion() {
        return version;
    }

    @Override
    public void close() throws IOException {
        if (zf != null)
            zf.close();
        if (zis != null)
            zis.close();
    }

    public enum Version {
        CDOC_V1_0("CDOC-1.0"), CDOC_V1_1("CDOC-1.1"), CDOC_V2_0("CDOC-2.0");

        private final String name;

        Version(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return this.name;
        }
    }
}
