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

import asic4j.Container;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class CDOCBuilder {
    private final static Logger log = LoggerFactory.getLogger(CDOCBuilder.class);
    private static final int GCM_IV_LEN = 12;
    private static final int GCM_TAG_LEN = 128;
    private transient SecretKey key;
    private CDOC.Version version = CDOC.Version.CDOC_V1_1;
    private boolean privacy = false;
    private OutputStream out = null;
    private ArrayList<X509Certificate> recipients = new ArrayList<>();
    private ArrayList<File> files = new ArrayList<>();
    private ArrayList<Path> paths = new ArrayList<>();
    private HashMap<String, InputStream> streams = new HashMap<>();
    private boolean validate = false;


    public CDOCBuilder(CDOC.Version v) {
        this.version = v;
    }

    public CDOCBuilder() {
    }

    private static void encrypt_gcm(InputStream in, SecretKey key, byte[] iv, OutputStream out) throws IOException, GeneralSecurityException {
        if (iv.length != GCM_IV_LEN)
            throw new IllegalArgumentException("IV must be 12 bytes (96 bits)");

        Cipher cipher = Cipher.getInstance(EncryptionMethod.AES256_GCM.getCipherName());
        GCMParameterSpec params = new GCMParameterSpec(GCM_TAG_LEN, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        out.write(iv);
        out.write(cipher.doFinal(IOUtils.toByteArray(in)));
    }

    public CDOCBuilder withTransportKey(byte[] key) {
        this.key = new SecretKeySpec(key, "AES");
        checkKey();
        return this;
    }

    public CDOCBuilder setOutputStream(OutputStream out) {
        this.out = out;
        return this;
    }

    public CDOCBuilder setVersion(CDOC.Version v) {
        this.version = v;
        return this;
    }

    public CDOCBuilder withTransportKey(SecretKey key) {
        this.key = key;
        return this;
    }

    public CDOCBuilder withPrivacy(boolean enabled) {
        privacy = enabled;
        return this;
    }

    public CDOCBuilder withValidation(boolean enabled) {
        validate = enabled;
        return this;
    }

    public CDOCBuilder addRecipient(X509Certificate c) {
        if (version == CDOC.Version.CDOC_V1_0 && !c.getPublicKey().getAlgorithm().equals("RSA")) {
            throw new IllegalArgumentException("Can do CDOC v1.0 only with RSA keys");
        }
        recipients.add(c);
        return this;
    }

    public CDOCBuilder addFile(File f) {
        files.add(f);
        return this;
    }

    public CDOCBuilder addPath(Path p) {
        paths.add(p);
        return this;
    }


    public CDOCBuilder addStream(String name, InputStream in) {
        streams.put(name, in);
        return this;
    }

    private void checkKey() {
        // generate DEK if not explicitly given
        if (key == null) {
            final byte[] keybytes;
            if (version == CDOC.Version.CDOC_V1_0)
                keybytes = new byte[16];
            else
                keybytes = new byte[32];
            CDOC.random.nextBytes(keybytes);
            key = new SecretKeySpec(keybytes, "AES");
        }

        // Check key
        if (version == CDOC.Version.CDOC_V1_0) {
            if (key.getEncoded().length != 16) {
                throw new IllegalArgumentException("Key must be 16 bytes for AES-128");
            }
        } else {
            if (key.getEncoded().length != 32) {
                throw new IllegalArgumentException("Key must be 32 bytes for AES-256");
            }
        }
    }

    public void buildToStream(OutputStream to) throws IOException, GeneralSecurityException {
        this.out = to;
        build();
    }

    public void build() throws IOException, GeneralSecurityException {
        ArrayList<AutoCloseable> toClose = new ArrayList<>();
        try {
            if (out == null || (recipients.size() == 0 && key == null) || (streams.size() == 0 && files.size() == 0 && paths.size() == 0)) {
                throw new IllegalStateException("Need to have output stream, files and recipients");
            }

            checkKey();

            // Make the payload streams
            for (File f : files) {
                FileInputStream fin = new FileInputStream(f);
                toClose.add(fin);
                streams.put(f.getName(), fin);
            }

            for (Path p : paths) {
                Path name = p.getFileName();
                if (name == null)
                    throw new IOException("Null path name: " + p);
                InputStream in = Files.newInputStream(p);
                toClose.add(in);
                streams.put(name.toString(), in);
            }


            if (version == CDOC.Version.CDOC_V1_0 || version == CDOC.Version.CDOC_V1_1) {
                // Generate recipients xml for recipients
                // Construct the overall document.
                Document recipientsXML = XMLENC.makeRecipientsXML(version, recipients, key, privacy);

                // Calculate payload
                byte[] data = Legacy.makePayload(streams);
                ByteArrayInputStream pin = new ByteArrayInputStream(data);
                ByteArrayOutputStream cout = new ByteArrayOutputStream();
                // Encrypt payload
                if (version == CDOC.Version.CDOC_V1_0) {
                    byte[] iv = new byte[16];
                    CDOC.random.nextBytes(iv);
                    Legacy.encrypt_cbc(pin, key, iv, cout);
                } else {
                    byte[] iv = new byte[12];
                    CDOC.random.nextBytes(iv);
                    encrypt_gcm(pin, key, iv, cout);
                }

                // Add payload
                Element cipherdata = recipientsXML.createElement("xenc:CipherData");
                Element payload = recipientsXML.createElement("xenc:CipherValue");
                payload.setTextContent(Base64.getEncoder().encodeToString(cout.toByteArray()));
                cipherdata.appendChild(payload);
                recipientsXML.getDocumentElement().appendChild(cipherdata);

                // XXX: qdigidoc requires at least the same number of properties as files in the payload
                // or the payload files willt not be shown after decryption. Having more properties
                // than files in the payload shrinks the file list automatically.
                Element props = recipientsXML.createElement("xenc:EncryptionProperties");
                for (String s: streams.keySet()) {
                    Element prop = recipientsXML.createElement("xenc:EncryptionProperty");
                    prop.setAttribute("Name", "orig_file");
                    prop.setTextContent("☠   DECRYPT FIRST   ☠|666|application/octet-stream|D0");
                    props.appendChild(prop);
                }
                recipientsXML.getDocumentElement().appendChild(props);
                // Store to output stream
                XML.dom2stream(recipientsXML, out);
            } else {
                try (ZipOutputStream zos = buildZipOutputStream()) {
                    for (Map.Entry<String, InputStream> in : streams.entrySet()) {
                        ZipEntry e = new ZipEntry(in.getKey());
                        if (privacy)
                            e = Container.strip(e);

                        log.trace("Storing {}", e.getName());
                        zos.putNextEntry(e);
                        IOUtils.copyLarge(in.getValue(), zos);
                        zos.closeEntry();
                    }
                    zos.flush();
                    zos.finish();
                }
            }
        } finally {
            for (AutoCloseable a : toClose) {
                try {
                    a.close();
                } catch (Exception e) {
                    // ignore
                }
            }
        }

    }

    // FIXME this is all backed by arrays at the moment.
    // For streams to work properly with GCM, must re-implement Cipher*Stream and possibly Zip*stream
    public ZipOutputStream buildZipOutputStream() throws IOException, GeneralSecurityException {
        if (version != CDOC.Version.CDOC_V2_0)
            throw new IllegalStateException("ZIP output stream is only available for CDOC 2.0");
        if (out == null || (recipients.size() == 0 && key == null)) {
            throw new IllegalStateException("Need to have output stream and recipients!");
        }

        checkKey();

        // Generate recipients xml for recipients
        Document recipientsXML = XMLENC.makeRecipientsXML(version, recipients, key, privacy);

        // Add payload reference to recipients.xml
        Element cipherdata = recipientsXML.createElement("xenc:CipherData");
        Element payload_ref = recipientsXML.createElement("xenc:CipherReference");
        payload_ref.setAttribute("URI", CDOC.PAYLOAD_ZIP);
        cipherdata.appendChild(payload_ref);
        recipientsXML.getDocumentElement().appendChild(cipherdata);

        byte[] rcpts = XML.dom2bytes(recipientsXML);
        if (validate && !XML.validate_cdoc(rcpts)) {
            throw new IllegalStateException("Generated recipients.xml did not validate!");
        }

        // Write container header + manifest
        Container asic = new Container(CDOC.MIMETYPE, out, privacy);
        asic.put_meta(CDOC.RECIPIENTS_XML, rcpts);
        asic.declare(CDOC.PAYLOAD_ZIP, "application/zip", -1);
        asic.writeHeader();
        asic.writeMetas();

        // Create a new ZipOutputStream for payload.zip
        ZipOutputStream container = asic.getZipOutputStream();

        // Generate random IV
        byte[] iv = new byte[GCM_IV_LEN];
        CDOC.random.nextBytes(iv);
        log.trace("IV: {}", Hex.toHexString(iv));

        Cipher cipher = Cipher.getInstance(EncryptionMethod.AES256_GCM.getCipherName());
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LEN, iv));
        return new CDOCZipOutputStream(container, new ByteArrayOutputStream(), cipher, asic.getManifest(), privacy);
    }
}
