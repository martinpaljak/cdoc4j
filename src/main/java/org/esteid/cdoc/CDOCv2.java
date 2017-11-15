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

import asic4j.Container;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.naming.NamingException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class CDOCv2 {

    public static final String MIMETYPE = "application/x-cryptodoc";

    public static void encrypt(File to, List<File> files, List<X509Certificate> recipients) throws GeneralSecurityException, NamingException, IOException {

        // Make the AES key that will be used to encrypt the payload
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey dek = keygen.generateKey();

        // Construct the overall document.
        Document recipientsXML = CDOCv1.makeRecipientsXML(recipients, dek);

        // Add payload reference to recipients.xml
        Element cipherdata = recipientsXML.createElement("xenc:CipherData");
        Element payload_ref = recipientsXML.createElement("xenc:CipherReference");
        payload_ref.setAttribute("URI", "payload.zip");
        cipherdata.appendChild(payload_ref);
        recipientsXML.getDocumentElement().appendChild(cipherdata);

        // Calculate actual payload
        byte[] data = CDOCv2.makePayload(files);

        // Encrypt payload
        byte[] iv = new byte[12];
        CDOC.random.nextBytes(iv);
        byte[] cgram = CDOCv1.encrypt_gcm(data, dek, iv);

        // Make container
        //Manifest mf = new Manifest(MIMETYPE);
        //mf.addFile("package.zip", "application/zip", cgram.length);
        //mf.toStream(System.out);


        byte[] rcpts = XML.dom2bytes(recipientsXML);
        if (!XML.validate(rcpts)) {
            System.out.println("recipients.xml does not validate!");
        }

        // Pump into container
        Container asic = new Container(MIMETYPE);
        asic.put_meta("META-INF/recipients.xml", rcpts);
        asic.put("payload.zip", "application/zip", cgram);

        // Write to file
        try (FileOutputStream fos = new FileOutputStream(to)) {
            asic.write(fos);
        }
    }

    // Wrap all files into payload.zip, usign STORE
    public static byte[] makePayload(List<File> files) throws IOException {
        ByteArrayOutputStream payload_b = new ByteArrayOutputStream();
        ZipOutputStream payload_z = new ZipOutputStream(payload_b);
        //payload_z.setLevel(9);

        for (File p : files) {
            ZipEntry ze = new ZipEntry(p.getName());
            byte[] fv = Files.readAllBytes(p.toPath());
            ze.setMethod(ZipEntry.DEFLATED);
            ze.setSize(fv.length);
            payload_z.putNextEntry(ze);
            payload_z.write(fv);
            payload_z.closeEntry();
        }
        payload_z.finish();
        return payload_b.toByteArray();
    }
}
