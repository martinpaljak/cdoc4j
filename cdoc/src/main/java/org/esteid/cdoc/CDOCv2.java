package org.esteid.cdoc;

import asic4j.Container;
import asic4j.Manifest;
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
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class CDOCv2 {

    public static String MIMETYPE = "application/x-cryptodoc";

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
        new SecureRandom().nextBytes(iv); // FIXME: re-use instance
        byte[] cgram = CDOCv1.encrypt_gcm(data, dek, iv);

        // Make container
        Manifest mf = new Manifest(MIMETYPE);
        mf.addFile("package.zip", "application/zip", cgram.length);
        mf.toStream(System.out);


        // Pump into container
        Container asic = new Container(MIMETYPE);
        asic.put_meta("META-INF/recipients.xml", XML.dom2bytes(recipientsXML));
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

        for (File p : files) {
            // put all in flat file
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
