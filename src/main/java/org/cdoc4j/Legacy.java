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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

// CDOC 1.0 hacks
public final class Legacy {

    static final String DIGIDOC_NS = "http://www.sk.ee/DigiDoc/v1.3.0#";
    static final String DIGIDOC_XSD = "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd";

    public static void encrypt_cbc(InputStream in, SecretKey key, byte[] iv, OutputStream out) throws IOException, GeneralSecurityException {
        if (iv.length != 16)
            throw new IllegalArgumentException("IV must be 16 bytes (128 bits)");

        // XXX: Double padding
        byte[] pad = padpkcs7(padx923(IOUtils.toByteArray(in)));

        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        out.write(iv);
        try (CipherOutputStream cout = new CipherOutputStream(out, c)) {
            IOUtils.copy(new ByteArrayInputStream(pad), cout);
        }
    }

    // FIXME: wrong place, bad implementation
    private static byte[] padx923(byte[] text) {
        int length = text.length;
        int totalLength = length;
        for (totalLength++; (totalLength % 16) != 0; totalLength++) ;
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
        int totalLength = length;
        for (totalLength++; (totalLength % 16) != 0; totalLength++) ;
        int padlength = totalLength - length;
        byte[] result = new byte[totalLength];
        System.arraycopy(text, 0, result, 0, length);
        for (int i = 0; i < padlength; i++) {
            result[length + i] = (byte) padlength;
        }
        return result;
    }

    public static byte[] concatenate(byte[]... args) {
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

    public static byte[] unpad(byte[] data) {
        // Last block is always full block of PKCS#7 padding
        if (data[data.length - 1] == 0x10) {
            data = Arrays.copyOf(data, data.length - 16);
        }
        // Remove X923 padding
        int padlen = data[data.length - 1];
        data = Arrays.copyOf(data, data.length - padlen);
        return data;
    }

    public static byte[] makePayload(Map<String, InputStream> files) throws IOException {
        Document payload = XML.getDocument();

        Element root = payload.createElement("SignedDoc");
        root.setAttribute("xmlns", DIGIDOC_NS);
        root.setAttribute("format", "DIGIDOC-XML");
        root.setAttribute("version", "1.3");
        payload.appendChild(root);

        // Files
        int id = 0; // XXX
        for (Map.Entry<String, InputStream> f : files.entrySet()) {
            byte[] fv = IOUtils.toByteArray(f.getValue());
            Element datafile = payload.createElement("DataFile");
            datafile.setAttribute("ContentType", "EMBEDDED_BASE64");
            datafile.setAttribute("Filename", f.getKey());
            datafile.setAttribute("MimeType", "application/octet-stream");
            datafile.setAttribute("Size", Long.toString(fv.length));
            datafile.setAttribute("Id", "D" + id);
            datafile.setTextContent(Base64.getEncoder().encodeToString(fv));
            root.appendChild(datafile);
            id++;
        }
        return XML.dom2bytes(payload);
    }

    // Extracts a SignedDoc into files
    public static Map<String, byte[]> extractPayload(byte[] payload) throws IOException {
        try {
            // Extract files from inner DDOC 1.3
            InputStream inner = new ByteArrayInputStream(payload);
            // XXX: behavior changes with jdk11+ (no namespace) vs jdk8 (requires namespace)
            NodeList files = (NodeList) XML.xPath.evaluate("//*[local-name()='SignedDoc']/*[local-name()='DataFile']", new InputSource(inner), XPathConstants.NODESET);
            // Collect files
            Map<String, byte[]> result = new HashMap<>();
            for (int i = 0; i < files.getLength(); i++) {
                Node n = files.item(i);

                byte[] bytes = Base64.getMimeDecoder().decode(n.getTextContent());
                result.put(n.getAttributes().getNamedItem("Filename").getTextContent(), bytes);
            }
            return result;
        } catch (XPathExpressionException e) {
            throw new IOException("Could not extract payload", e);
        }
    }

}
