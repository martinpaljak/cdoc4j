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
import asic4j.Manifest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

// Special stream that keeps count of written bytes
// and writes that to the ODF manifest.
public class CDOCZipOutputStream extends CloseShieldZipOutputStream {
    private static final Logger log = LoggerFactory.getLogger(CDOCZipOutputStream.class);


    private final Manifest mf;
    private final ZipOutputStream container;
    private final ByteArrayOutputStream payload;
    private final boolean privacy;
    private final Cipher cipher;

    // Cipher is initialized by caller
    public CDOCZipOutputStream(ZipOutputStream container, ByteArrayOutputStream payload, Cipher cipher, Manifest mf, boolean privacy) {
        super(payload, StandardCharsets.UTF_8);
        this.mf = mf;
        this.container = container;
        this.privacy = privacy;
        this.payload = payload;
        this.cipher = cipher;
    }


    @Override
    public void close() throws IOException {
        try {
            ZipEntry ze = new ZipEntry(CDOC.PAYLOAD_ZIP);
            if (privacy)
                Container.strip(ze);
            byte[] payloadbytes = payload.toByteArray();
            byte[] iv = cipher.getIV();
            byte[] cgram = cipher.doFinal(payloadbytes);

            container.putNextEntry(ze);
            // Write IV
            container.write(iv);
            container.write(cgram);
            // Close payload.zip entry
            container.closeEntry();
            container.flush();

            log.debug("Plaintext size: {}", payloadbytes.length);
            log.debug("Cryptogram size: {}", cgram.length);
            log.debug("payload.zip size: {} ", (iv.length + cgram.length));

            // Write the manifest with correct size
            mf.setFileSize(CDOC.PAYLOAD_ZIP, (iv.length + cgram.length));
            ZipEntry manifest = new ZipEntry(Manifest.MANIFEST_XML);
            if (privacy)
                manifest = Container.strip(manifest);

            container.putNextEntry(manifest);
            mf.toStream(container);
            container.closeEntry();
            // Finish with container
            container.flush();
            container.finish();
            container.close();
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed encryption", e);
        }
        //super.close();
    }
}
