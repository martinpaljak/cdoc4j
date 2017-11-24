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
package asic4j;

import org.cdoc4j.CDOC;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

// Class for OpenDocument ZIP container
// Only for writing at the moment.
public final class Container {
    // Overall manifest
    private Manifest mf;
    private boolean privacy = true;
    private ZipOutputStream zos;

    // Payload files
    private Map<ManifestEntry, byte[]> files;

    // META-INF files
    private Map<String, byte[]> metas;

    public Container(String mimetype, OutputStream out, boolean privacy) {
        mf = Manifest.create(mimetype);
        this.zos = new ZipOutputStream(out, StandardCharsets.UTF_8);
        files = new HashMap<>();
        metas = new HashMap<>();
        this.privacy = privacy;
    }

    // Remove tiem metadata, to not leak times without decrypting
    public static ZipEntry strip(ZipEntry e) {
        e.setCreationTime(FileTime.fromMillis(0));
        e.setLastAccessTime(FileTime.fromMillis(0));
        e.setLastModifiedTime(FileTime.fromMillis(0));
        return e;
    }

    public Manifest getManifest() {
        return mf;
    }

    public void put(Path p, String mimetype) throws IOException {
        Path fn = p.getFileName();
        if (fn == null) {
            throw new IllegalArgumentException("Path must encode a file!");
        }
        put(fn.toString(), mimetype, Files.readAllBytes(p));
    }

    public void put(String filename, String mimetype, byte[] data) {
        ManifestEntry mfe = new ManifestEntry(filename, mimetype, data.length);
        mf.addFile(mfe);
        files.put(mfe, data);
    }

    public void declare(String filename, String mimetype, long length) {
        ManifestEntry mfe = new ManifestEntry(filename, mimetype, length);
        mf.addFile(mfe);
    }

    public void put_meta(String fname, byte[] data) {
        // Assumes a META-INF
        metas.put(fname, data);
    }

    public void writeHeader() throws IOException {
        // mimetype commend
        String mimetype = mf.getMimeType();
        zos.setComment("mimetype=" + mimetype);

        // mimetype as first file
        ZipEntry mt = new ZipEntry("mimetype");
        mt.setMethod(ZipEntry.STORED);
        mt.setSize(mimetype.getBytes(StandardCharsets.US_ASCII).length);
        CRC32 crc32 = new CRC32();
        crc32.update(mimetype.getBytes(StandardCharsets.US_ASCII));
        mt.setCrc(crc32.getValue());
        if (privacy)
            mt = strip(mt);
        zos.putNextEntry(mt);
        zos.write(mimetype.getBytes(StandardCharsets.US_ASCII));
        zos.closeEntry();
    }

    public void writeManifest() throws IOException {
        ZipEntry zmf = new ZipEntry("META-INF/manifest.xml");
        if (!privacy)
            zmf.setComment("asic4j/" + CDOC.getLibraryVersion());
        if (privacy)
            zmf = strip(zmf);
        zos.putNextEntry(zmf);
        mf.toStream(zos);
        zos.closeEntry();
    }

    public void writeMetas() throws IOException {
        // Meta files
        for (Map.Entry<String, byte[]> fentry : metas.entrySet()) {
            ZipEntry ze = new ZipEntry(fentry.getKey());
            ze.setMethod(ZipEntry.DEFLATED);
            ze.setSize(fentry.getValue().length);
            if (privacy)
                ze = strip(ze);
            zos.putNextEntry(ze);
            zos.write(fentry.getValue());
            zos.closeEntry();
        }
    }

    public ZipOutputStream getZipOutputStream() {
        return zos;
    }

    public void write() throws IOException {
        writeHeader();
        writeMetas();
        // Payload files
        for (Map.Entry<ManifestEntry, byte[]> fentry : files.entrySet()) {
            ZipEntry ze = new ZipEntry(fentry.getKey().path);
            ze.setMethod(ZipEntry.DEFLATED);
            ze.setSize(fentry.getKey().size); // XXX: or value.size ?
            if (privacy)
                ze = strip(ze);
            zos.putNextEntry(ze);
            zos.write(fentry.getValue());
            zos.closeEntry();
        }
        writeManifest();

        // Done
        zos.finish();
    }
}
