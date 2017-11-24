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

import org.apache.commons.io.IOUtils;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class ContainerFile implements AutoCloseable {

    private final FileSystem fs;
    private final ZipFile zf;
    private String mimetype;
    private Manifest manifest;
    private Set<String> meta = new HashSet<>();  // Files that reside inside the ZIP in META-INF, thus are not part of the payload

    private ContainerFile(FileSystem fs, ZipFile zf) {
        this.fs = fs;
        this.zf = zf;
    }

    public static ContainerFile open(File f) throws IOException {
        return open(f.toPath());
    }

    public static ContainerFile open(Path p) throws IOException {
        // TODO: file internally
        URI uri = URI.create("jar:" + p.toUri());
        //System.out.println("Opening " + uri);
        Map<String, String> env = new HashMap<>();
        FileSystem fs = FileSystems.newFileSystem(uri, env);
        return new ContainerFile(fs, new ZipFile(p.toFile()));
    }

    public static ContainerFile create(Path p, String mimetype) throws IOException {
        return new ContainerFile(null, new ZipFile(p.toFile()));
    }

    public static String identify(File f) throws IOException {
        try (InputStream in = new FileInputStream(f)) {
            byte[] header = new byte[100];
            if (in.read(header, 0, 38) > 38) {
                System.out.println("PK: " + new String(header, 0, 2, StandardCharsets.US_ASCII.name()));
                System.out.println("mimetype: " + new String(header, 30, 8, StandardCharsets.US_ASCII.name()));
                //System.out.println("mimetype: " + HexUtils.bin2hex(Arrays.copyOfRange(header, 38, 60)));
            }
        }
        return null;
    }

    public Manifest getManifest() {
        return manifest;
    }

    public Set<String> getMetaFiles() {
        return meta;
    }

    public boolean check(List<String> errors) throws IOException {
        // SHOULD have comment
        if (zf.getComment() == null) {
            errors.add("Warning: No ZIP comment with MIME!");
        }

        // MUST have mimetype
        ZipEntry mimetype = zf.getEntry("mimetype");
        if (mimetype == null) {
            errors.add("Error: No mimetype file!");
            return false;
        }
        // Check for STORED
        if (mimetype.getMethod() != ZipEntry.STORED) {
            errors.add("Warning: mimetype is not STORED!");
        }
        // Check for extras
        if (mimetype.getExtra() != null) {
            errors.add("Warning: mimetype has extras!");
        }

        // Read mimetype entry
        try (BufferedReader bin = new BufferedReader(new InputStreamReader(zf.getInputStream(mimetype), StandardCharsets.US_ASCII))) {
            this.mimetype = bin.readLine();
            //debug.println("Info: mimetype=" + this.mimetype);
        }

        ZipEntry manifest = zf.getEntry("META-INF/manifest.xml");
        // Must have manifest
        if (manifest == null) {
            errors.add("Error: No manifest.xml!");
            return false;
        }

        // Check if manifest matches entries
        try (InputStream manifestin = zf.getInputStream(manifest)) {
            this.manifest = Manifest.fromStream(manifestin, this.mimetype);
        }

        // Check ZIP content
        Set<String> zip_entries = new HashSet<>();

        // Validate structure of zip
        for (ZipEntry e : Collections.list(zf.entries())) {
            if (e.getComment() != null) {
                //debug.println("Comment=" + e.getComment());
            }
            if (e.getExtra() != null) {
                //debug.println("Extra=" + HexUtils.bin2hex(e.getExtra()));
            }
            // OpenDocument 3.2. These should not be in manifest.xml XXX
            if (e.getName().equals("mimetype")) {
                continue;
            }
            if (e.isDirectory()) {
                //debug.println("Warning: folder entry in ZIP: " + e.getName());
                continue;
            }
            if (e.getName().startsWith("META-INF/")) {
                // manifest.xml is handled internally
                if (e.getName().equals("META-INF/manifest.xml")) {
                    continue;
                }
                // Other files are tracked
                meta.add(e.getName());
                continue;
            } else {
                // Payload, must be in manifest.xml
                zip_entries.add(e.getName());
            }
        }

        // Validate that payload files match.
        HashSet<String> mf_entries = new HashSet<>();
        for (ManifestEntry mfile : this.manifest.getFiles()) {
            mf_entries.add(mfile.path);
        }
        mf_entries.retainAll(zip_entries);
        if (mf_entries.size() != zip_entries.size()) {
            //debug.println("Error: Manifest does not match ZIP content." + mf_entries.size());
        }
        return true;
    }

    public byte[] get(String name) throws IOException {
        ZipEntry ze = zf.getEntry(name);
        if (ze == null)
            throw new IOException("No such file in the container: " + name);
        try (InputStream fin = zf.getInputStream(ze)) {
            return IOUtils.toByteArray(fin);
        }
    }

    public InputStream getStream(String name) throws IOException {
        return Files.newInputStream(fs.getPath(name));
    }

    public String getMimeType() {
        return mimetype;
    }

    @Override
    public void close() throws IOException {
        fs.close();
        zf.close();
    }
}
