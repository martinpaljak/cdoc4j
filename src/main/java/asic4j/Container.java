package asic4j;

import org.esteid.cdoc.CDOC;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

// Class for OpenDocument ZIP container
// Only for writing at the moment.
public class Container {
    // Overall manifest
    Manifest mf;

    // Payload files
    private Map<ManifestEntry, byte[]> files;

    // META-INF files
    private Map<String, byte[]> metas;

    public Container(String mimetype) {
        mf = new Manifest(mimetype);
        files = new HashMap<>();
        metas = new HashMap<>();
    }

    public void put(Path p, String mimetype) throws IOException {
        Path fn = p.getFileName();
        if (fn == null) {
            throw new IllegalArgumentException("Path must encode a file!");
        }
        put(fn.toString(), mimetype, Files.readAllBytes(p));
    }

    public void put(String filename, String mimetype, byte[] data) {
        ManifestEntry newmf = mf.addFile(filename, mimetype, data.length);
        files.put(newmf, data);
    }

    public void put_meta(String fname, byte[] data) {
        // Assumes a META-INF
        metas.put(fname, data);
    }

    /**
     * It is the responsibility of the caller to close the output stream.
     *
     * @param out
     * @throws IOException
     */
    public void write(OutputStream out) throws IOException {
        ZipOutputStream zos = new ZipOutputStream(out, StandardCharsets.UTF_8);
        // Get mimetype
        String mimetype = mf.getMimeType();
        zos.setComment("mimetype=" + mimetype);

        // mimetype
        ZipEntry mt = new ZipEntry("mimetype");
        mt.setMethod(ZipEntry.STORED);
        mt.setSize(mimetype.getBytes(StandardCharsets.US_ASCII).length);
        CRC32 crc32 = new CRC32();
        crc32.update(mimetype.getBytes(StandardCharsets.US_ASCII));
        mt.setCrc(crc32.getValue());
        zos.putNextEntry(mt);
        zos.write(mimetype.getBytes(StandardCharsets.US_ASCII));
        zos.closeEntry();

        // manifest
        ZipEntry zmf = new ZipEntry("META-INF/manifest.xml");
        zmf.setComment("asic4j/" + CDOC.getVersion());
        zos.putNextEntry(zmf);
        mf.toStream(zos);
        zos.closeEntry();

        // Meta files
        for (Map.Entry<String, byte[]> fentry : metas.entrySet()) {
            ZipEntry ze = new ZipEntry(fentry.getKey());
            ze.setMethod(ZipEntry.DEFLATED);
            ze.setSize(fentry.getValue().length);
            zos.putNextEntry(ze);
            zos.write(fentry.getValue());
            zos.closeEntry();
        }

        // Payload Files themselves
        for (Map.Entry<ManifestEntry, byte[]> fentry : files.entrySet()) {
            ZipEntry ze = new ZipEntry(fentry.getKey().path);
            ze.setMethod(ZipEntry.DEFLATED);
            ze.setSize(fentry.getKey().size); // XXX: or value.size ?
            zos.putNextEntry(ze);
            zos.write(fentry.getValue());
            zos.closeEntry();
        }

        // Done
        zos.finish();
    }
}
