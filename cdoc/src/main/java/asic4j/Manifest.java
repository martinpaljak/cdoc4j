package asic4j;

import org.esteid.cdoc.XML;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Manifest {
    private String mimetype; // mimetype of the package
    private List<ManifestEntry> files = new ArrayList<>(); // files listed in the manifest

    public Manifest(String mimetype) {
        this.mimetype = mimetype;
    }

    public static Manifest fromStream(InputStream in) throws IOException {
        return fromStream(in, null);
    }

    // TODO: get rid of System.err
    public static Manifest fromStream(InputStream in, String assumedMime) throws IOException {
        String packageMimeType = null;
        Document mf = XML.stream2dom(in);

        // TODO: possibly check against (RNG) schema?

        // Check version. We expect 1.2s
        String version = mf.getDocumentElement().getAttribute("manifest:version");
        if (version == null || version.equalsIgnoreCase("")) {
            System.err.println("Error: No manifest:version!");
            //return false;
        } else if (!version.equalsIgnoreCase("1.2")) {
            System.err.println("Error: manifest:version != 1.2");
            //return false;
        }

        List<ManifestEntry> files = new ArrayList<>();
        //NodeList files = mf.getDocumentElement().getChildNodes();
        for (Node n : XML.asList(mf.getDocumentElement().getElementsByTagName("manifest:file-entry"))) {
            String fullPath = n.getAttributes().getNamedItem("manifest:full-path").getTextContent();
            String mediaType = n.getAttributes().getNamedItem("manifest:media-type").getTextContent();
            long fileSize = -1;
            // Ignore package entry in manifest
            if (fullPath.equals("/")) {
                packageMimeType = mediaType;
                // But check the mimetype
                if (assumedMime != null) {
                    if (!mediaType.equals(assumedMime)) {
                        System.err.println("Error: mime type does not match expected: " + assumedMime + " vs " + mediaType);
                    }
                }
            } else {
                // File size is optional
                Node filesize = n.getAttributes().getNamedItem("manifest:size");
                if (filesize != null) {
                    // Add to container
                    fileSize = Long.valueOf(filesize.getTextContent());
                }
                ManifestEntry mfile = new ManifestEntry(fullPath, mediaType, fileSize);
                files.add(mfile);
            }
        }
        // Construct manifest.
        Manifest manifest = new Manifest(packageMimeType);
        for (ManifestEntry f : files) {
            manifest.addFile(f);
        }
        return manifest;
    }

    public String getMimeType() {
        return mimetype;
    }

    public Set<ManifestEntry> getFiles() {
        return new HashSet<>(files);
    }

    public ManifestEntry addFile(String path, String mimetype, long size) {
        ManifestEntry mf = new ManifestEntry(path, mimetype, size);
        files.add(mf);
        return mf;
    }

    public void addFile(ManifestEntry f) {
        files.add(f);
    }

    // Writes the constructed manifest as XML to the specified stream.
    public void toStream(OutputStream out) {
        // Construct the XML.
        Document manifest = XML.getDocument();
        Element root = manifest.createElement("manifest:manifest");
        root.setAttribute("xmlns:manifest", "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0");
        root.setAttribute("manifest:version", "1.2");
        manifest.appendChild(root);

        // Add package, if mimetype present
        if (mimetype != null) {
            Element pkg = manifest.createElement("manifest:file-entry");
            pkg.setAttribute("manifest:full-path", "/");
            pkg.setAttribute("manifest:media-type", this.mimetype);
            root.appendChild(pkg);
        }
        // Add all files
        for (ManifestEntry f : files) {
            // TODO: conditional ignorance of META-INF?
            if (f.path.startsWith("META-INF/")) {
                continue;
            }
            Element file = manifest.createElement("manifest:file-entry");
            file.setAttribute("manifest:full-path", f.path);
            file.setAttribute("manifest:media-type", f.mimetype);
            if (f.size != -1) {
                file.setAttribute("manifest:size", Long.toUnsignedString(f.size));
            }
            root.appendChild(file);
        }
        XML.dom2stream(manifest, out);
    }
}
