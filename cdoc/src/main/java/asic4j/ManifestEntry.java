package asic4j;

// Convenience container for a single manifest entry.
// This means metadata about a file.

public class ManifestEntry {

    public String path;
    public long size; // -1 indicates "no size info"
    public String mimetype;
    public ManifestEntry(String path, String mimetype, long size) {
        this.path = path;
        this.mimetype = mimetype;
        this.size = size;
    }

    @Override
    public String toString() {
        return path + (mimetype.equals("") ? "" : ", " + mimetype) + (size != -1 ? ", " + size : "");
    }
}