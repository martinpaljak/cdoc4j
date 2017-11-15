package org.esteid.cdoc;

import javax.naming.NamingException;
import java.io.*;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CDOC {
    final static SecureRandom random;

    static {
        try {
            // See DMI_RANDOM_USED_ONLY_ONCE for reasoning
            random = SecureRandom.getInstanceStrong();
            random.nextBytes(new byte[2]); // seed and discard first 16 bits
        } catch (NoSuchAlgorithmException e) {
            throw new Error("Need to have SecureRandom for encryption!");
        }
    }

    public static void encrypt(File to, List<File> files, List<X509Certificate> recipients) throws GeneralSecurityException, NamingException, IOException {
        // TODO: Any logic here, depending on recipients?
        CDOCv1.encrypt(CDOCv1.VERSION.V1_1, to, files, recipients);
    }

    public static void encrypt(Path to, List<Path> paths, List<X509Certificate> recipients) throws GeneralSecurityException, NamingException, IOException {
        List<File> fl = new ArrayList<>();
        for (Path p: paths)
            fl.add(p.toFile());
        encrypt( to.toFile(), fl, recipients);
    }

    public static String getVersion() {
        String version = "unknown-development";
        try (InputStream versionfile = CDOC.class.getResourceAsStream("pro_version.txt")) {
            if (versionfile != null) {
                try (BufferedReader vinfo = new BufferedReader(new InputStreamReader(versionfile, "UTF-8"))) {
                    version = vinfo.readLine();
                }
            }
        } catch (IOException e) {
            version = "unknown-error";
        }
        return version;
    }
}
