package org.esteid.cdoc;

import javax.naming.NamingException;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;

public class CDOC {
    public static void encrypt(File to, List<File> files, List<X509Certificate> recipients) throws GeneralSecurityException, NamingException, IOException {
        // Any logic here?
        CDOCv1.encrypt(CDOCv1.VERSION.V1_1, to, files, recipients);
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
