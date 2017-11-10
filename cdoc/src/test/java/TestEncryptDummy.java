import asic4j.ContainerFile;
import org.esteid.cdoc.CDOCv1;
import org.esteid.cdoc.CDOCv2;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TestEncryptDummy {
    @Test
    public void testEncryptionV1() throws Exception {
        File tmp = File.createTempFile("blah", "bluh");
        tmp.deleteOnExit();

        File data = new File("/etc/hosts");

        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate recipient = (X509Certificate) cf.generateCertificate(getClass().getResourceAsStream("sk-auth-ecc.pem"));

        CDOCv1.encrypt(CDOCv1.VERSION.V1_1, tmp, Arrays.asList(new File[]{data}), Arrays.asList(new X509Certificate[]{recipient}));

        // Read back in
        String f = new String(Files.readAllBytes(tmp.toPath()));
        System.out.println(f);
    }


    @Test
    public void testEncryptionV10RSA() throws Exception {
        File tmp = File.createTempFile("plix", "plax");
        tmp.deleteOnExit();

        File data = new File("/etc/hosts");

        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate recipient = (X509Certificate) cf.generateCertificate(getClass().getResourceAsStream("sk-auth.pem"));

        CDOCv1.encrypt(CDOCv1.VERSION.V1_0, tmp, Arrays.asList(new File[]{data}), Arrays.asList(new X509Certificate[]{recipient}));

        // Read back in
        String f = new String(Files.readAllBytes(tmp.toPath()));
        System.out.println(f);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptionV10ECC() throws Exception {
        File tmp = File.createTempFile("plix", "plax");
        tmp.deleteOnExit();

        File data = new File("/etc/hosts");

        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate recipient = (X509Certificate) cf.generateCertificate(getClass().getResourceAsStream("sk-auth-ecc.pem"));

        CDOCv1.encrypt(CDOCv1.VERSION.V1_0, tmp, Arrays.asList(new File[]{data}), Arrays.asList(new X509Certificate[]{recipient}));

        // Read back in
        String f = new String(Files.readAllBytes(tmp.toPath()));
        System.out.println(f);
    }


    @Test
    public void testEncryptionV2() throws Exception {
        File tmp = File.createTempFile("plix", "plax");
        tmp.deleteOnExit();

        File data = new File("/etc/hosts");

        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate recipient = (X509Certificate) cf.generateCertificate(getClass().getResourceAsStream("sk-auth-ecc.pem"));

        CDOCv2.encrypt(tmp, Arrays.asList(new File[]{data}), Arrays.asList(new X509Certificate[]{recipient}));

        ContainerFile ff = ContainerFile.open(tmp);
        List<String> errs = new ArrayList<>();
        ff.check(errs);
        System.out.println(errs);
    }
}