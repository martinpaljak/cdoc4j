import asic4j.ContainerFile;
import org.apache.commons.io.IOUtils;
import org.esteid.cdoc.CDOCv1;
import org.esteid.cdoc.CDOCv2;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TestEncryptDummy {
    static Path dummy;

    static X509Certificate ecc;
    static X509Certificate rsa;

    static boolean deleteOnExit = true;

    Path tmp;
    long start;

    @BeforeClass
    public static void resources() throws Exception {
        // Extract resource
        dummy = Files.createTempFile(null, null);
        IOUtils.copy(TestEncryptDummy.class.getResourceAsStream("CDOC-A-101-7.pdf"), Files.newOutputStream(dummy));
        System.out.println("Input file size: " + Files.size(dummy));
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        ecc = (X509Certificate) cf.generateCertificate(TestEncryptDummy.class.getResourceAsStream("sk-auth-ecc.pem"));
        rsa = (X509Certificate) cf.generateCertificate(TestEncryptDummy.class.getResourceAsStream("sk-auth.pem"));
    }

    @Before
    public void prepare() throws Exception {
        tmp = Files.createTempFile(null, null);
        if (deleteOnExit)
            tmp.toFile().deleteOnExit();
        start = System.currentTimeMillis();
    }

    @After
    public void measure() throws Exception {
        System.out.println("Created file of size " + Files.size(tmp) + " in " + (System.currentTimeMillis() - start) + "ms");
        Files.delete(tmp);
    }

    @Test
    public void testEncryptionV1ECC() throws Exception {
        CDOCv1.encrypt(CDOCv1.VERSION.V1_1, tmp.toFile(), Arrays.asList(new File[]{dummy.toFile()}), Arrays.asList(new X509Certificate[]{ecc}));
        System.out.println("V1ECC file size: " + Files.size(tmp));
    }


    @Test
    public void testEncryptionV10RSA() throws Exception {
        CDOCv1.encrypt(CDOCv1.VERSION.V1_0, tmp.toFile(), Arrays.asList(new File[]{dummy.toFile()}), Arrays.asList(new X509Certificate[]{rsa}));
        System.out.println("V1RSA file size: " + Files.size(tmp));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptionV10ECC() throws Exception {
        CDOCv1.encrypt(CDOCv1.VERSION.V1_0, tmp.toFile(), Arrays.asList(new File[]{dummy.toFile()}), Arrays.asList(new X509Certificate[]{ecc}));
    }


    @Test
    public void testEncryptionV2ECC() throws Exception {

        CDOCv2.encrypt(tmp.toFile(), Arrays.asList(new File[]{dummy.toFile()}), Arrays.asList(new X509Certificate[]{ecc}));

        System.out.println("V2ECC file size: " + Files.size(tmp));

        ContainerFile ff = ContainerFile.open(tmp);
        List<String> errs = new ArrayList<>();
        ff.check(errs);
        if (errs.size() > 0)
            System.out.println(errs);
    }

    @Test
    public void testEncryptionV2RSA() throws Exception {

        CDOCv2.encrypt(tmp.toFile(), Arrays.asList(new File[]{dummy.toFile()}), Arrays.asList(new X509Certificate[]{rsa}));

        System.out.println("V2RSA file size: " + Files.size(tmp));

        ContainerFile ff = ContainerFile.open(tmp);
        List<String> errs = new ArrayList<>();
        ff.check(errs);
        if (errs.size() > 0)
            System.out.println(errs);
    }
}