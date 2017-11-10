import org.apache.commons.io.IOUtils;
import org.esteid.cdoc.CDOCv1;
import org.esteid.cdoc.CDOCv2;
import org.junit.*;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

@RunWith(Parameterized.class)

public class TestEncryptDummy {
    static Path dummy;

    static X509Certificate ecc;
    static X509Certificate rsa;

    static boolean deleteOnExit = true;
    @Rule
    public TestName name = new TestName();
    Path tmp;
    long start;

    @Parameterized.Parameters
    public static List<Object[]> data() {
        return Arrays.asList(new Object[10][0]);
    }

    @BeforeClass
    public static void resources() throws Exception {
        // Extract resource
        dummy = Files.createTempFile(null, null);
        IOUtils.copy(TestEncryptDummy.class.getResourceAsStream("CDOC-A-101-7.pdf"), Files.newOutputStream(dummy));
        //dummy = Paths.get("/Users/martin/10M.bin");
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
        System.out.println("File size " + Files.size(tmp) + " for " + name.getMethodName() + " in " + (System.currentTimeMillis() - start) + "ms");
        Files.delete(tmp);
    }

    @Test
    public void testEncryptionV11ECC() throws Exception {
        CDOCv1.encrypt(CDOCv1.VERSION.V1_1, tmp.toFile(), Arrays.asList(new File[]{dummy.toFile()}), Arrays.asList(new X509Certificate[]{ecc}));
    }

    @Test
    public void testEncryptionV10RSA() throws Exception {
        CDOCv1.encrypt(CDOCv1.VERSION.V1_0, tmp.toFile(), Arrays.asList(new File[]{dummy.toFile()}), Arrays.asList(new X509Certificate[]{rsa}));
    }

    @Test
    public void testEncryptionV20ECC() throws Exception {
        CDOCv2.encrypt(tmp.toFile(), Arrays.asList(new File[]{dummy.toFile()}), Arrays.asList(new X509Certificate[]{ecc}));
    }

    @Test
    public void testEncryptionV20RSA() throws Exception {
        CDOCv2.encrypt(tmp.toFile(), Arrays.asList(new File[]{dummy.toFile()}), Arrays.asList(new X509Certificate[]{rsa}));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptionV10ECC() throws Exception {
        CDOCv1.encrypt(CDOCv1.VERSION.V1_0, tmp.toFile(), Arrays.asList(new File[]{dummy.toFile()}), Arrays.asList(new X509Certificate[]{ecc}));
    }

}