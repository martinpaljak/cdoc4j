package org.cdoc4j;

import org.apache.commons.io.IOUtils;
import org.esteid.hacker.FakeEstEIDCA;
import org.junit.*;
import org.junit.rules.TestName;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

public class TestEncryptDummy {

    static Path dummy;
    static X509Certificate ecc;
    static X509Certificate rsa;
    static boolean deleteOnExit = true;

    static {
        // Set up slf4j simple in a way that pleases us
        System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
        System.setProperty("org.slf4j.simpleLogger.levelInBrackets", "true");
        System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
    }

    @Rule
    public TestName name = new TestName();
    Path tmp;
    long start;

    @BeforeClass
    public static void resources() throws Exception {
        // Extract resource
        dummy = Files.createTempFile(null, null);
        IOUtils.copy(TestEncryptDummy.class.getResourceAsStream("/CDOC-A-101-7.pdf"), Files.newOutputStream(dummy));
        System.out.println("Input file sizes: " + (Files.size(dummy)));

        // Parse certificates
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        ecc = (X509Certificate) cf.generateCertificate(TestEncryptDummy.class.getResourceAsStream("/sk-auth-ecc.pem"));
        rsa = (X509Certificate) cf.generateCertificate(TestEncryptDummy.class.getResourceAsStream("/sk-auth.pem"));
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
        System.out.println(tmp);
        // Files.delete(tmp);
    }

    @Test
    public void testEncryptionV11ECC() throws Exception {
        CDOCBuilder creator = new CDOCBuilder(CDOC.Version.CDOC_V1_1);
        creator.addPath(dummy);
        creator.addRecipient(ecc);
        creator.setOutputStream(Files.newOutputStream(tmp));
        creator.build();
    }

    @Test
    public void testEncryptionV10RSA() throws Exception {
        CDOCBuilder creator = new CDOCBuilder(CDOC.Version.CDOC_V1_0);
        creator.addPath(dummy);
        creator.addRecipient(rsa);
        creator.setOutputStream(Files.newOutputStream(tmp));
        creator.build();
        // The EncryptionProperty thing fails
        Assert.assertFalse(XML.validate_cdoc(Files.readAllBytes(tmp)));
    }

    @Test
    public void testEncryptionV10RSA2Files() throws Exception {
        CDOCBuilder creator = new CDOCBuilder(CDOC.Version.CDOC_V1_0);
        creator.addPath(dummy);
        creator.addStream("test.txt", new ByteArrayInputStream("Hello, World!".getBytes(StandardCharsets.US_ASCII)));
        creator.addRecipient(rsa);
        creator.setOutputStream(Files.newOutputStream(tmp));
        creator.build();
        // The EncryptionProperty thing fails
        Assert.assertFalse(XML.validate_cdoc(Files.readAllBytes(tmp)));
    }

    @Test
    public void testEncryptionV20ECC() throws Exception {
        CDOCBuilder creator = new CDOCBuilder(CDOC.Version.CDOC_V2_0);
        creator.addPath(dummy);
        creator.addRecipient(ecc);
        creator.withValidation(true);
        creator.setOutputStream(Files.newOutputStream(tmp));
        creator.build();
    }

    @Test
    public void testEncryptionV20RSA() throws Exception {
        CDOCBuilder creator = new CDOCBuilder(CDOC.Version.CDOC_V2_0);
        creator.addPath(dummy);
        creator.addRecipient(rsa);
        creator.withValidation(true);
        creator.setOutputStream(Files.newOutputStream(tmp));
        creator.build();
    }

    @Test
    public void testEncryptionV20preshared() throws Exception {
        byte[] key = new byte[32];
        CDOC.random.nextBytes(key);
        CDOCBuilder creator = new CDOCBuilder(CDOC.Version.CDOC_V2_0);
        creator.addPath(dummy);
        creator.withTransportKey(key);
        creator.withValidation(true);
        creator.setOutputStream(Files.newOutputStream(tmp));
        //creator.build();

        creator.buildToStream(Files.newOutputStream(tmp));


        // Read back in
        Assert.assertTrue(CDOC.isCDOC(tmp.toFile()));
        Assert.assertFalse(CDOC.isCDOC(dummy.toFile()));

        CDOC cdoc = CDOC.open(tmp.toFile());
        Assert.assertEquals(0, cdoc.getRecipients().size());
        Assert.assertNotNull("Not pre-shared key", cdoc.preSharedKey());
        Map<String, byte[]> files = cdoc.getFiles(new SecretKeySpec(key, "AES"));
        Assert.assertEquals(1, files.size());
    }


    @Test(expected = IllegalArgumentException.class)
    public void testEncryptionV10ECC() throws Exception {
        CDOCBuilder creator = new CDOCBuilder(CDOC.Version.CDOC_V1_0);
        creator.addPath(dummy);
        creator.addRecipient(ecc);
        creator.setOutputStream(Files.newOutputStream(tmp));
        creator.build();
    }

    @Test
    public void testRecipientParsing() throws Exception {
        byte[] helloWorld = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        // Make dummy certificate
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair keyPair = kpg.generateKeyPair();

        // Make fake CA
        FakeEstEIDCA ca = new FakeEstEIDCA();
        File cafile = new File("fake.ca");
        if (cafile.exists()) {
            ca.loadFromFile(cafile);
        } else {
            ca.generate();
            ca.storeToFile(cafile);
        }

        X509Certificate c = ca.generateUserCertificate(keyPair.getPublic(), false, "Albert", "Einstein",
                "12345678901", "albert@example.com", new Date(), new Date());
        System.out.println("Generated " + c.getSubjectDN());
        // Create
        ByteArrayOutputStream mem = new ByteArrayOutputStream();
        CDOCBuilder creator = new CDOCBuilder(CDOC.Version.CDOC_V1_1);
        //creator.addPath(dummy);
        creator.addStream("test.txt", new ByteArrayInputStream(helloWorld));

        creator.addRecipient(ecc);
        creator.addRecipient(rsa);
        creator.addRecipient(c);
        //creator.withValidation(true);
        creator.setOutputStream(mem);
        creator.build();

        // Parse
        CDOC cdoc = CDOC.from(new ByteArrayInputStream(mem.toByteArray()));
        System.out.println("Detected version: " + cdoc.getVersion());
        Collection<Recipient> recipients = cdoc.getRecipients();
        Assert.assertEquals(3, recipients.size());
        for (Recipient r : recipients) {
            System.out.println("Recipient of type " + r.getType() + " name is " + r.getName());
            if (r.getName().contains("EINSTEIN")) {
                SecretKey dek = Decrypt.getKey(keyPair, r, cdoc.getAlgorithm());
                // Use DEK to decrypt
                ByteArrayOutputStream pload = new ByteArrayOutputStream();
                cdoc.decrypt(dek, pload);
                byte[] pdata = pload.toByteArray();
                Map<String, byte[]> files = Legacy.extractPayload(pdata);
                System.out.println(new String(files.get("test.txt"), "UTF-8"));
                Assert.assertTrue(Arrays.equals(helloWorld, files.get("test.txt")));

            }
        }
    }
}