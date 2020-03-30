package org.cdoc4j;

import org.apache.commons.io.IOUtils;
import org.esteid.sk.FakeEstEIDCA;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static org.cdoc4j.CDOC.Version;


public class TestFullCycle {
    static FakeEstEIDCA ca;

    static {
        // Set up slf4j simple in a way that pleases us
        System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
        System.setProperty("org.slf4j.simpleLogger.levelInBrackets", "true");
        System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
    }

    byte[] helloWorld = "Hello, World!".getBytes(StandardCharsets.UTF_8);
    byte[] byeWorld = "Bye, World!".getBytes(StandardCharsets.UTF_8);
    String HELLONAME = "test1.txt";
    String BYENAME = "test2.txt";
    KeyPair ecckeypair;
    KeyPair rsakeypair;

    X509Certificate ecccertificate;
    X509Certificate rsacertificate;


    @BeforeClass
    public static void beforeClass() throws Exception {
        ca = new FakeEstEIDCA();
        File cafile = new File("fake.ca");
        if (cafile.exists()) {
            ca.loadFromFile(cafile);
        } else {
            ca.generate();
            ca.storeToFile(cafile);
        }
    }

    @Before
    public void before() throws Exception {
        // Generate fresh key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        ecckeypair = kpg.generateKeyPair();

        kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsakeypair = kpg.generateKeyPair();

        // Generate fresh certificates
        ecccertificate = ca.generateUserCertificate(ecckeypair.getPublic(), false, "Albert", "Einstein",
                "12345678901", "albert@example.com", new Date(), new Date());
        rsacertificate = ca.generateUserCertificate(rsakeypair.getPublic(), false, "Albert", "Einstein",
                "12345678902", "albert@example.com", new Date(), new Date());

    }

    @Test
    public void testV10RSA() throws Exception {
        // Create
        ByteArrayOutputStream mem = new ByteArrayOutputStream();
        CDOCBuilder creator = new CDOCBuilder(Version.CDOC_V1_0);
        creator.addStream(HELLONAME, new ByteArrayInputStream(helloWorld));
        creator.addRecipient(rsacertificate);
        creator.setOutputStream(mem);
        creator.build();


        CDOC cdoc = CDOC.from(new ByteArrayInputStream(mem.toByteArray()));
        SecretKey dek = Decrypt.getKey(rsakeypair, cdoc.getRecipients().get(0), cdoc.getAlgorithm());
        Map<String, byte[]> files = cdoc.getFiles(dek);
        Assert.assertTrue(Arrays.equals(helloWorld, files.get(HELLONAME)));
    }

    @Test
    public void testV11RSA() throws Exception {
        // Create
        ByteArrayOutputStream mem = new ByteArrayOutputStream();
        CDOCBuilder creator = new CDOCBuilder(Version.CDOC_V1_1);
        creator.addStream(HELLONAME, new ByteArrayInputStream(helloWorld));
        creator.addRecipient(rsacertificate);
        creator.setOutputStream(mem);
        creator.build();


        CDOC cdoc = CDOC.from(new ByteArrayInputStream(mem.toByteArray()));
        Assert.assertEquals(1, cdoc.getRecipients().size());
        SecretKey dek = Decrypt.getKey(rsakeypair, cdoc.getRecipients().get(0), cdoc.getAlgorithm());
        Map<String, byte[]> files = cdoc.getFiles(dek);
        Assert.assertEquals(1, files.size());
        Assert.assertTrue(Arrays.equals(helloWorld, files.get(HELLONAME)));
    }

    @Test
    public void testV11ECC() throws Exception {
        // Create
        ByteArrayOutputStream mem = new ByteArrayOutputStream();
        CDOCBuilder creator = new CDOCBuilder(Version.CDOC_V1_1);
        creator.addStream(HELLONAME, new ByteArrayInputStream(helloWorld));
        creator.addStream(BYENAME, new ByteArrayInputStream(byeWorld));

        creator.addRecipient(ecccertificate);
        creator.setOutputStream(mem);
        creator.build();


        CDOC cdoc = CDOC.from(new ByteArrayInputStream(mem.toByteArray()));
        Assert.assertEquals(1, cdoc.getRecipients().size());
        SecretKey dek = Decrypt.getKey(ecckeypair, cdoc.getRecipients().get(0), cdoc.getAlgorithm());
        Map<String, byte[]> files = cdoc.getFiles(dek);
        Assert.assertEquals(2, files.size());
        Assert.assertTrue(Arrays.equals(helloWorld, files.get(HELLONAME)));
    }


    @Test
    public void testV11Combined() throws Exception {
        // Create
        ByteArrayOutputStream mem = new ByteArrayOutputStream();
        CDOCBuilder creator = new CDOCBuilder(Version.CDOC_V1_1);
        creator.addStream(HELLONAME, new ByteArrayInputStream(helloWorld));
        creator.addStream(BYENAME, new ByteArrayInputStream(byeWorld));
        creator.addRecipient(ecccertificate);
        creator.addRecipient(rsacertificate);
        creator.setOutputStream(mem);
        creator.build();


        CDOC cdoc = CDOC.from(new ByteArrayInputStream(mem.toByteArray()));
        Assert.assertEquals(2, cdoc.getRecipients().size());
        SecretKey dek = Decrypt.getKey(ecckeypair, cdoc.getRecipients().get(0), cdoc.getAlgorithm());
        Map<String, byte[]> files = cdoc.getFiles(dek);
        Assert.assertEquals(2, files.size());
        Assert.assertTrue(Arrays.equals(helloWorld, files.get(HELLONAME)));

        dek = Decrypt.getKey(rsakeypair, cdoc.getRecipients().get(1), cdoc.getAlgorithm());
        files = cdoc.getFiles(dek);
        Assert.assertEquals(2, files.size());
        Assert.assertTrue(Arrays.equals(byeWorld, files.get(BYENAME)));

    }


    @Test
    public void testV20RSA() throws Exception {
        // Create
        ByteArrayOutputStream mem = new ByteArrayOutputStream();
        CDOCBuilder creator = new CDOCBuilder(Version.CDOC_V2_0);
        creator.addStream(HELLONAME, new ByteArrayInputStream(helloWorld));
        creator.addRecipient(rsacertificate);
        creator.withValidation(true);
        creator.setOutputStream(mem);
        creator.build();

        CDOC cdoc = CDOC.from(new ByteArrayInputStream(mem.toByteArray()));
        Assert.assertEquals(1, cdoc.getRecipients().size());
        SecretKey dek = Decrypt.getKey(rsakeypair, cdoc.getRecipients().get(0), cdoc.getAlgorithm());
        Map<String, byte[]> files = cdoc.getFiles(dek);
        Assert.assertEquals(1, files.size());
        Assert.assertTrue(Arrays.equals(helloWorld, files.get(HELLONAME)));
    }

    @Test
    public void testV20Combined() throws Exception {
        // Create
        ByteArrayOutputStream mem = new ByteArrayOutputStream();
        CDOCBuilder creator = CDOC.builder().setVersion(Version.CDOC_V2_0);
        creator.addStream(HELLONAME, new ByteArrayInputStream(helloWorld));
        creator.addStream(BYENAME, new ByteArrayInputStream(byeWorld));

        creator.addRecipient(rsacertificate);
        creator.addRecipient(ecccertificate);

        creator.withValidation(true);
        creator.setOutputStream(mem);
        creator.build();

        CDOC cdoc = CDOC.from(new ByteArrayInputStream(mem.toByteArray()));
        Assert.assertEquals(2, cdoc.getRecipients().size());
        SecretKey dek = Decrypt.getKey(rsakeypair, cdoc.getRecipients().get(0), cdoc.getAlgorithm());
        Map<String, byte[]> files = cdoc.getFiles(dek);
        Assert.assertEquals(2, files.size());
        Assert.assertTrue(Arrays.equals(helloWorld, files.get(HELLONAME)));
        dek = Decrypt.getKey(ecckeypair, cdoc.getRecipients().get(1), cdoc.getAlgorithm());
        // This will not work with a stream backed reader without caching
        files = cdoc.getFiles(dek);
        Assert.assertEquals(2, files.size());
        Assert.assertTrue(Arrays.equals(byeWorld, files.get(BYENAME)));
    }


    @Test
    public void testZipOutputStream() throws Exception {
        // Create
        ByteArrayOutputStream mem = new ByteArrayOutputStream();
        CDOCBuilder creator = new CDOCBuilder(Version.CDOC_V2_0);
        creator.addRecipient(ecccertificate);
        creator.setOutputStream(mem);
        creator.withPrivacy(true);
        creator.withValidation(true);
        try (ZipOutputStream zos = creator.buildZipOutputStream()) {
            zos.putNextEntry(new ZipEntry(HELLONAME));
            zos.write(helloWorld);
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry(BYENAME));
            zos.write(byeWorld);
            zos.closeEntry();
        }

        CDOC cdoc = CDOC.from(new ByteArrayInputStream(mem.toByteArray()));
        Assert.assertEquals(1, cdoc.getRecipients().size());
        SecretKey dek = Decrypt.getKey(ecckeypair, cdoc.getRecipients().get(0), cdoc.getAlgorithm());
        Map<String, byte[]> files = cdoc.getFiles(dek);
        Assert.assertEquals(2, files.size());
        Assert.assertTrue(Arrays.equals(helloWorld, files.get(HELLONAME)));
        Assert.assertTrue(Arrays.equals(byeWorld, files.get(BYENAME)));
    }


    @Test
    public void testZipInputStream() throws Exception {
        // Use a static key
        byte[] key = new byte[32];
        CDOC.random.nextBytes(key);

        // Create
        ByteArrayOutputStream mem = new ByteArrayOutputStream();
        CDOCBuilder creator = new CDOCBuilder(Version.CDOC_V2_0);
        creator.addRecipient(ecccertificate);
        creator.addRecipient(rsacertificate);
        creator.setOutputStream(mem);
        creator.withTransportKey(key);
        try (ZipOutputStream zos = creator.buildZipOutputStream()) {
            zos.putNextEntry(new ZipEntry(HELLONAME));
            zos.write(helloWorld);
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry(BYENAME));
            zos.write(byeWorld);
            zos.closeEntry();
        }

        CDOC cdoc = CDOC.from(new ByteArrayInputStream(mem.toByteArray()));

        ZipInputStream zin = cdoc.getZipInputStream(new SecretKeySpec(key, "AES"));
        ZipEntry entry;
        while ((entry = zin.getNextEntry()) != null) {
            byte[] fv = IOUtils.toByteArray(zin);
            if (entry.getName().equals(HELLONAME))
                Assert.assertTrue(Arrays.equals(helloWorld, fv));
            if (entry.getName().equals(BYENAME))
                Assert.assertTrue(Arrays.equals(byeWorld, fv));
        }
    }
}
