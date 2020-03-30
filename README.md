# cdoc4j · [![Build Status](https://github.com/martinpaljak/cdoc4j/workflows/Release%20CI/badge.svg)](https://github.com/martinpaljak/cdoc4j/actions)  [![Release](	https://img.shields.io/github/release/martinpaljak/cdoc4j/all.svg)](https://github.com/martinpaljak/cdoc4j/releases) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.martinpaljak/cdoc4j/badge.svg)](https://mvnrepository.com/artifact/com.github.martinpaljak/cdoc4j) [![Javadocs](https://www.javadoc.io/badge/com.github.martinpaljak/cdoc4j.svg)](https://www.javadoc.io/doc/com.github.martinpaljak/cdoc4j) [![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/martinpaljak/cdoc4j/blob/master/LICENSE)

Small Java library for handling CDOC encryption format, with Elliptic Curve support ("CDOC 1.1 amendment").

For working with CDOC files from the command line, use the [cdoc utility](https://github.com/martinpaljak/cdoc).

### Supported formats
- [CDOC 1.0](https://github.com/martinpaljak/cdoc/wiki/CDOC-1.0): AES-128 CBC, *RSA recipients only*, XML base64 container (supported by [@open-eid](https://github.com/open-eid) software)
- **[CDOC 1.1](https://github.com/martinpaljak/cdoc4j/blob/master/docs/CDOC-A-101-7.pdf) (default):** AES-256 GCM, RSA and ECC recipients, XML base64 container (supported _soon_ by [@open-eid](https://github.com/open-eid) software)
- [CDOC 2.0](FORMAT.md): AES-256 GCM, RSA and ECC recipients, ZIP container (_at least_ 30%, usually 50% smaller files compared to XML, not (yet) supported by @open-eid software)

----

- Include dependency
```xml
<dependency>
    <groupId>com.github.martinpaljak</groupId>
    <artifactId>cdoc4j</artifactId>
    <version>0.0.8</version>
</dependency>
```
- **When using Oracle Java, make sure you have ["Unlimited Strength Jurisdiction Policy Files"](https://github.com/martinpaljak/cdoc/wiki/UnlimitedCrypto) installed!**
- Get coding!

## Creating CDOC files
```java
import org.cdoc4j.CDOCBuilder;
import static org.cdoc4j.CDOC.VERSION.CDOC_V2_0;

// 0. Create the builder
CDOCBuilder builder = CDOC.builder();
// Override default CDOC 1.1 version
builder.setVersion(CDOC_V2_0);

// 1. Where to write the output
builder.setOutputStream(new FileOutputStream("output.cdoc"));

// 2. Set recipients
X509Certificate cert = ...
builder.addRecipient(cert);

// 3. For legacy XML containers, add files via any of the following methods
builder.addStream("test1.txt", new URL("http://www.example.com/test1.txt")); // or ByteArrayInputStream
builder.addFile(new File("test2.txt"));
builder.addPath(Paths.get("test3.txt"));
builder.build(); // Writes it to output stream
builder.buildToStream(new FileOutputStream("otherfile.cdoc"));
```

## Opening CDOC files
```java
import CDOC;

// 1. Either from a file
CDOC cdoc = CDOC.open(new File("test.cdoc"));

// 2. Or from an InputStream
InputStream input = new URL("http://example.com/sample.cdoc").openStream();
CDOC cdoc = CDOC.from(input);

// 3. Once the file has been opened, get recipients 
List<Recipient> recipients = cdoc.getRecipients();

// 4. Information in a Recipient object allows to construct the transport key for decryption
KeyPair kp = ...
SecretKey key = Decrypt.getKey(kp, recipients.get(0));

// 5. Knowing the transport key allows to access the encrypted files
Map<String, byte[]> files = cdoc.getFiles(key); // Can consume a lot of memory with large files
```

## ~~CDOC 2.0 and streams~~ (Work in Progress)
CDOC 2.0 is designed to be more resource efficient and flexible than CDOC 1.x. CDOC 2.0 is a standard ODF ZIP container with an inner ZIP file, which allows to use standard Java [ZipInputStream](https://docs.oracle.com/javase/8/docs/api/java/util/zip/ZipInputStream.html)/[ZipOutputStream](https://docs.oracle.com/javase/8/docs/api/java/util/zip/ZipOutputStream.html) interfaces. This way you can easily encrypt and decrypt files with sizes in several gigabytes without running out of memory.

```java
// To open the payload as a ZipInputStream
ZipInputStream zip = cdoc.getZipInputStream(key);

// To add files via ZipOutputStream
ZipOutputStream zip = CDOC.builder(CDOC_V2_0).addRecipient(...).buildZipOutputStream();
zip.putNextEntry(new ZipEntry("test.txt"));
IOUtils.copy(new InputSream(...), zip);
zip.closeEntry();
zip.close();
```

## Notes and caveats
* CDOC 1.X uses XML and in-memory processing of Base64 data, which requires a lot of memory. Thus it is advisable to only encrypt small files (in the range of 1M..100M, not 100M..1G) into v1.X formats and to make sure that enough memory is available to the JVM (`-Xmx8g`)

## Dependencies
- [BouncyCastle](https://www.bouncycastle.org) (MIT)
- [Apache Commons IO](https://commons.apache.org/io/) (Apache)
- [slf4j](https://www.slf4j.org/) (MIT)

