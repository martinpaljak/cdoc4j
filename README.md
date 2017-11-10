# CDOC

Small Java library for _creating_ encrypted CDOC files, with Elliptic Curve support ("CDOC 1.1?").

Usage:

```java
// 1. Where to write the output
File output = File.createTempFile("foobar", null);

// 2. Which files to encrypt
List<File> files = new ArrayList<>();
files.add(new File("/some/file"));
files.add(new File("/some/other/file"));

// 3. To whom to encrypt
List<X509Certificate> recipients = new ArrayList<>();
recipients.add();

// 4. Encrypt.
CDOC.encrypt(output, files, recipients);

// 5. output is now an encrypted file
```

Supported formats:
- CDOC 1.0: AES-128 CBC, *RSA recipients only*, XML base64 container (supported by [@open-eid](https://github.com/open-eid) software)
- **CDOC 1.1 (default):** AES-256 GCM, RSA and ECC recipients, XML base64 container (supported by [@open-eid](https://github.com/open-eid) software)
- CDOC 2.0: AES-256 GCM, RSA and ECC recipients, ZIP container (30 to 50 percent smaller files compared to XML, not (yet) supported by @open-eid software) 
