# CDOC 2.0 specification
> DRAFT v0.4 07-11-2017, martin.paljak@eesti.ee

## Introduction
CDOC is a file format for storing encrypted data together with data for/about intended recipients.

The main goals of CDOC v2.0 format over [CDOC v1.0](https://github.com/martinpaljak/idcrypt/wiki/CDOC-1.0) (and CDOC-1.1) are resource-effectiveness when processing containers (less XML parsing), compatibility with ASiC containers (based on OpenDocument v1.2 ZIP packages) and general alignment with newer and future algorithms.

It defines and clarifies the subset of relevant standards and provides guidelines and requirements for compliant implementations.

## References
- [OpenDocument v1.2 part 3: packages](https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html)
- [ETSI EN 319 162-1 V1.1.1 (ASiC baseline containers)](http://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf)
- [ETSI EN 319 162-2 V1.1.1 (Additional ASiC containers)](http://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf)
- [XML Encryption Syntax and Processing](https://www.w3.org/TR/xmlenc-core/)
- [XML Encryption Syntax and Processing Version 1.1](https://www.w3.org/TR/xmlenc-core1/)
- [XML Signature Syntax and Processing (Second Edition)](https://www.w3.org/TR/xmldsig-core/)
- [RFC 6931](https://tools.ietf.org/html/rfc6931)


## Overview
CDOC v2.0 files are essentially [OpenDocument v1.2](https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html) containers, conforming to [OpenDocument Extended Package](https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html#__RefHeading__752793_826425813). The mime type is `application/x-cryptodoc` and recommended extension `.cdoc`.

Information about transport keys, recipients etc is stored in `META-INF/recipients.xml` which conforms to [XML-ENC v1.1](https://www.w3.org/TR/xmlenc-core1/) standard and schema.

This arrangement is comparable to ASiC-S ODF containers.

## Container layout
Overall ZIP container of `example.cdoc`:
```
example.cdoc
   |-- mimetype
   |-- META-INF
   |   |-- manifest.xml
   |   `-- recipients.xml
   `-- payload.zip
```

`manifest.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest manifest:version="1.2" xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
    <manifest:file-entry manifest:full-path="/" manifest:media-type="application/x-cryptodoc"/>
    <manifest:file-entry manifest:full-path="payload.zip"
        manifest:media-type="application/zip" manifest:size="165"/>
</manifest:manifest>
```

## Package requirements
* The mime type of CDOC v2.0 is `application/x-cryptodoc`
* The file extension SHOULD be `.cdoc`
* The mime type SHOULD be present in Zip comment (ASiC 6.2.1 clause 3)
* The `mimetype` file MUST be present, together with the `media-type` manifest element for the package (See [OpenDocument: 3.3 MIME Media Type](https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html#MIME_type_stream))
* The format MAY be used with ZIP64 extension.
* Storage of encrypted files MUST follow the rules laid down in [OpenDocument section 3.4.1](https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html#__RefHeading__752813_826425813), regarding actual payload size in manifest.

## Payload requirements
* Multiple files MUST be encapsulated in a ZIP container before encryption, which implementations SHOULD display inline after decryption (ASiC baseline B.1.3)
* Payload ZIP encapsulation MAY be used for a single file, to hide original file name
* The name of the encapsulated ZIP file SHOULD be `payload.zip`
* The payload of the package MUST NOT contain subfolders. All encrypted files MUST reside in the root folder.

## Implementation requirements
* Implementations SHOULD support ZIP64 for files larger than 4GB
  * Lack of support for ZIP64 MUST be documented in accompanying documentation
* Implementations SHOULD allow to decrypt files which lack proper MIME information
* Formatting of encrypted files (IV, padding, authentication tags etc) MUST conform to XML-ENC (XML-ENC 5.2: Block Encryption Algorithms)

## ID-card profile

The use with Estonian ID-card defaults to:

### RSA keys
* RSA 2048 PKCS#1 v1.5 for transport key encryption
* AES-GCM 256 for payload encryption
* `META-INF/recipients.xml` snippet:

```
<EncryptedData>
  <EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#aes256-gcm'/>
  <EncryptedKey>
    <EncryptionMethod Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-1_5'/>
    ...
  </EncryptedKey>
  ...
</EncryptedData>
```

### ECC keys
* P-384 (secp384r1) ECDH-ES with Concat KDF and AES KeyWrap for transport key encryption
* AES-GCM 256 for payload encryption
* `META-INF/recipients.xml` snippet:

```
<EncryptedData>
    <EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
    <KeyInfo>
        <EncryptedKey Recipient="...">
            <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes256"/>
            <KeyInfo>
                <AgreementMethod Algorithm="http://www.w3.org/2009/xmlenc11#ECDH-ES">
                    <KeyDerivationMethod Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF">
                        <ConcatKDFParams AlgorithmID="..." PartyUInfo="..." PartyVInfo="...">
                            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha384"/>
                        </ConcatKDFParams>
                    </KeyDerivationMethod>
                    <OriginatorKeyInfo>
                        <KeyValue>
                            <ECKeyValue>
                                <NamedCurve URI="urn:oid:1.3.132.0.34"/>
                                <PublicKey>...</PublicKey>
                            </ECKeyValue>
                        </KeyValue>
                    </OriginatorKeyInfo>
                    <RecipientKeyInfo>
                        <X509Data>
                            <X509Certificate>...</ds:X509Certificate>
                        </X509Data>
                    </RecipientKeyInfo>
                </AgreementMethod>
            </KeyInfo>
            <CipherData>
                <CipherValue>...</CipherValue>
            </CipherData>
        </EncryptedKey>
    </KeyInfo>
    ...
</EncryptedData>    
```

## Samples of `META-INF/recipients.xml`

### Encryption of a single file with a pre-shared key
`READMe.txt` is encrypted with AES-GCM 256 and the key itself is supposedly known to the receiver via out of band means

```
<EncryptedData xmlns='http://www.w3.org/2001/04/xmlenc#' MimeType="text/plain" />
   <EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#aes256-gcm'/>
   <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
     <ds:KeyName>The pre-shared key</ds:KeyName>
   </ds:KeyInfo>
   <CipherData><CipherReference URI="README.txt"/></CipherData>
</EncryptedData>
```

### Encryption of a single file with a certificate
The file `Important.bdoc` is encrypted with AES-256 in GCM mode. The transport key is encrypted with RSA PKCS#1 and the resulting cryptogram is included.

```
<EncryptedData xmlns='http://www.w3.org/2001/04/xmlenc#' MimeType="application/vnd.etsi.asic-e+zip"/>
   <EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#aes256-gcm'/>
   <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
     <EncryptedKey Recipient="PALJAK,MARTIN,38207162722,DIGI-ID">
       <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
       <ds:KeyInfo>
         <ds:X509Data>
           <ds:X509Certificate>MIIE6...</ds:X509Certificate>
         </ds:X509Data>
       </ds:KeyInfo>
       <CipherData>
         <CipherValue>h3SJo...</CipherValue>
       </CipherData>
     </EncryptedKey>
   </ds:KeyInfo>
   <CipherData><CipherReference URI="Important.bdoc"/></CipherData>
</EncryptedData>
```
## Transition tips
- v2.0 has the bytes `PK` as the first two bytes of the file
- v1.0 has the XML header `<?` or relevant BOM in the first bytes of the file

## Rationale for format
The original goal was to accommodate encrypted and signed (XAdES) payloads inside a single ASiC container (.bdoc). This already sets the scene for capabilities of potential implementors: ZIP processing (for container) and XML processing (for signatures.xml as well as manifest.xml) is readily available in all modern development platforms.

Both [ZIP](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) and [ODF](http://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html#__RefHeading__752811_826425813) have encryption capabilities, but mostly bound to a fixed password-based key derivation scheme and implementation-specific if not proprietary encryption options. Re-implementation of such formats would give no flexibility and no real cross-usage benefits.

For actual binary storage of encrypted data inside the ZIP container, formats such as [CMS aka S/MIME (RFC 5652)](https://tools.ietf.org/html/rfc5652) or [OpenPGP (RFC 4880)](https://tools.ietf.org/html/rfc4880) could be used, but would offer little benefit in the container context (and thus no real benefit in cross-usage).

XML - while somewhat morally outdated - is by definition extensible and thus allows to build upon the base specification without heavily changing the implementations.
