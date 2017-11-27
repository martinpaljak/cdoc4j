package org.cdoc4j;

public enum EncryptionMethod {
    AES128_CBC("http://www.w3.org/2001/04/xmlenc#aes128-cbc", "AES-128 CBC", "AES/CBC/NoPadding"),
    AES256_GCM("http://www.w3.org/2009/xmlenc11#aes256-gcm", "AES-256 GCM", "AES/GCM/NoPadding");

    private final String uri;
    private final String name;
    private final String cipher;


    EncryptionMethod(String uri, String name, String cipher) {
        this.uri = uri;
        this.name = name;
        this.cipher = cipher;
    }

    public static EncryptionMethod fromURI(String uri) {
        for (EncryptionMethod e : values()) {
            if (e.uri.equals(uri))
                return e;
        }
        return null;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getAlgorithmURI() {
        return uri;
    }

    public String getCipherName() {
        return cipher;
    }
}