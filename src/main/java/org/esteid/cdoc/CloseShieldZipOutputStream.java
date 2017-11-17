package org.esteid.cdoc;

import org.apache.commons.io.output.CloseShieldOutputStream;

import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.zip.ZipOutputStream;

// For writing a ZIP to another ZIP Stream, without closing the outer container
public class CloseShieldZipOutputStream extends ZipOutputStream {
    public CloseShieldZipOutputStream(OutputStream s, Charset c) {
        super(new CloseShieldOutputStream(s), c);
    }
}
