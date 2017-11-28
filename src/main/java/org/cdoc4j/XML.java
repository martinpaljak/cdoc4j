/**
 * Copyright (c) 2017 Martin Paljak
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.cdoc4j;

import org.apache.commons.io.input.CloseShieldInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.util.*;

/**
 * Utilities to work with XML in a safe and sane way.
 */
public final class XML {
    public static final XPath xPath;
    private final static Logger log = LoggerFactory.getLogger(XML.class);

    static {
        final class NSContext implements NamespaceContext {
            private final Map<String, String> prefixes = new HashMap<>();

            public NSContext(final Map<String, String> prefMap) {
                prefixes.putAll(prefMap);
            }

            @Override
            public String getNamespaceURI(String prefix) {
                return prefixes.get(prefix);
            }

            @Override
            public String getPrefix(String uri) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Iterator getPrefixes(String uri) {
                throw new UnsupportedOperationException();
            }
        }
        xPath = XPathFactory.newInstance().newXPath();

        HashMap<String, String> prefixes = new HashMap<>();
        prefixes.put("ddoc", "http://www.sk.ee/DigiDoc/v1.3.0#");
        prefixes.put("xenc", "http://www.w3.org/2001/04/xmlenc#");
        prefixes.put("ds", "http://www.w3.org/2000/09/xmldsig#");
        prefixes.put("xenc11", "http://www.w3.org/2009/xmlenc11#");
        prefixes.put("dsig11", "http://www.w3.org/2009/xmldsig11#");

        NSContext nsctx = new NSContext(prefixes);
        xPath.setNamespaceContext(nsctx);
    }

    public static DocumentBuilder getSecureParser() {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            dbf.setNamespaceAware(true);
            dbf.setFeature("http://xml.org/sax/features/validation", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setFeature("http://apache.org/xml/features/validation/schema", false);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            return dbf.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new RuntimeException("Could not build XML parser", e);
        }
    }

    public static Document stream2dom(InputStream in) throws IOException {
        try {
            // XXX: stupid parser closes my streams....
            return getSecureParser().parse(new CloseShieldInputStream(in));
        } catch (SAXException e) {
            throw new IOException("Could not parse XML", e);
        }
    }

    public static byte[] dom2bytes(Document doc) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        dom2stream(doc, bos);
        return bos.toByteArray();
    }

    public static void dom2stream(Document doc, OutputStream out) {
        // Serialize
        DOMImplementationLS domImplementation = (DOMImplementationLS) doc.getImplementation();
        LSOutput lsOutput = domImplementation.createLSOutput();
        lsOutput.setEncoding("UTF-8");
        lsOutput.setByteStream(out);
        LSSerializer lsSerializer = domImplementation.createLSSerializer();
        // Look nice!
        lsSerializer.getDomConfig().setParameter("format-pretty-print", Boolean.TRUE);
        lsSerializer.write(doc, lsOutput);
    }

    public static Document getDocument() {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            return db.newDocument();
        } catch (ParserConfigurationException e) {
            throw new RuntimeException("Could not build DocumentBuilder", e);
        }
    }

    public static List<Node> asList(NodeList n) {
        return n.getLength() == 0 ? Collections.emptyList() : new NodeListWrapper(n);
    }

    public static boolean validate_cdoc(byte[] d) throws IOException {
        try (InputStream schema = XML.class.getResourceAsStream("xenc-schema-11.xsd")) {
            return validate(d, schema);
        }
    }

    // Schema validator
    public static boolean validate(byte[] d, InputStream schema) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setValidating(true);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);

            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);

            dbf.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaLanguage", XMLConstants.W3C_XML_SCHEMA_NS_URI);
            dbf.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource", schema);
            DocumentBuilder db = dbf.newDocumentBuilder();

            db.setEntityResolver((publicId, systemId) -> {
                final String[] allowed = new String[]{"xenc-schema.xsd", "datatypes.dtd", "XMLSchema.dtd", "xenc-schema-11.xsd", "xmldsig-core-schema.xsd"};

                for (String f : allowed) {
                    if (systemId.endsWith(f))
                        return new InputSource(XML.class.getResourceAsStream(f));
                }
                throw new IOException("No resource available");
            });

            final ArrayList<String> warnings = new ArrayList<>();
            db.setErrorHandler(new ErrorHandler() {
                @Override
                public void warning(SAXParseException exception) throws SAXException {
                    warnings.add(exception.getMessage());
                }

                @Override
                public void error(SAXParseException exception) throws SAXException {
                    warnings.add(exception.getMessage());
                }

                @Override
                public void fatalError(SAXParseException exception) throws SAXException {
                    warnings.add(exception.getMessage());
                }
            });

            db.parse(new ByteArrayInputStream(d));
            for (String w : warnings) {
                log.error("XML validation error: {}", w);
            }
            return warnings.size() == 0;
        } catch (ParserConfigurationException | SAXException | IOException e) {
            log.error("Failed to validate: {} ", e.getMessage());
            return false;
        }
    }

    static final class NodeListWrapper extends AbstractList<Node> implements RandomAccess {
        private final NodeList list;

        NodeListWrapper(NodeList l) {
            list = l;
        }

        public Node get(int index) {
            return list.item(index);
        }

        public int size() {
            return list.getLength();
        }
    }
}
