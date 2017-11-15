package org.esteid.cdoc;

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
public class XML {
    public static final XPath xPath;

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

        @SuppressWarnings("serial")
        HashMap<String, String> prefixes = new HashMap<>();
        prefixes.put("ddoc", "http://www.sk.ee/DigiDoc/v1.3.0#");
        prefixes.put("xenc", "http://www.w3.org/2001/04/xmlenc#");
        prefixes.put("ds", "http://www.w3.org/2000/09/xmldsig#");

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
            throw new RuntimeException("Could not create XML parser", e);
        }
    }

    public static Document stream2dom(InputStream in) throws IOException {
        try {
            return XML.getSecureParser().parse(in);
        } catch (SAXException e) {
            throw new IOException("Could not parse XML", e);
        }
    }

    public static byte[] dom2bytes(Document doc) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        dom2stream(doc, bos);
        byte[] xml = bos.toByteArray();
        return xml;
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
            throw new RuntimeException("Could not create DocumentBuilder", e);
        }
    }

    public static List<Node> asList(NodeList n) {
        return n.getLength() == 0 ? Collections.emptyList() : new NodeListWrapper(n);
    }

    // Schema validator
    public static final boolean validate(byte[] d) {
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
            dbf.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource", XML.class.getResourceAsStream("schema/cdoc.xsd"));
            DocumentBuilder db = dbf.newDocumentBuilder();

            db.setEntityResolver((publicId, systemId) -> {
                String[] allowed = new String[]{"xenc-schema.xsd", "datatypes.dtd", "XMLSchema.dtd", "xenc-schema-11.xsd", "xmldsig-core-schema.xsd"};
                //System.out.println("Want " + publicId + " " + systemId);
                String[] p = systemId.split("/");

                for (String f : allowed) {
                    if (systemId.endsWith(f))
                        return new InputSource(XML.class.getResourceAsStream("schema/" + f));
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
            System.out.println("Total of " + warnings.size() + " warnings or errors");
            return warnings.size() == 0;
        } catch (ParserConfigurationException | SAXException | IOException e) {
            System.out.println("Failed to validate: " + e.getMessage());
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
