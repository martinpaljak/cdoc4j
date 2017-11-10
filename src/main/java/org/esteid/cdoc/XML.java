package org.esteid.cdoc;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;

import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
