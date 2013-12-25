package org.company.security.csp.xml.dsig.test;

import static org.junit.Assert.*;

import java.io.InputStream;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.company.security.csp.CSPNative;
import org.company.security.csp.CSPProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class SignTest {
	private static final String CSP_PROVIDER = "CSPProvider";
	private static final String CSPXML_PROVIDER = "CSPXMLDSig";
	private static final String STORE_NAME = "Windows-MY";
	

	private XMLSignatureFactory fac;
	private List<Key> signKeys;
	
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		CSPNative.init("target/native", null);
		
		// Поставщик хеш функций и подписей
		if(Security.getProvider(CSP_PROVIDER) == null)
			Security.addProvider(new CSPProvider());
		
		// Поставщик XML dsign JSR-105
		if(Security.getProvider(CSPXML_PROVIDER) == null)
			Security.addProvider(new org.company.security.csp.xml.dsig.internal.dom.XMLDSigRI());
	}

	@Before
	public void before() throws Exception {
		
		fac = XMLSignatureFactory.getInstance("DOM", CSPXML_PROVIDER);
		compareClasses("XMLSignatureFactory", fac.getClass(), org.company.security.csp.xml.dsig.internal.dom.DOMXMLSignatureFactory.class);
		
		signKeys = new ArrayList<Key>();
		
		KeyStore keyStore = java.security.KeyStore.getInstance(STORE_NAME, CSP_PROVIDER);
		keyStore.load(null, null);
		
		for(Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
			String alias = aliases.nextElement();
			
			Key key = keyStore.getKey(alias, null);
			
			if(key != null) {
				compareClasses("PrivateKey", key.getClass(), org.company.security.csp.CSPPrivateKey.class);
				signKeys.add(key);
			}
		}
	}

	private void compareClasses(String title, Class<?> expected, Class<?> actual) {
		if(expected != actual) {
			System.out.format("%s as (expected == actual -> %s)\n" +
					"\nexpected: %s" +
					"\nactual:   %s\n",
					title,
					(expected == actual),
					expected,
					actual);
		}
		assertEquals("Не совпадают классы ", expected, actual);
	}
	
	@Test
	public void test() throws Exception {
		if(signKeys.isEmpty())
			return;
		
		String templateName = "signature-enveloping-gost-template.xml";
		InputStream inputStream = getClass().getClassLoader().getResourceAsStream(templateName);

		assertNotNull("Не найден файл " + templateName, templateName);

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = dbf.newDocumentBuilder().parse(inputStream);

		CSPNative.closeSilently(inputStream);

		// Find Signature element
		NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0) {
			throw new Exception("Cannot find Signature element");
		}
		DOMStructure domSignature = new DOMStructure(nl.item(0));
		// unmarshal the XMLSignature
		XMLSignature signature = fac.unmarshalXMLSignature(domSignature);

		// create copy of Signature
		XMLSignature newSignature = fac.newXMLSignature(
				signature.getSignedInfo(), 
				null, 
				signature.getObjects(),
				signature.getId(), 
				signature.getSignatureValue().getId());

		// Sign the template
		Node parent = domSignature.getNode().getParentNode();
		DOMSignContext signContext = new DOMSignContext(signKeys.get(0), parent);
		
		// устанавливаем нужного поставщика подписей, который добыл закрытый ключ для подписи
		signContext.setProperty("org.jcp.xml.dsig.internal.dom.SignatureProvider", Security.getProvider(CSP_PROVIDER));
		
		// remove the signature node (since it will get recreated)
		parent.removeChild(domSignature.getNode());
		newSignature.sign(signContext);
//		TestUtils.validateSecurityOrEncryptionElement(parent.getLastChild());

		// check that Object element retained namespace definitions
		Element objElem = (Element)parent.getFirstChild().getLastChild();
		Attr a = objElem.getAttributeNode("xmlns:test");
		if (!a.getValue().equals("http://www.example.org/ns"))
			throw new Exception("Object namespace definition not retained");
		
		System.out.format("XML документ с подписью:\n----- Begin XML Document ------\n%s\n----- End XML Document ------\n",
				domToString(doc));
	}

	private String domToString(Document doc) throws Exception {
		//set up a transformer
		TransformerFactory transfac = TransformerFactory.newInstance();
		Transformer trans = transfac.newTransformer();
		trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		trans.setOutputProperty(OutputKeys.INDENT, "yes");

		//create string from xml tree
		StringWriter sw = new StringWriter();
		StreamResult result = new StreamResult(sw);
		DOMSource source = new DOMSource(doc);
		trans.transform(source, result);
		String xmlString = sw.toString();
		
		return xmlString;
	}
}
