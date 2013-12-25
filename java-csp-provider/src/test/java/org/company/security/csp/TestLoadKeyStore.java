package org.company.security.csp;

import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestLoadKeyStore {
	private static final Logger LOGGER = LoggerFactory.getLogger(TestLoadKeyStore.class);
	
	private static final String PROVIDER_NAME = "CSPProvider";
	private static final String STORE_NAME = "Windows-MY";

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		LoadNative.loadProvider();
		
		if(Security.getProvider(PROVIDER_NAME) == null)
			Security.addProvider(new CSPProvider());		
	}
	
	@Test
	public void testLoalCertificates() throws Exception {
		KeyStore keyStore = java.security.KeyStore.getInstance(STORE_NAME, PROVIDER_NAME);
		keyStore.load(null, null);

		Enumeration<String> aliases = keyStore.aliases();
		
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
			
			LOGGER.debug("Ключ {}" +
					"\n\tSubject {}" +
					"\n\tS/N     {}" +
					"\n\tIssuer  {}",
					new Object[]{ 
					alias,
					cert.getSubjectDN().getName(),
					cert.getSerialNumber().toString(16),
					cert.getIssuerDN().getName()
					});
		}
	}
}
