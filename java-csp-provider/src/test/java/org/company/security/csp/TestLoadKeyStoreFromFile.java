package org.company.security.csp;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509CollectionStoreParameters;
import org.bouncycastle.x509.X509Store;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestLoadKeyStoreFromFile {
	private static final String KEYSTORE_FILE = "target/test-classes/cert.sst";

	private static final Logger LOGGER = LoggerFactory.getLogger(TestLoadKeyStoreFromFile.class);
	
	private static final String PROVIDER_NAME = "CSPProvider";
	private static final String STORE_NAME = "FILE";
	private static Provider cspProvider;


	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		LoadNative.loadProvider();
		
		if(Security.getProvider(PROVIDER_NAME) == null)
			Security.addProvider(new CSPProvider());
		
		cspProvider = Security.getProvider(PROVIDER_NAME);
	}
	
	@Rule
	public TestName testName = new TestName();
	
	@Before
	public void setUp() throws Exception {
		LOGGER.info("********************************************************************************");
		LOGGER.info("Testing: " + getTestMethodName() + "(" + getClass().getName() + ")");
		LOGGER.info("********************************************************************************");
	}
	@After
	public void tearDown() throws Exception {
		LOGGER.info("********************************************************************************");
		LOGGER.info("Testing done: " + getTestMethodName() + "(" + getClass().getName() + ")");
		LOGGER.info("********************************************************************************");
	}

	public String getTestMethodName() {
		return testName.getMethodName();
	}
	
	@Test
	public void testLoalCertificatesByBuilder() throws Exception {
		new TestName().getMethodName();
		LOGGER.debug("--- testLoalCertificatesByBuilder ---");
		
		KeyStore keyStore = CSPKeyStore.Builder.newInstance("FILE", 
				cspProvider, 
				KEYSTORE_FILE, 
				null).getKeyStore();

		Enumeration<String> aliases = keyStore.aliases();
		
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
			boolean keyEntry = keyStore.isKeyEntry(alias);
			
			LOGGER.debug("Ключ {}" +
					"\n\tSubject {}" +
					"\n\tS/N     {}" +
					"\n\tIssuer  {}" +
					"\n\tKeyEntry {}",
					new Object[]{ 
					alias,
					cert.getSubjectDN().getName(),
					cert.getSerialNumber().toString(16),
					cert.getIssuerDN().getName(),
					keyEntry
					});
		}
	}
	
	@Test
	public void testLoalCertificatesByParams() throws Exception {
		LOGGER.debug("--- testLoalCertificatesByParams ---");
		
		CSPKeyStore.KeyStoreProtection protection = new CSPKeyStore.KeyStoreProtection(
				STORE_NAME, 
				cspProvider,
				KEYSTORE_FILE,
				null);
		CSPKeyStore.SimpleLoadStoreParameter parameter = new CSPKeyStore.SimpleLoadStoreParameter(protection);
		
		KeyStore keyStore = java.security.KeyStore.getInstance(STORE_NAME, PROVIDER_NAME);
		keyStore.load(parameter);

		Enumeration<String> aliases = keyStore.aliases();
		
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
			boolean keyEntry = keyStore.isKeyEntry(alias);
			
			LOGGER.debug("Ключ {}" +
					"\n\tSubject {}" +
					"\n\tS/N     {}" +
					"\n\tIssuer  {}" +
					"\n\tKeyEntry {}",
					new Object[]{ 
					alias,
					cert.getSubjectDN().getName(),
					cert.getSerialNumber().toString(16),
					cert.getIssuerDN().getName(),
					keyEntry
					});
		}
	}
}
