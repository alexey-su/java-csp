package org.company.security.csp;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestCertFactory {
	private static final String CSP_PROVIDER = "CSPProvider";
	private static final String BC_PROVIDER = "BC";
	private static final String STORE_NAME = "Windows-MY";

	private static final Logger LOGGER = LoggerFactory.getLogger(TestLoadKeyStoreFromFile.class);
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		LoadNative.loadProvider();
		
		if(Security.getProvider(CSP_PROVIDER) == null)
			Security.addProvider(new CSPProvider());
		
		if(Security.getProvider(BC_PROVIDER) == null)
			Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void test() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", CSP_PROVIDER);
		CertificateFactory bcCertificateFactory = CertificateFactory.getInstance("X509", BC_PROVIDER);
		KeyStore keyStore = java.security.KeyStore.getInstance(STORE_NAME, CSP_PROVIDER);
		keyStore.load(null, null);
		
		for(Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
			String alias = aliases.nextElement();
			
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
			byte[] encoded = certificate.getEncoded();
			ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
			
			X509Certificate certificate2 = (X509Certificate) certificateFactory.generateCertificate(bis);
			
			assertNotEquals("Не совпадают сертификаты", encoded, certificate2.getEncoded());
			
			bis.close();
			
			bis = new ByteArrayInputStream(encoded);			
			X509Certificate certificate3 = (X509Certificate) bcCertificateFactory.generateCertificate(bis);
			
			String cspIssuer = certificate.getIssuerX500Principal().getName();
			String bcIssuer = certificate3.getIssuerX500Principal().getName();
			String cspIssuerDN = certificate.getIssuerDN().getName();
			String bcIssuerDN = certificate3.getIssuerDN().getName();

			String cspSubject = certificate.getSubjectX500Principal().getName();
			String bcSubject = certificate3.getSubjectX500Principal().getName();
			String cspSubjectDN = certificate.getSubjectDN().getName();
			String bcSubjectDN = certificate3.getSubjectDN().getName();

			LOGGER.debug("IssuerX500Principal" +
					"\n\tCSP: {}" +
					"\n\tBC:  {}" +
					"\n\tequals {}", new Object[]{
					cspIssuer,
					bcIssuer,
					cspIssuer.equals(bcIssuer)});
			
			LOGGER.debug("IssuerDN" +
					"\n\tCSP: {}" +
					"\n\tBC:  {}" +
					"\n\tequals {}", new Object[]{
					cspIssuerDN,
					bcIssuerDN,
					cspIssuerDN.equals(bcIssuerDN)});
			
			LOGGER.debug("SubjectX500Principal" +
					"\n\tCSP: {}" +
					"\n\tBC : {}" +
					"\n\tequals {}", new Object[]{
					cspSubject,
					bcSubject,
					cspSubject.equals(bcSubject)});
			
			LOGGER.debug("SubjectDN" +
					"\n\tCSP: {}" +
					"\n\tBC:  {}" +
					"\n\tequals {}", new Object[]{
					cspSubjectDN,
					bcSubjectDN,
					cspSubjectDN.equals(bcSubjectDN)});
			
//			assertNotEquals("Не совпадают названия IssuerX500Principal",
//					certificate.getIssuerX500Principal().getName(),
//					bcIssuerBC);
//			
//			assertEquals("Не совпадают названия IssuerX500Principal",
//					certificate.getSubjectX500Principal().getName(),
//					certificate3.getSubjectX500Principal().getName());
		}
	}

}
