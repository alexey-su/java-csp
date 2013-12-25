package org.company.security.csp;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestSignature {

	private static final Logger LOGGER = LoggerFactory.getLogger(TestSignature.class);
	
	private static final String CSP_PROVIDER = "CSPProvider";
	private static final String CSP_DIGEST = "GOST3411";
	private static final String CSP_SIGNATURE = "GOST3411withGOST3410EL";
	
	private static final String BC_PROVIDER = "BC";
	private static final String BC_SIGNATURE = "GOST3411withECGOST3410";
	
	private static final String STORE_NAME = "Windows-MY";
	private static final String ALG_OID_GOST = "1.2.643.2.2.98";

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
//		new NativeLibraryLoader().loadLibraries();
		LoadNative.loadProvider();
		
		if(Security.getProvider(CSP_PROVIDER) == null)
			Security.addProvider(new CSPProvider());
		
		if(Security.getProperty(BC_PROVIDER) == null)
			Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void test() throws Exception {
		LOGGER.debug("start TestSignature test");
		
		Signature cspSignatureSign = Signature.getInstance(CSP_SIGNATURE, CSP_PROVIDER);
		Signature cspSignatureVerify = Signature.getInstance(CSP_SIGNATURE, CSP_PROVIDER);
		Signature bcSignatureVerify = Signature.getInstance(BC_SIGNATURE, BC_PROVIDER);
		
		KeyStore keyStore = java.security.KeyStore.getInstance(STORE_NAME, CSP_PROVIDER);
		keyStore.load(null, null);
		
		for(Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
			String alias = aliases.nextElement();
			
			Key key = keyStore.getKey(alias, null);
			
			if(key != null) {
				X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
				byte[] input = alias.getBytes();
				
				LOGGER.debug("Certificate" +
						"\n\tSubject {}" +
						"\n\tIssuer  {}" +
						"\n\tSerial Number {}" +
						"\n\talgorithm {}", new Object[]{
						certificate.getSubjectDN().getName(),
						certificate.getIssuerDN().getName(),
						certificate.getSerialNumber().toString(16),
						certificate.getPublicKey().getAlgorithm()
				});
				String algorithm = key.getAlgorithm();
				LOGGER.debug("PrivateKey algorithm {}", algorithm);
				
				if(ALG_OID_GOST.equals(algorithm)) {
					LOGGER.debug("TestSignature test -> cspSignatureSign.initSign");
					cspSignatureSign.initSign((PrivateKey) key);
					LOGGER.debug("TestSignature test -> cspSignatureSign.update");
					cspSignatureSign.update(input);
					LOGGER.debug("TestSignature test -> cspSignatureSign.sign");
					byte[] sign = cspSignatureSign.sign();

					bcSignatureVerify.initVerify(certificate);
					bcSignatureVerify.update(input);
					bcSignatureVerify.verify(sign);

					LOGGER.debug("TestSignature test -> cspSignatureVerify.initVerify");
					cspSignatureVerify.initVerify(certificate);
					LOGGER.debug("TestSignature test -> cspSignatureVerify.update");
					cspSignatureVerify.update(input);
					LOGGER.debug("TestSignature test -> cspSignatureVerify.verify");
					cspSignatureVerify.verify(sign);
				}
			}
		}
		//fail("Not yet implemented");
	}

}
