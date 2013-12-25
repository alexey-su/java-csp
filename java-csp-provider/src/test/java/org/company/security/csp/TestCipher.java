package org.company.security.csp;

import static org.junit.Assert.*;

import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import javax.crypto.Cipher;

import org.junit.BeforeClass;
import org.junit.Test;


public class TestCipher {
	private static final String CSP_PROVIDER = "CSPProvider";
	private static final String STORE_NAME = "Windows-MY";
	private static final String CIPHER_NAME = "GOST28147";
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		LoadNative.loadProvider();
		
		if(Security.getProvider(CSP_PROVIDER) == null)
			Security.addProvider(new CSPProvider());
		
//		if(Security.getProperty(BC_PROVIDER) == null)
//			Security.addProvider(new BouncyCastleProvider());
	}
			
	@Test
	public void test() throws Exception {
		
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(CIPHER_NAME, CSP_PROVIDER);
		}
		catch(SecurityException e) {
			String message = e.getMessage();
			String actual = "JCE cannot authenticate the provider";
			
			if(message.startsWith(actual)) {
				System.err.println("Надо использовать OpenJDK. " + message);
				return;
			}
			else
				throw e;
		}
		
		KeyStore keyStore = java.security.KeyStore.getInstance(STORE_NAME, CSP_PROVIDER);
		keyStore.load(null, null);
		for(Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
			String alias = aliases.nextElement();
			
			Key key = keyStore.getKey(alias, null);
			
			if(key != null) {
				Certificate certificate = keyStore.getCertificate(alias);
				byte[] input = alias.getBytes();
				
//				cipher.init(Cipher.ENCRYPT_MODE, certificate);
//				byte[] encode = cipher.doFinal(input);
//				
//				cipher.init(Cipher.DECRYPT_MODE, key);
//				byte[] decode = cipher.doFinal(encode);
//				
//				
//				assertNotEquals(decode, input);
			}
		}
		
//		fail("Not yet implemented");
	}

}
