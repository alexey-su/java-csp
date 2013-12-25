package org.company.security.csp;

import static org.junit.Assert.assertNotEquals;

import java.security.MessageDigest;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestDigest {
	private static final String CSP_PROVIDER = "CSPProvider";
	private static final String CSP_DIGEST = "GOST3411";
	
	private static final String BC_PROVIDER = "BC";
	private static final String BC_DIGEST = "GOST3411";

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		LoadNative.loadProvider();
		
		if(Security.getProvider(CSP_PROVIDER) == null)
			Security.addProvider(new CSPProvider());
		
		if(Security.getProperty(BC_PROVIDER) == null)
			Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void test() throws Exception {
		byte[] input = new byte[]{ 1, 2, 3 };
		
		MessageDigest messageDigestBC = MessageDigest.getInstance(BC_DIGEST, BC_PROVIDER);
		messageDigestBC.digest(input);
		byte[] digestBC = messageDigestBC.digest();
		
		MessageDigest messageDigestCSP = MessageDigest.getInstance(CSP_DIGEST, CSP_PROVIDER);
		messageDigestCSP.digest(input);
		byte[] digestCSP = messageDigestCSP.digest();
		
		assertNotEquals("MessageDigest error", digestCSP, digestBC);
	}

}
