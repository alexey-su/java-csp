/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.company.security.csp;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

public final class CSPProvider extends Provider {
	public static final String CSP_PROVIDER = "CSPProvider";
	private static final long serialVersionUID = 1L;

	static {
		try {
			CSPNative.init();
		}
		catch(UnsatisfiedLinkError e) {
			e.printStackTrace();
		}
	}
	
	public CSPProvider() {
		super(CSP_PROVIDER, 1, "Java CSP Provider");
		AccessController.doPrivileged(new PrivilegedAction<Void>() {
			public Void run() {
				/* === SSL Contexts === */
//				put("SSLContext.SSL", SSLContextImpl.class.getName());
//				put("SSLContext.TLS", SSLContextImpl.class.getName());
//				put("Alg.Alias.SSLContext.TLSv1", "TLS");
//				put("Alg.Alias.SSLContext.TLSv1.1", "TLS");
//				put("Alg.Alias.SSLContext.TLSv1.2", "TLS");
//				put("Alg.Alias.SSLContext.SSLv3", "SSL");
//				put("Alg.Alias.SSLContext.SSLv2", "SSL");

				/* === Message Digests === */
				put("MessageDigest.GOST3411", CSPDigest.GOST3411.class.getName());
				put("MessageDigest.GOST3411-SafeTouch", CSPDigest.GOST3411_SafeTouch.class.getName());
				put("Alg.Alias.MessageDigest.1.2.643.2.2.9", "GOST3411");		// szOID_CP_GOST_R3411
				put("Alg.Alias.MessageDigest.OID.1.2.643.2.2.9", "GOST3411");

//				put("Mac.HMAC_GOSTR3411", CSPDigest.HMACGOST3411.class.getName());
//				put("Alg.Alias.Mac.1.2.643.2.2.10", "HMAC_GOSTR3411");
//				put("Alg.Alias.Mac.OID.1.2.643.2.2.10", "HMAC_GOSTR3411");
//				put("Mac.HMAC34_GOST3411", CSPDigest.HMAC34GOST3411.class.getName());
//				put("Mac.MAC_GOST28147", CSPDigest.MACGOST28147.class.getName());

//				/* == KeyPairGenerators == */
//				put("KeyPairGenerator.GOST3410", CSPKeyPairGOST3410.class.getName());
//				put("KeyPairGenerator.GOST3410EL", CSPKeyPairGOST3410.class.getName());
//				put("KeyPairGenerator.GOST3410EPH", CSPKeyPairGOST3410EPH.class.getName());
//				put("KeyPairGenerator.GOST3410ELEPH", CSPKeyPairGOST3410EPH.class.getName());
//				put("Alg.Alias.KeyPairGenerator.1.2.643.2.2.20", "GOST3410");
//				put("Alg.Alias.KeyPairGenerator.1.2.643.2.2.19", "GOST3410EL");
//				put("Alg.Alias.KeyPairGenerator.OID.1.2.643.2.2.20", "GOST3410");
//				put("Alg.Alias.KeyPairGenerator.OID.1.2.643.2.2.19", "GOST3410EL");
//
//				/* == KeyFactory == */
//				put("KeyFactory.GOST3410", CSPKeyFactory.GOST3410.class.getName());
//				put("KeyFactory.GOST3410EL", CSPKeyFactory.GOST3410EL.class.getName());
//				put("KeyFactory.GOST3410DH", CSPKeyFactory.GOST3410DH.class.getName());
//				put("KeyFactory.GOST3410DHEL", CSPKeyFactory.GOST3410DHEL.class.getName());
//				put("Alg.Alias.KeyFactory.1.2.643.2.2.20", "GOST3410");			// szOID_CP_GOST_R3410
//				put("Alg.Alias.KeyFactory.1.2.643.2.2.19", "GOST3410EL");		//  szOID_CP_GOST_R3410EL
//				put("Alg.Alias.KeyFactory.OID.1.2.643.2.2.20", "GOST3410");
//				put("Alg.Alias.KeyFactory.OID.1.2.643.2.2.19", "GOST3410EL");
//				put("Alg.Alias.KeyFactory.1.2.643.2.2.99", "GOST3410DH");		// szOID_CP_DH_EX
//				put("Alg.Alias.KeyFactory.1.2.643.2.2.98", "GOST3410DHEL");		// szOID_CP_DH_EL
//				put("Alg.Alias.KeyFactory.OID.1.2.643.2.2.99", "GOST3410DH");
//				put("Alg.Alias.KeyFactory.OID.1.2.643.2.2.98", "GOST3410DHEL");

				/* == Cipher engines == */
//				put("Cipher.GOST28147", CSPCipher.class.getName());
//				put("Alg.Alias.Cipher.1.2.643.2.2.21", "GOST28147");			// szOID_CP_GOST_28147 
//				put("Alg.Alias.Cipher.OID.1.2.643.2.2.21", "GOST28147"); 

				/* == Signatures == */
//				put("Signature.GOST3411withGOST3410", SignatureGOST3411withGOST3410.class.getName());
				put("Signature.GOST3411withGOST3410EL", CSPSignature.GOST3411withGOST3410EL.class.getName());
//				put("Signature.GOST3411withGOST3410DHEL", SignatureGOST3411withGOST3410DHEL.class.getName());
//				put("Signature.NONEwithGOST3410", SignatureNONEwithGOST3410.class.getName());
				put("Signature.NONEwithGOST3410EL", CSPSignature.NONEwithGOST3410EL.class.getName());
//				put("Signature.NONEwithGOST3410DHEL", SignatureNONEwithGOST3410DHEL.class.getName());
//				put("Alg.Alias.Signature.1.2.643.2.2.4", "GOST3411withGOST3410");		// szOID_CP_GOST_R3411_R3410
				put("Alg.Alias.Signature.1.2.643.2.2.3", "GOST3411withGOST3410EL");		// szOID_CP_GOST_R3411_R3410EL
//				put("Alg.Alias.Signature.OID.1.2.643.2.2.4", "GOST3411withGOST3410");
				put("Alg.Alias.Signature.OID.1.2.643.2.2.3", "GOST3411withGOST3410EL");
//				put("Alg.Alias.Signature.1.2.643.2.2.9with1.2.643.2.2.19", "GOST3411withGOST3410EL");

				/* == KeyFactory == */
				put("KeyManagerFactory.X509", KeyManagerFactoryImpl.class.getName());
				put("TrustManagerFactory.X509", TrustManagerFactoryImpl.class.getName());

				/* == KeyStore == */
				put("KeyStore.Windows-MY", CSPKeyStore.MY.class.getName());
				put("KeyStore.Windows-ROOT", CSPKeyStore.ROOT.class.getName());
				put("KeyStore.Windows-CA", CSPKeyStore.CA.class.getName());
				put("KeyStore.Linux-AddressBook", CSPKeyStore.AddressBook.class.getName());
				put("KeyStore.FILE", CSPKeyStore.FILE.class.getName());

				put("CertificateFactory.X.509", CSPCertificateFactory.class.getName());
				put("CertificateFactory.Alias.X509", "X.509");
				return null;
			}
		});
	}
}
