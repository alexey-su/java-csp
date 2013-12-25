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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyFactorySpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

abstract class CSPKeyFactory  extends KeyFactorySpi {
	private final String algorithm; 

//	public static class GOST3410 extends CSPKeyFactory {
//
//		public GOST3410() {
//			super("GOST3410");
//		}
//	}

	public static class GOST3410EL extends CSPKeyFactory {

		public GOST3410EL() {
			super("GOST3410EL");
		}
	}

//	public static class GOST3410DH extends CSPKeyFactory {
//
//		public GOST3410DH() {
//			super("GOST3410DH");
//		}
//	}
	
	public static class GOST3410DHEL extends CSPKeyFactory {

		public GOST3410DHEL() {
			super("GOST3410DHEL");
		}
	}

	public CSPKeyFactory(String algorithm) {
		this.algorithm = algorithm;
	}

	@Override
	protected PublicKey engineGeneratePublic(KeySpec keySpec)
			throws InvalidKeySpecException {

		if(keySpec instanceof X509EncodedKeySpec) {
			byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
			try {
				return NativeCrypto.initPublicKey(encoded, encoded.length);
			} catch (InvalidKeyException e) {
				throw new InvalidKeySpecException(e.getMessage(), e);
			} catch (NoSuchAlgorithmException e) {
				throw new InvalidKeySpecException(e.getMessage(), e);
			}
		} 
		else
			throw new InvalidKeySpecException("Use only X509EncodedKeySpec");
	}

	@Override
	protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
			throws InvalidKeySpecException {

		return null;
	}

	@Override
	protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
			throws InvalidKeySpecException {

		return null;
	}

	@Override
	protected Key engineTranslateKey(Key key) throws InvalidKeyException {

		return null;
	}
}
