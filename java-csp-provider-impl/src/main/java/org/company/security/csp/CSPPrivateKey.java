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

import java.io.IOException;
import java.security.InvalidKeyException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

public class CSPPrivateKey extends CSPKey implements java.security.PrivateKey {
	private static final long serialVersionUID = 8986466200520529548L;
	private static final Logger LOGGER = LoggerFactory.getLogger(CSPPrivateKey.class);

	public CSPPrivateKey(long hCryptoProvider, long hCryptoKey, int keyLength) {
		super(hCryptoProvider, hCryptoKey, keyLength);
	}

	@Override
	public String getAlgorithm() {
		try {
			if(getHCryptKey() != 0) {
				String oid = getAlgOID();

				if(oid != null) {
					return new AlgorithmId(new ObjectIdentifier(oid)).getName();
				}
			}
		} catch (IOException e) {
			LOGGER.error("Error parse algorithm", e);
		} catch (InvalidKeyException e) {
			LOGGER.error("Error algorithm id", e);
		}
		return "CSP CryptoAPI";
	}

	/**
	 * Данный класс не сериализуется
	 */
	private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
		throw new java.io.NotSerializableException();
	}
	
	private String getAlgOID() throws InvalidKeyException {
		return NativeCrypto.getKeyAlgOID(getHCryptKey());
	}
}
