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
package org.company.security.csp.ws.security.components.crypto;

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.AlgorithmSuiteValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LocalAlgorithmSuiteValidator extends AlgorithmSuiteValidator {
	private static final Logger LOG = LoggerFactory.getLogger(LocalAlgorithmSuiteValidator.class);
	
	private final AlgorithmSuite algorithmSuite;

	public LocalAlgorithmSuiteValidator(AlgorithmSuite algorithmSuite) {
		super(algorithmSuite);
		this.algorithmSuite = algorithmSuite;
	}

	@Override
    /**
     * Check the asymmetric key length
     */
	public void checkAsymmetricKeyLength(
			PublicKey publicKey
			) throws WSSecurityException {
		if (publicKey == null) {
			return;
		}
		int length = -1;
		
		LOG.debug("Algorithm {}", publicKey.getAlgorithm());
		
		if (publicKey instanceof RSAPublicKey) {
			length = ((RSAPublicKey)publicKey).getModulus().bitLength();
		} else if (publicKey instanceof DSAPublicKey) {
			length = ((DSAPublicKey)publicKey).getParams().getP().bitLength();
		} else {
			try {
				// FIXME verify Algorithm OID in provider's KeyFactory
				
				byte[] encoded = publicKey.getEncoded();
				if(encoded != null && encoded.length > 0)
					length = algorithmSuite.getMinimumAsymmetricKeyLength() + 1;
			}
			catch(Exception e) {
				LOG.error(e.getMessage(), e);
			}
		}
		
		if (length < 0) {
			LOG.debug("An unknown public key was provided");
			throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
		}
		else if (length < algorithmSuite.getMinimumAsymmetricKeyLength()
			|| length > algorithmSuite.getMaximumAsymmetricKeyLength()) {
			LOG.debug("The asymmetric key length does not match the requirement");
			throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
		}
	}
}
