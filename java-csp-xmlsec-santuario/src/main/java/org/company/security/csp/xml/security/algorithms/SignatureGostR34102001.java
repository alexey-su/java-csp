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
package org.company.security.csp.xml.security.algorithms;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.Base64;

/**
 * Базовый класс реализации алгиртма ГОСТ ЭЦП.
 * За основу был взят базовый DSA.
 * 
 * @author Aleksey
 */
abstract class SignatureGostR34102001 extends SignatureAlgorithmSpi {

	/** {@link org.apache.commons.logging} logging facility */
	static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SignatureGostR34102001.class);

	/** Field algorithm */
	private java.security.Signature _signatureAlgorithm = null;

	/**
	 * Constructor SignatureDSA
	 *
	 * @throws XMLSignatureException
	 */
	SignatureGostR34102001() throws XMLSignatureException {

		String algorithmID = JCEMapper.translateURItoJCEID(engineGetURI());
		if (log.isDebugEnabled())
			log.debug("Created SignatureGostr34102001Gostr3411 using " + algorithmID);

		String provider = JCEMapper.getProviderId();
		try {
			if (provider == null) {
				this._signatureAlgorithm = Signature.getInstance(algorithmID);
			} else {
				this._signatureAlgorithm = 
					Signature.getInstance(algorithmID, provider);
			}
		} catch (java.security.NoSuchAlgorithmException ex) {
			Object[] exArgs = { algorithmID, ex.getLocalizedMessage() };
			throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
		} catch (java.security.NoSuchProviderException ex) {
			Object[] exArgs = { algorithmID, ex.getLocalizedMessage() };
			throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
		}
	}

	/**
	 * @inheritDoc
	 */
	@Override
	protected void engineSetParameter(AlgorithmParameterSpec params) throws XMLSignatureException {

		try {
			this._signatureAlgorithm.setParameter(params);
		} catch (InvalidAlgorithmParameterException ex) {
			throw new XMLSignatureException("empty", ex);
		}
	}

	/**
	 * @inheritDoc
	 */
	@Override
	protected boolean engineVerify(byte[] signature) throws XMLSignatureException {

		try {
			if (log.isDebugEnabled())
				log.debug("Called gostr34102001-gostr3411.verify() on " + Base64.encode(signature));

			return this._signatureAlgorithm.verify(signature);
		} catch (SignatureException ex) {
			throw new XMLSignatureException("empty", ex);
		} 
	}

	/**
	 * @inheritDoc
	 */
	@Override
	protected void engineInitVerify(Key publicKey) throws XMLSignatureException {

		if (!(publicKey instanceof PublicKey)) {
			String supplied = publicKey.getClass().getName();
			String needed = PublicKey.class.getName();
			Object exArgs[] = { supplied, needed };

			throw new XMLSignatureException
			("algorithms.WrongKeyForThisOperation", exArgs);
		}

		try {
			System.out.println("engineInitVerify publicKey is " + publicKey.getClass());
			
			this._signatureAlgorithm.initVerify((PublicKey) publicKey);
		} catch (InvalidKeyException ex) {
			// reinstantiate Signature object to work around bug in JDK
			// see: http://bugs.sun.com/view_bug.do?bug_id=4953555
			Signature sig = this._signatureAlgorithm;
			try {
				this._signatureAlgorithm = Signature.getInstance
				(_signatureAlgorithm.getAlgorithm(), _signatureAlgorithm.getProvider().getName());
			} catch (Exception e) {
				// this shouldn't occur, but if it does, restore previous
				// Signature
				if (log.isDebugEnabled()) {
					log.debug("Exception when reinstantiating Signature:" + e);
				}
				this._signatureAlgorithm = sig;
			}
			throw new XMLSignatureException("empty", ex);
		}
	}

	/**
	 * @inheritDoc
	 */
	@Override
	protected byte[] engineSign() throws XMLSignatureException {

		try {
			byte jcebytes[] = this._signatureAlgorithm.sign();
			
			return jcebytes;
		} catch (SignatureException ex) {
			throw new XMLSignatureException("empty", ex);
		}
	}

	/**
	 * @inheritDoc
	 */
	@Override
	protected void engineInitSign(Key privateKey, SecureRandom secureRandom)
	throws XMLSignatureException {

		if (!(privateKey instanceof PrivateKey)) {
			String supplied = privateKey.getClass().getName();
			String needed = PrivateKey.class.getName();
			Object exArgs[] = { supplied, needed };

			throw new XMLSignatureException("algorithms.WrongKeyForThisOperation", exArgs);
		}

		try {
			this._signatureAlgorithm.initSign((PrivateKey) privateKey,
					secureRandom);
		} catch (InvalidKeyException ex) {
			throw new XMLSignatureException("empty", ex);
		}
	}

	/**
	 * @inheritDoc
	 */
	@Override
	protected void engineInitSign(Key privateKey) throws XMLSignatureException {

		if (!(privateKey instanceof PrivateKey)) {
			String supplied = privateKey.getClass().getName();
			String needed = PrivateKey.class.getName();
			Object exArgs[] = { supplied, needed };

			throw new XMLSignatureException("algorithms.WrongKeyForThisOperation", exArgs);
		}

		try {
			this._signatureAlgorithm.initSign((PrivateKey) privateKey);
		} catch (InvalidKeyException ex) {
			throw new XMLSignatureException("empty", ex);
		}
	}

	/**
	 * @inheritDoc
	 */
	@Override
	protected void engineUpdate(byte[] input) throws XMLSignatureException {
		try {
			this._signatureAlgorithm.update(input);
		} catch (SignatureException ex) {
			throw new XMLSignatureException("empty", ex);
		}
	}

	/**
	 * @inheritDoc
	 */
	@Override
	protected void engineUpdate(byte input) throws XMLSignatureException {
		try {
			this._signatureAlgorithm.update(input);
		} catch (SignatureException ex) {
			throw new XMLSignatureException("empty", ex);
		}
	}

	/**
	 * @inheritDoc
	 */
	@Override
	protected void engineUpdate(byte buf[], int offset, int len)
	throws XMLSignatureException {
		try {
			this._signatureAlgorithm.update(buf, offset, len);
		} catch (SignatureException ex) {
			throw new XMLSignatureException("empty", ex);
		}
	}

	/**
	 * Method engineGetJCEAlgorithmString
	 *
	 * @inheritDoc
	 */
	@Override
	protected String engineGetJCEAlgorithmString() {
		return this._signatureAlgorithm.getAlgorithm();
	}

	/**
	 * Method engineGetJCEProviderName
	 *
	 * @inheritDoc
	 */
	@Override
	protected String engineGetJCEProviderName() {
		return this._signatureAlgorithm.getProvider().getName();
	}

    /**
     * Method engineSetHMACOutputLength
     *
     * @param HMACOutputLength
     * @throws XMLSignatureException
     */
	@Override
    protected void engineSetHMACOutputLength(int HMACOutputLength)
            throws XMLSignatureException {
        throw new XMLSignatureException(
	    "algorithms.HMACOutputLengthOnlyForHMAC");
    }

    /**
     * Method engineInitSign
     *
     * @param signingKey
     * @param algorithmParameterSpec
     * @throws XMLSignatureException
     */
	@Override
    protected void engineInitSign(
        Key signingKey, AlgorithmParameterSpec algorithmParameterSpec)
            throws XMLSignatureException {
        throw new XMLSignatureException(
            "algorithms.CannotUseAlgorithmParameterSpecOnDSA");
    }
	
}
