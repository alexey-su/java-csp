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

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

import org.company.security.csp.parameter.DigestParameterSpec;

abstract class CSPSignature extends SignatureSpi {
	
	public static class GOST3411withGOST3410EL extends CSPSignature {

		public GOST3411withGOST3410EL() {
			super("GOST3411withGOST3410EL");
		}

	}

	public static class NONEwithGOST3410EL extends CSPSignature.Raw {

		public NONEwithGOST3410EL() {
			super("GOST3411withGOST3410EL");
		}

	}

	protected String digestName;
	protected String signName;

	// message digest implementation we use
	private final MessageDigest messageDigest;

	// message digest name
	private String messageDigestAlgorithm;

	// flag indicating whether the digest has been reset
	private boolean needsReset;

	// the signing key
	private CSPKey privateKey = null;

	// the verification key
	private CSPKey publicKey = null;

	private List<AlgorithmParameterSpec> parameters;

	public CSPSignature(String algorithm) {
		int of = algorithm.indexOf("with");
		digestName = null;
		signName = null;
			
		if(of > 0) {
			digestName = algorithm.substring(0, of);
			signName = algorithm.substring(of + 4); 
		}
		if(digestName == null || digestName.equalsIgnoreCase("NONE")) {
			messageDigest = null;
			messageDigestAlgorithm = null;
		}
		else {
			try {
				messageDigest = MessageDigest.getInstance(digestName, CSPProvider.CSP_PROVIDER);
				// Get the digest's canonical name
				messageDigestAlgorithm = messageDigest.getAlgorithm();

			} catch (NoSuchAlgorithmException e) {
				throw new ProviderException(e);
			} catch (NoSuchProviderException e) {
				throw new ProviderException(e);
			}
		}
		needsReset = false;
	}

	public abstract static class Raw extends CSPSignature {

		// the longest supported digest is 512 bits (SHA-512)
		private static final int RAW_MAX = 64;

		private final byte[] precomputedDigest;
		private int offset = 0;

		public Raw(String algorithm) {
			super(algorithm);
			precomputedDigest = new byte[RAW_MAX];
		}

		// Stores the precomputed message digest value.
		@Override
		protected void engineUpdate(byte b) throws SignatureException {
			if (offset >= precomputedDigest.length) {
				offset = RAW_MAX + 1;
				return;
			}
			precomputedDigest[offset++] = b;
		}

		// Stores the precomputed message digest value.
		@Override
		protected void engineUpdate(byte[] b, int off, int len)
				throws SignatureException {
			if (offset + len > precomputedDigest.length) {
				offset = RAW_MAX + 1;
				return;
			}
			System.arraycopy(b, off, precomputedDigest, offset, len);
			offset += len;
		}

		// Stores the precomputed message digest value.
		@Override
		protected void engineUpdate(ByteBuffer byteBuffer) {
			int len = byteBuffer.remaining();
			if (len <= 0) {
				return;
			}
			if (offset + len > precomputedDigest.length) {
				offset = RAW_MAX + 1;
				return;
			}
			byteBuffer.get(precomputedDigest, offset, len);
			offset += len;
		}

		@Override
		protected void resetDigest(){
			offset = 0;
		}

		// Returns the precomputed message digest value.
		@Override
		protected byte[] getDigestValue() throws SignatureException {
			if (offset > RAW_MAX) {
				throw new SignatureException("Message digest is too long");
			}

			// Determine the digest algorithm from the digest length
			if (offset == 20) {
				setDigestName("SHA1");
			} else if (offset == 36) {
				setDigestName("SHA1+MD5");
			} else if (offset == 32) {
				if(signName != null && signName.startsWith("GOST3410")) {
					setDigestName("GOST3411");
				} else {
					setDigestName("SHA-256");
				}
			} else if (offset == 48) {
				setDigestName("SHA-384");
			} else if (offset == 64) {
				setDigestName("SHA-512");
			} else if (offset == 16) {
				setDigestName("MD5");
			} else {
				throw new SignatureException(
						"Message digest length is not supported");
			}

			byte[] result = new byte[offset];
			System.arraycopy(precomputedDigest, 0, result, 0, offset);
			offset = 0;

			return result;
		}
	}

	@Override
	protected void engineInitVerify(PublicKey key)
			throws InvalidKeyException {

		if(!(key instanceof CSPPublicKey)) {
			// берем данные открытого ключа
			if(key instanceof PublicKey) {
				byte[] encoded = key.getEncoded();
				
				if(encoded != null) {
					key = initPublicKey(encoded, encoded.length);
				}
			}
		}

		if(!(key instanceof CSPPublicKey)) {
			throw new InvalidKeyException("Key type not supported");
		}
		publicKey = (CSPPublicKey) key;
		privateKey = null;
		needsReset = true;
		resetDigest();
	}

	private CSPPublicKey initPublicKey(byte[] encoded, int length) throws InvalidKeyException {
		try {
			return NativeCrypto.initPublicKey(encoded, length);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
	}

	@Override
	protected void engineInitSign(PrivateKey key)
			throws InvalidKeyException {

		if(!(key instanceof CSPPrivateKey)) {
			throw new InvalidKeyException("Key type not supported");
		}
		privateKey = (CSPPrivateKey) key;
		publicKey = null;
		needsReset = true;
		resetDigest();
	}

	protected void resetDigest() {
		if(needsReset) {
			messageDigest.reset();
			needsReset = false;
		}
	}

	protected byte[] getDigestValue() throws SignatureException {
		needsReset = false;
		return messageDigest.digest();
	}

	protected void setDigestName(String name) {
		messageDigestAlgorithm = name;
	}

	@Override
	protected void engineUpdate(byte b) throws SignatureException {
		messageDigest.update(b);
		needsReset = true;
	}

	@Override
	protected void engineUpdate(byte[] b, int off, int len)
			throws SignatureException {
		messageDigest.update(b, off, len);
		needsReset = true;
	}

	@Override
	protected void engineUpdate(ByteBuffer input) {
		messageDigest.update(input);
		needsReset = true;
	}

	@Override
	protected byte[] engineSign() throws SignatureException {
		byte[] hash = getDigestValue();
		boolean noHashOID = this instanceof Raw;
		byte[] result;

		result = signHash(noHashOID, hash, hash.length,
				messageDigestAlgorithm,
				privateKey.getProviderId(),
				privateKey.getContainer());
		// Convert signature array from little endian to big endian
		return convertEndianArray(result);
	}

	@SuppressWarnings("unused")
	private byte[] signHash(boolean noHashOID, byte[] hash, int hashSize,
			String messageDigestAlgorithm, 
			long hCryptoProvider, long hCryptoKey) {

		return NativeCrypto.signHash(this, noHashOID, hash, hashSize,
				messageDigestAlgorithm, 
				hCryptoProvider, hCryptoKey);
	}
	
	private byte[] signHash(boolean noHashOID, byte[] hash, int hashSize,
			String messageDigestAlgorithm,
			int providerId, String context) {

		return NativeCrypto.sign(this, noHashOID, hash, hashSize, messageDigestAlgorithm, 
				providerId, context);
	}
	
	private boolean verifySignedHash(byte[] hash, int hashSize,
			String messageDigestAlgorithm,
			byte[] signature, int signatureSize, 
			long hCryptoProvider,
			long hCryptoKey) {

		return NativeCrypto.verifySignedHash(hash, hashSize,
				messageDigestAlgorithm,
				signature, signatureSize,
				hCryptoProvider, hCryptoKey);
	}

	/**
	 * Convert array from big endian to little endian, or vice versa.
	 */
	private byte[] convertEndianArray(byte[] byteArray) {
		if (byteArray == null || byteArray.length == 0)
			return byteArray;

		byte[] retval = new byte[byteArray.length];

		// make it big endian
		for (int i = 0; i < byteArray.length; i++)
			retval[i] = byteArray[byteArray.length - i - 1];

		return retval;
	}

	@Override
	protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
		byte[] hash = getDigestValue();

		return verifySignedHash(hash, hash.length,
				messageDigestAlgorithm,
				convertEndianArray(sigBytes), sigBytes.length, 
				publicKey.getHCryptProvider(),
				publicKey.getHCryptKey());
	}


	@Override
	@Deprecated
	protected void engineSetParameter(String param, Object value)
			throws InvalidParameterException {
	}

	@Override
	@Deprecated
	protected Object engineGetParameter(String param)
			throws InvalidParameterException {
		return null;
	}

	@Override
	protected void engineSetParameter(AlgorithmParameterSpec params)
			throws InvalidAlgorithmParameterException {

		if(params != null) {
			if(parameters == null) {
				parameters = new ArrayList<AlgorithmParameterSpec>();
			}
			parameters.add(params);
		}
	}

	/**
	 * Вызывается из {@link NativeCrypto#digestInit(CSPDigest, String)}
	 * 
	 * @param hCryptoProvider нативный крипто провайдер
	 * @param hCryptoHash нативный крипто хеш
	 * @param length размер хеша в битах
	 */
	public void initDigestParameters(long hCryptoProvider, long hCryptoHash) {
		if(parameters != null)
			for(AlgorithmParameterSpec parameter : parameters)
				if(parameter instanceof DigestParameterSpec)
					((DigestParameterSpec) parameter).initDigestParameter(hCryptoProvider, hCryptoHash);
	}
}
