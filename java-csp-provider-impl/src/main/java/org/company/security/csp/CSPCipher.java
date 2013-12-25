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

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class CSPCipher extends CipherSpi {

	private static final int MODE_ENCRYPT = 1;
	private static final int MODE_DECRYPT = 2;
	private static final int MODE_SIGN = 3;
	private static final int MODE_VERIFY = 4;

	private static final int KP_BLOCKLEN = 8;	// Block size of the cipher
	private static final int KP_KEYLEN = 9;	// Length of key in bits

	private int mode;
	private String paddingType;
	private int paddingLength = 0;
	private int outputSize;
	
	
	private CSPKey publicKey;
	private CSPKey privateKey;


	public CSPCipher() {
	}

	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {

	}

	@Override
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {
		paddingType = padding;
	}

	@Override
	protected int engineGetBlockSize() {
		return 0;
	}

	@Override
	protected int engineGetOutputSize(int inputLen) {
		return outputSize;
	}

	@Override
	protected byte[] engineGetIV() {
		return null;
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {
		return null;
	}

	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
		init(opmode, key);
	}


	@Override
	protected void engineInit(int opmode, Key key,
			AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		
		if(params != null)
			throw new InvalidAlgorithmParameterException("Parameters not supported");
		init(opmode, key);
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {

		if(params != null)
			throw new InvalidAlgorithmParameterException("Parameters not supported");
		init(opmode, key);
	}

	private void init(int opmode, Key key) throws InvalidKeyException {
		boolean encrypt;
		
		switch(opmode) {
		case Cipher.ENCRYPT_MODE:
		case Cipher.WRAP_MODE:
			encrypt = true;
			break;
		case Cipher.DECRYPT_MODE:
		case Cipher.UNWRAP_MODE:
			paddingLength = 0;
			encrypt = false;
			break;
		default:
			throw new InvalidKeyException("Unknown mode: " + opmode);
		}

		if(!(key instanceof CSPKey)) {
			if(key instanceof PublicKey) {
				CSPPublicKey publicKey = importPublicKey(key);
				
				if(publicKey == null) {
					throw new InvalidKeyException("Unsupported key type: " + key);
				}
				key = publicKey;
			}
			else {
				throw new InvalidKeyException("Unsupported key type: " + key);
			}
		}
		else if(encrypt) {
			paddingLength = getPaddingLength(((CSPKey) key).getHCryptKey());
		}

		if(key instanceof PublicKey) {
			mode = encrypt ? MODE_ENCRYPT : MODE_VERIFY;
			publicKey = (CSPPublicKey) key;
			privateKey = null;
			outputSize = publicKey.length() / 8;
		}
		else if(key instanceof java.security.PrivateKey) {
			mode = encrypt ? MODE_SIGN : MODE_DECRYPT;
			privateKey = (CSPPrivateKey) key;
			publicKey = null;
			outputSize = privateKey.length() / 8;
		}
		else {
			throw new InvalidKeyException("Unsupported key type: " + key);
		}
	}

	private CSPPublicKey importPublicKey(Key key) throws InvalidKeyException {
		byte[] keyEncoded = key.getEncoded();
		try {
			return NativeCrypto.initPublicKey(keyEncoded, keyEncoded.length);
		} catch (NoSuchAlgorithmException e) {
			throw new InvalidKeyException(e.getMessage(), e);
		}
	}

	private int getPaddingLength(long hCryptoKey) {
		try {
			return NativeCrypto.getKeyParam(hCryptoKey, KP_BLOCKLEN);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
	}

	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		return engine(input, inputOffset, inputLen, false);
	}

	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException {
		
		byte[] result = engine(input, inputOffset, inputLen, true);
		int n = result.length;
		
		if(outputOffset + n > output.length) {
			throw new ShortBufferException("Data must not be longer than " + (output.length - outputOffset)  + " bytes");
		}
		System.arraycopy(result, 0, output, outputOffset, n);
		return n;
	}

	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {

		return engine(input, inputOffset, inputLen, true);
	}

	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {

		byte[] result = engine(input, inputOffset, inputLen, true);
		int n = result.length;
		
		if(outputOffset + n > output.length) {
			if(n > inputLen)
				throw new BadPaddingException("Data must not be longer (" + n + ") than " + (output.length - outputOffset)  + " bytes");
			else
				throw new IllegalBlockSizeException("Data must not be longer than " + (output.length - outputOffset)  + " bytes");
		}
		System.arraycopy(result, 0, output, outputOffset, n);
		return n;
	}

	private byte[] engine(byte[] input, int inputOffset, int inputLen, boolean doFinal) {
		try {
			switch (mode) {
			case MODE_SIGN:
				return encryptDecrypt(input, inputOffset, inputLen,
						privateKey.getHCryptKey(), true, doFinal, paddingLength);

			case MODE_VERIFY:
				return encryptDecrypt(input, inputOffset, inputLen,
						publicKey.getHCryptKey(), false, doFinal, paddingLength);

			case MODE_ENCRYPT:
				return encryptDecrypt(input, inputOffset, inputLen,
						publicKey.getHCryptKey(), true, doFinal, paddingLength);

			case MODE_DECRYPT:
				return encryptDecrypt(input, inputOffset, inputLen,
						privateKey.getHCryptKey(), false, doFinal, paddingLength);

			default:
				throw new AssertionError("Internal error");
			}

		} catch (InvalidKeyException e) {
			throw new ProviderException(e);
		}
	}
	
	private byte[] encryptDecrypt(byte[] data, int dataOffset, int dataSize, long hCryptKey, 
			boolean doEncrypt, boolean doFinal,
			int paddingLength) throws InvalidKeyException {
		return NativeCrypto.encryptDecrypt(data, dataOffset, dataSize, hCryptKey, doEncrypt, doFinal, paddingLength);
	}
}
