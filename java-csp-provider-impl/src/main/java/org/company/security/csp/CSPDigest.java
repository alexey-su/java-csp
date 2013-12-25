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

import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigestSpi;


public abstract class CSPDigest extends MessageDigestSpi {

	public static class GOST3411 extends CSPDigest {

		public GOST3411() {
			super("GOST3411");
		}
	}

	public static class GOST3411_SafeTouch extends CSPDigest {

		public GOST3411_SafeTouch() {
			super("GOST3411");
		}

		@Override
		public void initDigest(long hCryptoProvider, long hCryptoHash, int length) {
			super.initDigest(hCryptoProvider, hCryptoHash, length);
			
			// включаем отображение данных на экране
		}
		
	}

	protected final String algorithm;
	protected long hCryptoProvider = 0;
	protected long hCryptoHash = 0;
	protected int length;
	private boolean init = false;

	public CSPDigest(String algorithm) {
		this.algorithm = algorithm;
	}

	private void engineInit() {
		if(!init) {
			synchronized (this) {
				if(!init) {
					try {
						NativeCrypto.digestInit(this, algorithm);
					} catch (GeneralSecurityException e) {
						throw new IllegalArgumentException(e.getMessage(), e);
					}
				}
			}
		}
	}

	/**
	 * Вызывается из {@link NativeCrypto#digestInit(CSPDigest, String)}
	 * 
	 * @param hCryptoProvider нативный крипто провайдер
	 * @param hCryptoHash нативный крипто хеш
	 * @param length размер хеша в битах
	 */
	public void initDigest(long hCryptoProvider, long hCryptoHash, int length) {
		this.hCryptoProvider = hCryptoProvider;
		this.hCryptoHash = hCryptoHash;
		this.length = length;
		this.init = hCryptoHash != 0;
	}

	@Override
	protected void finalize() throws Throwable {
		try {
			synchronized(this) {
				destroy();
			}
		}
		finally {
			super.finalize();
		}
	}

	public void destroy() {
		NativeCrypto.digestDestroy(hCryptoProvider, hCryptoHash);
		hCryptoHash = 0;
		hCryptoProvider = 0;
		init = false;
	}

	@Override
	protected void engineUpdate(byte input) {
		engineInit();
		try {
			NativeCrypto.digestEngineUpdateByte(hCryptoHash, input);
		} catch (DigestException e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		engineInit();
		try {
			NativeCrypto.digestEngineUpdateBytes(hCryptoHash, input, offset, len);
		} catch (DigestException e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
	}

	@Override
	protected byte[] engineDigest() {
		engineInit();
		try {
			return NativeCrypto.digestEngineDigest(hCryptoHash);
		} catch (DigestException e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
	}

	@Override
	protected void engineReset() {
		destroy();
	}
}
