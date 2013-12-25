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

import java.security.KeyStoreException;

abstract class CSPKey implements java.security.Key {
	private static final long serialVersionUID = 4852829008747501367L;

	protected long hCryptProvider = 0;
	protected long hCryptKey = 0;
	protected int keyLength = 0;
	/**
	 * Название контейнера, в котором находится ключ
	 */
	protected String container;
	/**
	 * Идентификатор провайдера
	 */
	protected int providerId;

	public CSPKey(long hCryptoProvider, long hCryptoKey, int keyLength) {
		this.hCryptProvider = hCryptoProvider;
		this.hCryptKey = hCryptoKey;
		this.keyLength = keyLength;
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
		NativeCrypto.keyDestroy(hCryptProvider, hCryptKey);
		hCryptKey = 0;
		hCryptProvider = 0;
	}

	public int length() {
		return keyLength;
	}

	/**
	 * native HCRYPTPROV
	 */
	public long getHCryptProvider() {
		return hCryptProvider;
	}

	/**
	 * native HCRYPTKEY
	 */
	public long getHCryptKey() {
		return hCryptKey;
	}

	@Override
	public abstract String getAlgorithm();

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}

	public String getContainer() {
		return container;
	}

	public void setContainer(String container) {
		this.container = container;
	}

	public int getProviderId() {
		return providerId;
	}

	public void setProviderId(int providerId) {
		this.providerId = providerId;
	}

	protected static String getContainerName(long hCryptoProv) throws KeyStoreException {
		return NativeCrypto.getContainerName(hCryptoProv);
	}
}
