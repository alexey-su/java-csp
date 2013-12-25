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

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.CredentialException;
import org.apache.ws.security.components.crypto.Merlin;

import org.company.security.csp.CSPKeyStore;

/**
 * Замена базового провайдера работы с хранилищами сертификатов и ключей.
 * <br/>Цель - использование особенностей работы c хранилищем закрытых ключей JCP (HDImageStore).
 */
public class LocalMerlin extends Merlin {
	private static final String CSP_PROVIDER = "CSPProvider";
	private static final String CSP_STORE_TYPE_FILE = "FILE";
	private static final String HD_IMAGE_STORE = "HDImageStore";
	private static final org.apache.commons.logging.Log LOG = 
			org.apache.commons.logging.LogFactory.getLog(Merlin.class);

	/**
	 * Дубликат закрытой функции из базового класса.
	 */
	private static String createKeyStoreErrorMessage(KeyStore keystore) throws KeyStoreException {
		Enumeration<String> aliases = keystore.aliases();
		StringBuilder sb = new StringBuilder(keystore.size() * 7);
		boolean firstAlias = true;
		while (aliases.hasMoreElements()) {
			if (!firstAlias) {
				sb.append(", ");
			}
			sb.append(aliases.nextElement());
			firstAlias = false;
		}
		String msg = " in keystore of type [" + keystore.getType()
				+ "] from provider [" + keystore.getProvider()
				+ "] with size [" + keystore.size() + "] and aliases: {"
				+ sb.toString() + "}";
		return msg;
	}
	
	
	public LocalMerlin() {
		super();
	}

	public LocalMerlin(Properties properties, ClassLoader loader)
			throws CredentialException, IOException {
		super(properties, loader);
	}

	public LocalMerlin(Properties properties) throws CredentialException,
			IOException {
		super(properties);
	}

	/**
	 * Базовый Merlin не загружает хранилище личных ключей и доверенных сертификатов,
	 * если файл не указан.
	 * <br/>Цель - при отсутствии имени файла, система поднимает хранилище личных ключей.
	 */
	@Override
	public void loadProperties(Properties properties, ClassLoader loader)
			throws CredentialException, IOException {
		super.loadProperties(properties, loader);
		
		String provider = properties.getProperty(CRYPTO_KEYSTORE_PROVIDER);
		if (provider != null)
			provider = provider.trim();
		
		if(CSP_PROVIDER.equals(provider)) {
			// если тип хранилища FILE, надо загрузить его другим способом
			if(keystore != null && CSP_STORE_TYPE_FILE.equals(keystore.getType())) {
				keystore = null;
			}

			if(keystore == null) {
				String passwd = properties.getProperty(KEYSTORE_PASSWORD); //, "security");
				String type = properties.getProperty(KEYSTORE_TYPE, KeyStore.getDefaultType());
				String keyStoreLocation = properties.getProperty(KEYSTORE_FILE);
				if (keyStoreLocation == null) {
					keyStoreLocation = properties.getProperty(OLD_KEYSTORE_FILE);
				}

				if(passwd != null)
					passwd = passwd.trim();
				if(type != null)
					type = type.trim();

				keystore = load(null, passwd, provider, type, keyStoreLocation);
			}

			// если тип хранилища FILE, надо загрузить его другим способом
			if(truststore != null && CSP_STORE_TYPE_FILE.equals(truststore.getType())) {
				truststore = null;
			}

			if(truststore == null) {
				String passwd = properties.getProperty(TRUSTSTORE_PASSWORD); //, "changeit");
				String type = properties.getProperty(TRUSTSTORE_TYPE, KeyStore.getDefaultType());
				String trustStoreLocation = properties.getProperty(TRUSTSTORE_FILE);

				if(passwd != null)
					passwd = passwd.trim();
				if(type != null)
					type = type.trim();

				truststore = load(null, passwd, provider, type, trustStoreLocation);
			}
		}
	}
	/**
	 * Loads the keystore from an <code>InputStream </code>.
	 * <p/>
	 *
	 * @param input <code>InputStream</code> to read from
	 * @throws CredentialException
	 */
	public KeyStore load(InputStream input, String storepass, String provider, String type, String keyStoreLocation) 
			throws CredentialException {
		KeyStore ks = null;

		
		if(CSP_PROVIDER.equals(provider)) {
			try {
				if(CSP_STORE_TYPE_FILE.equals(type) && keyStoreLocation != null) {
					ks = CSPKeyStore.Builder.newInstance(type, 
							Security.getProvider(provider), 
							keyStoreLocation, 
							(storepass != null ? storepass.toCharArray() : null)).getKeyStore();
				}
				else {
					ks = KeyStore.getInstance(type, provider);
					ks.load(input, (storepass != null && storepass.length() != 0 ? storepass.toCharArray() : null));
				}
	        } catch (IOException e) {
	            if (LOG.isDebugEnabled()) {
	                LOG.debug(e.getMessage(), e);
	            }
	            throw new CredentialException(CredentialException.IO_ERROR, "ioError00", e);
	        } catch (GeneralSecurityException e) {
	            if (LOG.isDebugEnabled()) {
	                LOG.debug(e.getMessage(), e);
	            }
	            throw new CredentialException(CredentialException.SEC_ERROR, "secError00", e);
	        } catch (Exception e) {
	            if (LOG.isDebugEnabled()) {
	                LOG.debug(e.getMessage(), e);
	            }
	            throw new CredentialException(CredentialException.FAILURE, "error00", e);
	        }
		}
		else {
			ks = super.load(input, storepass, provider, type);
		}
		
		return ks;
	}

	/**
	 * Gets the private key corresponding to the identifier.
	 *
	 * @param identifier The implementation-specific identifier corresponding to the key
	 * @param password The password needed to get the key
	 * @return The private key
	 */
	@Override
	public PrivateKey getPrivateKey(
			String identifier,
			String password
			) throws WSSecurityException {
		if (keystore == null) {
			throw new WSSecurityException("The keystore is null");
		}
		try {
			if (identifier == null || !keystore.isKeyEntry(identifier)) {
				String msg = "Cannot find key for alias: [" + identifier + "]";
				String logMsg = createKeyStoreErrorMessage(keystore);
				LOG.error(msg + logMsg);
				throw new WSSecurityException(msg);
			}
			if (password == null && privatePasswordSet) {
				password = properties.getProperty(KEYSTORE_PRIVATE_PASSWORD);
				if (password != null) {
					password = password.trim();
				}
			}
			
			Key keyTmp = loadPrivateKey(identifier, password);
			if (!(keyTmp instanceof PrivateKey)) {
				String msg = "Key is not a private key, alias: [" + identifier + "]";
				String logMsg = createKeyStoreErrorMessage(keystore);
				LOG.error(msg + logMsg);
				throw new WSSecurityException(msg);
			}
			return (PrivateKey) keyTmp;
		} catch (KeyStoreException ex) {
			throw new WSSecurityException(
					WSSecurityException.FAILURE, "noPrivateKey", new Object[]{ex.getMessage()}, ex
					);
		} catch (UnrecoverableKeyException ex) {
			throw new WSSecurityException(
					WSSecurityException.FAILURE, "noPrivateKey", new Object[]{ex.getMessage()}, ex
					);
		} catch (NoSuchAlgorithmException ex) {
			throw new WSSecurityException(
					WSSecurityException.FAILURE, "noPrivateKey", new Object[]{ex.getMessage()}, ex
					);
		}
	}

	/**
	 * Получение закрытого ключа из хранилища.
	 * <p>Для хранилища HDImageStore пустой пароль передается как null.
	 * Базовый вариант передает пустой массив char[]{}. 
	 */
	protected Key loadPrivateKey(String identifier, String password)
			throws KeyStoreException, NoSuchAlgorithmException,
			UnrecoverableKeyException {
		
		char[] passwordArray = null;
		
		if(password == null) { 
			String type = keystore.getType();
			if(HD_IMAGE_STORE.equals(type))
				passwordArray = null;
			else
				passwordArray = new char[]{};
		}
		else {
			passwordArray = password.toCharArray();
		}
		
		Key keyTmp = keystore.getKey(identifier, passwordArray);
		
		return keyTmp;
	}
}
