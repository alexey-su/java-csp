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
package org.company.security.csp.wss4j.test;

import java.security.KeyStore;
import java.security.Security;
import java.util.Enumeration;
import java.util.Properties;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.company.security.csp.CSPNative;
import org.company.security.csp.CSPProvider;
import org.company.security.csp.ws.security.components.crypto.LocalMerlin;

public class LocalMerlinTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(LocalMerlinTest.class);
	
	public static final String CSP_PROVIDER = "CSPProvider";
	public static final String CSPXML_PROVIDER = "CSPXMLDSig";
	public static final String STORE_NAME = "Windows-MY";

	@Test
	public void test() throws Exception {
		createProviders();
		Properties config = getConfig();
		LocalMerlin crypto = new LocalMerlin(config);
		
		LOGGER.debug("LocalMerlin получение ключей");
		Enumeration<String> aliases = crypto.getKeyStore().aliases();
		int size = 0;
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			LOGGER.debug("LocalMerlin load alias {}", alias);
			size++;
		}
		LOGGER.debug("Количество ключей в хранилище {}", size); 
	}

	/**
	 * Регистрация криптографических поставщиков
	 */
	private void createProviders() throws Exception {
		CSPNative.init("target/native", null);
		
		// Поставщик хеш функций и подписей
		if(Security.getProvider(CSP_PROVIDER) == null)
			Security.addProvider(new CSPProvider());
	}
	
	private Properties getConfig() {
		Properties prop = new Properties();
		prop.put("org.apache.ws.security.crypto.provider", "org.company.security.csp.ws.security.components.crypto.LocalMerlin");
		prop.put("org.apache.ws.security.crypto.merlin.cert.provider", "CSPProvider");
		prop.put("org.apache.ws.security.crypto.merlin.keystore.provider", "CSPProvider");
		prop.put("org.apache.ws.security.crypto.merlin.keystore.type", "Windows-MY");
		prop.put("org.apache.ws.security.crypto.merlin.truststore.type", "Windows-MY");
		return prop;
	}
	
	/**
	 * Находим первый доступный закрытый ключ для подписывания SOAP сообщения
	 * @return
	 * @throws Exception
	 */
	@Test
	public void findKeyAlias() throws Exception {
		KeyStore keyStore = java.security.KeyStore.getInstance(STORE_NAME, CSP_PROVIDER);
		keyStore.load(null, null);
		
		LOGGER.debug("KeyStore получение ключей");
		int size = 0;
		for(Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
			String alias = aliases.nextElement();
			LOGGER.debug("KeyStore load alias {}", alias);
			size++;
		}
		LOGGER.debug("Количество ключей в хранилище {}", size); 
	}
}
