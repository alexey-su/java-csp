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

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.ws.security.components.crypto.CryptoType;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.company.security.csp.CSPNative;
import org.company.security.csp.CSPProvider;
import org.company.security.csp.ws.security.components.crypto.LocalMerlin;

public class KeyStoreFileTest {
	private static final String CSP_PROVIDER = "CSPProvider";

	private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreFileTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		CSPNative.init("target/native", null);
	
		// Поставщик хеш функций и подписей
		if(Security.getProvider(CSP_PROVIDER) == null)
			Security.addProvider(new CSPProvider());
	}

	@Test
	public void test() throws Exception {
		Properties prop = new Properties();

		// настройка системы криптографии
		prop.put("org.apache.ws.security.crypto.provider", "org.company.security.csp.ws.security.components.crypto.LocalMerlin");
		prop.put("org.apache.ws.security.crypto.merlin.cert.provider", "CSPProvider");
		prop.put("org.apache.ws.security.crypto.merlin.keystore.provider", "CSPProvider");
		prop.put("org.apache.ws.security.crypto.merlin.keystore.type", "Windows-MY");
//		prop.put("org.apache.ws.security.crypto.merlin.truststore.type", "Linux-AddressBook");
		prop.put("org.apache.ws.security.crypto.merlin.truststore.type", "FILE");
		prop.put("org.apache.ws.security.crypto.merlin.truststore.password", "");
		prop.put("org.apache.ws.security.crypto.merlin.truststore.file", "target/test-classes/trusted/cert.sst");



		LocalMerlin crypto = new LocalMerlin(prop);

		KeyStore keyStore = crypto.getTrustStore();
		assertNotNull("Не загрузилось хранилище доверенных сертификатов", keyStore);

		Enumeration<String> aliases = keyStore.aliases();
		String issuerName = null;
		BigInteger serial = null;

		assertTrue("В хранилище нет сертификатов", aliases.hasMoreElements());

		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
			boolean keyEntry = keyStore.isKeyEntry(alias);

			LOGGER.debug("Ключ {}" +
					"\n\tSubject {}" +
					"\n\tS/N     {}" +
					"\n\tIssuer  {}" +
					"\n\tKeyEntry {}",
					new Object[]{ 
					alias,
					cert.getSubjectDN().getName(),
					cert.getSerialNumber().toString(16),
					cert.getIssuerDN().getName(),
					keyEntry
					});

			issuerName = cert.getIssuerX500Principal().getName();
			serial = cert.getSerialNumber();
		}

		assertNotNull("Не удалось получить IssuerName", issuerName);
		assertNotNull("Не удалось получить SerialNumber", serial);

		CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
		cryptoType.setIssuerSerial(issuerName, serial);

		X509Certificate[] certificates = crypto.getX509Certificates(cryptoType);
		int count = certificates != null ? certificates.length : 0;

		assertEquals("Не найден сертификат", 1, count);
	}

}
