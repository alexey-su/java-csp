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

import java.lang.reflect.Field;
import java.security.Security;

import javax.xml.stream.XMLInputFactory;

import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.testutil.common.AbstractBusClientServerTestBase;
import org.junit.BeforeClass;
import org.junit.Test;

import org.company.security.csp.CSPNative;
import org.company.security.csp.CSPProvider;
import org.company.security.csp.wss4j.test.hello_world_soap_http.Greeter;

public class CXFGostTest extends AbstractBusClientServerTestBase {
	private static final String CSP_PROVIDER = "CSPProvider";
	private static final String CSPXML_PROVIDER = "CSPXMLDSig";
	private static final String STORE_NAME = "Windows-MY";
	private static final String ALG_OID_GOST_PRIVATEKEY_EXCHANGE = "1.2.643.2.2.98";	// закрытый ключ обмена
	private static final String ALG_OID_GOST_PRIVATEKEY_SIGN = "1.2.643.2.2.99";		// закрытый ключ подписи

	private static Greeter clientGreeterStream;
	private static String userKeyAlias;
	private static LocalClient localClient;

	static {
		try {
			Field xmlInputFactoryField = StaxUtils.class.getDeclaredField("SAFE_INPUT_FACTORY");
			xmlInputFactoryField.setAccessible(true);
			XMLInputFactory xmlInputFactory = (XMLInputFactory)xmlInputFactoryField.get(null);
			xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, Boolean.FALSE);

			// подгружаем в Apache Santuario xmlsign ГОСТ ЭЦП
//			XmlDSignTools.init();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Регистрация криптографических поставщиков
	 */
	private static void createProviders() throws Exception {
		CSPNative.init("target/native", null);

		// Поставщик хеш функций и подписей
		if(Security.getProvider(CSP_PROVIDER) == null)
			Security.addProvider(new CSPProvider());

		// Поставщик XML dsign JSR-105
		if(Security.getProvider(CSPXML_PROVIDER) == null)
			Security.addProvider(new org.company.security.csp.xml.dsig.internal.dom.XMLDSigRI());
	}

	@BeforeClass
	public static void beforeClass() throws Exception {
		// Регистрация криптографических поставщиков
		createProviders();

		if(LocalServer.findKeyAlias() != null) {
			assertTrue("Server failed to launch", launchServer(LocalServer.class, true));

			// стартуем локальную шину веб сервисов
			createStaticBus();

			// создаем локального клиента
			localClient = new LocalClient();
		}
	}

	@Test
	public void f() {
		if(localClient != null)
			localClient.getGreeter().greetMe("Cold start");
	}
}
