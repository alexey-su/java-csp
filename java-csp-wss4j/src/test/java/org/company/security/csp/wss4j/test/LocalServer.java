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

import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.ws.Endpoint;

import org.apache.cxf.interceptor.InterceptorProvider;
import org.apache.cxf.interceptor.LoggingInInterceptor;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.testutil.common.AbstractBusTestServerBase;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.company.security.csp.CSPNative;
import org.company.security.csp.CSPProvider;
import org.company.security.csp.ws.security.action.LocalSignatureAction;
import org.company.security.csp.ws.security.processor.LocalSignatureProcessor;
import org.company.security.csp.wss4j.test.hello_world_soap_http.GreeterServiceImpl;


public class LocalServer extends AbstractBusTestServerBase {
	private static final Logger LOGGER = LoggerFactory.getLogger(LocalServer.class);

	private static final String CSP_PROVIDER = "CSPProvider";
	private static final String CSPXML_PROVIDER = "CSPXMLDSig";
	private static final String STORE_NAME = "Windows-MY";
	private static final String ALG_OID_GOST_PRIVATEKEY_EXCHANGE = "1.2.643.2.2.98";	// szOID_CP_DH_EL "1.2.643.2.2.98"
	private static final String ALG_OID_GOST_PRIVATEKEY_SIGN = "1.2.643.2.2.99";		// szOID_CP_DH_EX "1.2.643.2.2.99"

	public static final String PORT = allocatePort(LocalServer.class);
	private static Object userKeyAlias;

	private Endpoint ep;

	protected void run() {
		System.setProperty("org.apache.cxf.bus.factory", "org.apache.cxf.bus.CXFBusFactory");
		Object implementor = new GreeterServiceImpl();
		String address = "http://localhost:" + PORT + "/GreeterServiceWSS4J";
		ep = Endpoint.create(implementor);
		Map<String, Object> props = new HashMap<String, Object>(2);
		ep.setProperties(props);
		
		if(ep instanceof InterceptorProvider) {
			try {
				createProviders();
				createServerInterceptors((InterceptorProvider) ep);
			}
			catch(Exception e) {
				LOGGER.error(e.getMessage(), e);
				fail(e.getMessage());
			}
		}

		ep.publish(address);
	}

	public void tearDown() {
		ep.stop();
		ep = null;
	}
	
	private void createServerInterceptors(InterceptorProvider server) {

		// определяем собственный класс системы подписывания
		Map<Integer, Class<?>> wssConfigActions = new HashMap<Integer, Class<?>>();
		wssConfigActions.put(Integer.valueOf(WSConstants.SIGN), LocalSignatureAction.class);

		Map<QName, Class<?>> wssConfigProcessors = new HashMap<QName, Class<?>>();
		wssConfigProcessors.put(WSSecurityEngine.SIGNATURE, LocalSignatureProcessor.class);
		
		Map<String, Object> serverOutParams = createServerOutParams(wssConfigActions);
		Map<String, Object> serverInParams = createServerInParams(wssConfigProcessors);
		
		WSS4JOutInterceptor wss4JOutInterceptor = new WSS4JOutInterceptor(serverOutParams);
		//wss4JOutInterceptor.setProperties(serverOutParams);
		server.getOutInterceptors().add(wss4JOutInterceptor);
		
		WSS4JInInterceptor wss4JInInterceptor = new WSS4JInInterceptor(serverInParams);
		//wss4JInInterceptor.setProperties(serverInParams);
		server.getInInterceptors().add(wss4JInInterceptor);

		LoggingInInterceptor loggingInInterceptor = new LoggingInInterceptor();
		LoggingOutInterceptor loggingOutInterceptor = new LoggingOutInterceptor();

		server.getOutInterceptors().add(loggingOutInterceptor);
		server.getOutFaultInterceptors().add(loggingOutInterceptor);

		server.getInInterceptors().add(loggingInInterceptor);
		server.getInFaultInterceptors().add(loggingInInterceptor);
	}

	/**
	 * Регистрация криптографических поставщиков
	 */
	private void createProviders() throws Exception {
		CSPNative.init("target/native", null);

		// Поставщик хеш функций и подписей
		if(Security.getProvider(CSP_PROVIDER) == null)
			Security.addProvider(new CSPProvider());

		// Поставщик XML dsign JSR-105
		if(Security.getProvider(CSPXML_PROVIDER) == null)
			Security.addProvider(new org.company.security.csp.xml.dsig.internal.dom.XMLDSigRI());

		userKeyAlias = findKeyAlias();
		assertNotNull("Нет ключа подписи", userKeyAlias);
	}

	public static String findKeyAlias() throws Exception {
		KeyStore keyStore = java.security.KeyStore.getInstance(STORE_NAME, CSP_PROVIDER);
		keyStore.load(null, null);
		
		for(Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
			String alias = aliases.nextElement();
			Key key = keyStore.getKey(alias, null);

			if(key != null) {
				// берем только ГОСТ ключи
				if(isGostKey(key.getAlgorithm())) {
					X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);

					try {
						certificate.checkValidity();
						return alias;
					}
					catch(CertificateExpiredException ignore) {}
					catch (CertificateNotYetValidException ignore) {}
				}
			}
		}
		return null;
	}

	private static boolean isGostKey(String algorithm) {
		return 
				ALG_OID_GOST_PRIVATEKEY_EXCHANGE.equals(algorithm) ||
				ALG_OID_GOST_PRIVATEKEY_SIGN.equals(algorithm);
	}

	/**
	 * Параметры сервера отправляющего SOAP сообщение
	 */
	private static Map<String, Object> createServerOutParams(
			Map<Integer, Class<?>> wssConfigActions) {
		Map<String, Object> serverOutParams = new HashMap<String, Object>();
		serverOutParams.put("wss4j.action.map", wssConfigActions);
//		serverOutParams.put(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
		serverOutParams.put(WSHandlerConstants.ACTION, "Timestamp Signature");
		serverOutParams.put(WSHandlerConstants.USER, "transmitter");
		serverOutParams.put(WSHandlerConstants.SIGNATURE_USER, userKeyAlias);
		serverOutParams.put(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
		serverOutParams.put(WSHandlerConstants.SIG_PROP_FILE, "receiver-crypto.properties");
		serverOutParams.put(WSHandlerConstants.SIG_DIGEST_ALGO, "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
		serverOutParams.put(WSHandlerConstants.SIG_ALGO, "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411");
		return serverOutParams;
	}

	/**
	 * Параметры клиента принимающего SOAP сообщение
	 */
	private static Map<String, Object> createServerInParams(
			Map<QName, Class<?>> wssConfigProcessors) {
		Map<String, Object> serverInParams = new HashMap<String, Object>();
		serverInParams.put("wss4j.processor.map", wssConfigProcessors);
//		serverInParams.put(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
		serverInParams.put(WSHandlerConstants.ACTION, "Timestamp Signature");
		serverInParams.put(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
		serverInParams.put(WSHandlerConstants.SIG_PROP_FILE, "receiver-crypto.properties");
		serverInParams.put(WSHandlerConstants.SIG_DIGEST_ALGO, "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
		serverInParams.put(WSHandlerConstants.SIG_ALGO, "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411");
		return serverInParams;
	}
	
	public static void main(String[] args) {
		try {
			LocalServer s = new LocalServer();
			s.start();
		} catch (Exception ex) {
			ex.printStackTrace();
			System.exit(-1);
		} finally {
			System.out.println("done!");
		}
	}

}
