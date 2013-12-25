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

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.interceptor.InterceptorProvider;
import org.apache.cxf.message.Message;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.junit.Assert;

import org.company.security.csp.CSPNative;
import org.company.security.csp.CSPProvider;
import org.company.security.csp.ws.security.action.LocalSignatureAction;
import org.company.security.csp.ws.security.processor.LocalSignatureProcessor;
import org.company.security.csp.wss4j.test.hello_world_soap_http.Greeter;
import org.company.security.csp.wss4j.test.hello_world_soap_http.SOAPService;


public class LocalClient extends Assert {
	private static final String CSP_PROVIDER = "CSPProvider";
	private static final String CSPXML_PROVIDER = "CSPXMLDSig";
	private static final String STORE_NAME = "Windows-MY";
	
	private static final String ALG_OID_GOST_PRIVATEKEY_EXCHANGE = "1.2.643.2.2.98";	// закрытый ключ szOID_CP_DH_EL
	private static final String ALG_OID_GOST_PRIVATEKEY_SIGN = "1.2.643.2.2.99";		// закрытый ключ szOID_CP_DH_EX

	private Greeter greeter;
	private String userKeyAlias;

	
	public LocalClient() throws Exception {
		createProviders();
		createClient();
	}


	public Greeter getGreeter() {
		return greeter;
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
	
	private void createClient() throws Exception {
		SOAPService soapService = new SOAPService(CXFGostTest.class.getClassLoader().getResource("integration/helloWorld.wsdl"));
		greeter = soapService.getSoapPort();
		final Client client = ClientProxy.getClient(greeter);
		
		createClientInterceptors(client);
		
		client.getRequestContext().put(Message.ENDPOINT_ADDRESS, "http://localhost:" + LocalServer.PORT + "/GreeterServiceWSS4J");
	}
	
	private void createClientInterceptors(InterceptorProvider client) {
		
		// определяем собственный класс системы подписывания
		Map<Integer, Class<?>> wssConfigActions = new HashMap<Integer, Class<?>>();
		wssConfigActions.put(Integer.valueOf(WSConstants.SIGN), LocalSignatureAction.class);
		
		Map<QName, Class<?>> wssConfigProcessors = new HashMap<QName, Class<?>>();
		wssConfigProcessors.put(WSSecurityEngine.SIGNATURE, LocalSignatureProcessor.class);

		Map<String, Object> clientOutParams = createClientOutParams(wssConfigActions);
		Map<String, Object> clientInParams = createClientInParams(wssConfigProcessors);
		
		WSS4JOutInterceptor wss4JOutInterceptor = new WSS4JOutInterceptor(clientOutParams);
		//wss4JOutInterceptor.setProperties(clientOutParams);
		client.getOutInterceptors().add(wss4JOutInterceptor);
		
		WSS4JInInterceptor wss4JInInterceptor = new WSS4JInInterceptor(clientInParams);
		//wss4JInInterceptor.setProperties(clientInParams);
		client.getInInterceptors().add(wss4JInInterceptor);

//		LoggingInInterceptor loggingInInterceptor = new LoggingInInterceptor();
//		LoggingOutInterceptor loggingOutInterceptor = new LoggingOutInterceptor();
	}
	
	/**
	 * Параметры клиента отправляющего SOAP сообщение
	 */
	private Map<String, Object> createClientOutParams(
			Map<Integer, Class<?>> wssConnfigMap) {
		
		Map<String, Object> clientOutParams = new HashMap<String, Object>();
		clientOutParams.put("wss4j.action.map", wssConnfigMap);
//		clientOutParams.put(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
		clientOutParams.put(WSHandlerConstants.ACTION, "Timestamp Signature");
		clientOutParams.put(WSHandlerConstants.USER, "transmitter");
		clientOutParams.put(WSHandlerConstants.SIGNATURE_USER, userKeyAlias);
//		clientOutParams.put(WSHandlerConstants.ENCRYPTION_USER, userKeyAlias);
		clientOutParams.put(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
		clientOutParams.put(WSHandlerConstants.SIG_PROP_FILE, "transmitter-crypto.properties");
//		clientOutParams.put(WSHandlerConstants.ENC_PROP_FILE, "transmitter-crypto.properties");
//		params.put(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
//		params.put(WSHandlerConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
		clientOutParams.put(WSHandlerConstants.SIG_DIGEST_ALGO, "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
		clientOutParams.put(WSHandlerConstants.SIG_ALGO, "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411");
		return clientOutParams;
	}

	/**
	 * Параметры клиента принимающего SOAP сообщение
	 */
	private Map<String, Object> createClientInParams(
			Map<QName, Class<?>> wssConfigProcessors) {
		
		Map<String, Object> clientInParams = new HashMap<String, Object>();
		clientInParams.put("wss4j.processor.map", wssConfigProcessors);
//		clientInParams.put(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
		clientInParams.put(WSHandlerConstants.ACTION, "Timestamp Signature");
		clientInParams.put(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
		clientInParams.put(WSHandlerConstants.SIG_PROP_FILE, "transmitter-crypto.properties");
//		clientInParams.put(WSHandlerConstants.DEC_PROP_FILE, "transmitter-crypto.properties");
//		clientInParams.put(Merlin.CRYPTO_CERT_PROVIDER, CSP_PROVIDER);
//		clientInParams.put(Merlin.CRYPTO_KEYSTORE_PROVIDER, CSP_PROVIDER);
		clientInParams.put(WSHandlerConstants.SIG_DIGEST_ALGO, "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
		clientInParams.put(WSHandlerConstants.SIG_ALGO, "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411");
		return clientInParams;
	}

	/**
	 * Находим первый доступный закрытый ключ для подписывания SOAP сообщения
	 * @return
	 * @throws Exception
	 */
	private String findKeyAlias() throws Exception {
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
	
	private boolean isGostKey(String algorithm) {
		return 
				ALG_OID_GOST_PRIVATEKEY_EXCHANGE.equals(algorithm) ||
				ALG_OID_GOST_PRIVATEKEY_SIGN.equals(algorithm);
	}
	
}
