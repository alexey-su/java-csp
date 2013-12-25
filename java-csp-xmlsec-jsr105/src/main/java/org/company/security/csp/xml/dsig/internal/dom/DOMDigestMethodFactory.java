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
package org.company.security.csp.xml.dsig.internal.dom;

import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.spec.DigestMethodParameterSpec;

import org.apache.xml.security.algorithms.JCEMapper;
import org.w3c.dom.Element;

public class DOMDigestMethodFactory {
	
	public DigestMethod unmarshal(Element dmElem) throws MarshalException {
		String xmlAlgorithm = DOMUtils.getAttributeValue(dmElem, "Algorithm");
		String jceAlgorithm = JCEMapper.translateURItoJCEID(xmlAlgorithm);
		DigestMethodParameterSpec params = null;
		
		if(jceAlgorithm != null) {
			try {
				MessageDigest.getInstance(jceAlgorithm);
			}
			catch(NoSuchAlgorithmException e) {
				throw new MarshalException("unsupported DigestMethod algorithm: " + xmlAlgorithm, e);
			}
		}
		else {
			throw new MarshalException("unsupported DigestMethod algorithm: " + xmlAlgorithm);
		}
		
		DOMDigestMethodProxy proxy = null;
		try {
			proxy = new DOMDigestMethodProxy(xmlAlgorithm, jceAlgorithm, params);
			
			Element paramsElem = DOMUtils.getFirstChildElement(dmElem);
			if (paramsElem != null) {
				params = proxy.unmarshalParams(paramsElem);

				if (params != null) {
					proxy.checkParams(params);
					proxy = new DOMDigestMethodProxy(xmlAlgorithm, jceAlgorithm, params);
				}
			}
		} 
		catch (InvalidAlgorithmParameterException iape) {
			throw new MarshalException(iape);
		}
		return proxy;
	}
	
	public DigestMethod newDigestMethod(String algorithm,
			DigestMethodParameterSpec params) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		
		String jceAlgorithm = JCEMapper.translateURItoJCEID(algorithm);
		
		if(jceAlgorithm != null) {
			MessageDigest.getInstance(jceAlgorithm);
		}
		else {
			throw new NoSuchAlgorithmException("unsupported algorithm " + algorithm); 
		}
		
		return new DOMDigestMethodProxy(algorithm, jceAlgorithm, params);
	}
}
