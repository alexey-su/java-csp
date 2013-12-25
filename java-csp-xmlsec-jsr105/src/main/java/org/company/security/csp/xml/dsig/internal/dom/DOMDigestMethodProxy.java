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
import java.security.spec.AlgorithmParameterSpec;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.spec.DigestMethodParameterSpec;

import org.w3c.dom.Element;

public class DOMDigestMethodProxy extends BaseStructure implements DigestMethod {
	private String xmlAlgorithm;
	private String jceAlgorithm;
	private DigestMethodParameterSpec params;

	public DOMDigestMethodProxy(String xmlAlgorithm, String jceAlgorithm,
			DigestMethodParameterSpec params)
			throws InvalidAlgorithmParameterException {
		this.xmlAlgorithm = xmlAlgorithm;
		this.jceAlgorithm = jceAlgorithm;

		if (params != null && !(params instanceof DigestMethodParameterSpec)) {
			throw new InvalidAlgorithmParameterException(
					"params must be of type DigestMethodParameterSpec");
		}
		checkParams((DigestMethodParameterSpec) params);
		this.params = (DigestMethodParameterSpec) params;
	}

	public String getMessageDigestAlgorithm() {
		return jceAlgorithm;
	}

	@Override
	public String getAlgorithm() {
		return xmlAlgorithm;
	}

	@Override
	public AlgorithmParameterSpec getParameterSpec() {
		return params;
	}

	/**
	 * Checks if the specified parameters are valid for this algorithm. By
	 * default, this method throws an exception if parameters are specified
	 * since most DigestMethod algorithms do not have parameters. Subclasses
	 * should override it if they have parameters.
	 * 
	 * @param params
	 *            the algorithm-specific params (may be <code>null</code>)
	 * @throws InvalidAlgorithmParameterException
	 *             if the parameters are not appropriate for this digest method
	 */
	void checkParams(DigestMethodParameterSpec params)
			throws InvalidAlgorithmParameterException {
		if (params != null) {
			throw new InvalidAlgorithmParameterException("no parameters "
					+ "should be specified for the "
					+ getMessageDigestAlgorithm() + " DigestMethod algorithm");
		}
	}

	/**
	 * Unmarshals <code>DigestMethodParameterSpec</code> from the specified
	 * <code>Element</code>. By default, this method throws an exception since
	 * most DigestMethod algorithms do not have parameters. Subclasses should
	 * override it if they have parameters.
	 * 
	 * @param paramsElem
	 *            the <code>Element</code> holding the input params
	 * @return the algorithm-specific <code>DigestMethodParameterSpec</code>
	 * @throws MarshalException
	 *             if the parameters cannot be unmarshalled
	 */
	public DigestMethodParameterSpec unmarshalParams(Element paramsElem)
			throws MarshalException {
		throw new MarshalException("no parameters should "
				+ "be specified for the " + getMessageDigestAlgorithm()
				+ " DigestMethod algorithm");
	}
}
