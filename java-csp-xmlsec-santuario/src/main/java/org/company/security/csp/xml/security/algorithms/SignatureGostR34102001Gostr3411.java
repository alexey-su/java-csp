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
package org.company.security.csp.xml.security.algorithms;

import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.Constants;

public class SignatureGostR34102001Gostr3411 extends SignatureGostR34102001 {

	/** Field _URI */
	public static final String _URI = Constants.MoreAlgorithmsSpecNS + "gostr34102001-gostr3411";

	@Override
	protected String engineGetURI() {
		return SignatureGostR34102001Gostr3411._URI;
	}

	/**
	 * Constructor SignatureGostr34102001Gostr3411
	 *
	 * @throws XMLSignatureException
	 */
	public SignatureGostR34102001Gostr3411() throws XMLSignatureException {
	}
}
