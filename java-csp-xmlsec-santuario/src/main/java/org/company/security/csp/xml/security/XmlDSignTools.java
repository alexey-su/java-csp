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
package org.company.security.csp.xml.security;

import java.security.Provider;
import java.security.Security;


//import org.apache.ws.security.WSSConfig;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.Constants;
import org.company.security.csp.xml.security.algorithms.SignatureGostR34102001Gostr3411;
import org.company.security.csp.xml.security.algorithms.SignatureGostR34102001URN;


/**
 * Инициализация XMLDSIGN.
 * Базовый JCPxml не инициализируется в следствии разных ClassLoader.
 */
public class XmlDSignTools {
	public static final String URL_V1_ALGORITHM_DIGEST = Constants.MoreAlgorithmsSpecNS + "gostr3411";
	public static final String URL_V2_ALGORITHM_DIGEST = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";
	public static final String URL_V1_ALGORITHM_SIGNATURE = Constants.MoreAlgorithmsSpecNS + "gostr34102001-gostr3411";
	public static final String URL_V2_ALGORITHM_SIGNATURE = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";
	public static final String URL_V1_ALGORITHM_ENCRIPTION = Constants.MoreAlgorithmsSpecNS + "gost28147";
	public static final String URL_V2_ALGORITHM_ENCRIPTION = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gost28147";

	public static final String JCENAME_ALGORITHM_DIGEST = "GOST3411";
	public static final String JCENAME_ALGORITHM_SIGNATURE = "GOST3411withGOST3410EL";
	public static final String JCENAME_ALGORITHM_ENCRIPTION = "GostJCE/CBC/ISO10126Padding";

	public static void init(String providerId) throws AlgorithmAlreadyRegisteredException, XMLSignatureException, ClassNotFoundException {
		org.apache.xml.security.Init.init();

		// CryptoPro MessageDigest
		JCEMapper.Algorithm digest = new JCEMapper.Algorithm("", JCENAME_ALGORITHM_DIGEST, "MessageDigest");
		JCEMapper.register(URL_V1_ALGORITHM_DIGEST, digest);
		JCEMapper.register(URL_V2_ALGORITHM_DIGEST, digest);

		// CryptoPro Signature
		JCEMapper.Algorithm signature = new JCEMapper.Algorithm("", JCENAME_ALGORITHM_SIGNATURE, "Signature");
		JCEMapper.register(URL_V1_ALGORITHM_SIGNATURE, signature);
		JCEMapper.register(URL_V2_ALGORITHM_SIGNATURE, signature);

		// CryptoPro BlockEncryption
		JCEMapper.Algorithm encryption = new JCEMapper.Algorithm("GOST28147", JCENAME_ALGORITHM_ENCRIPTION, "BlockEncryption", 256);
		JCEMapper.register(URL_V1_ALGORITHM_ENCRIPTION, encryption);
		JCEMapper.register(URL_V2_ALGORITHM_ENCRIPTION, encryption);

		SignatureAlgorithm.register(URL_V1_ALGORITHM_SIGNATURE, SignatureGostR34102001Gostr3411.class);
		SignatureAlgorithm.register(URL_V2_ALGORITHM_SIGNATURE, SignatureGostR34102001URN.class);

		// устанавливаем криптопровайдера
		JCEMapper.setProviderId(providerId);
	}
}
