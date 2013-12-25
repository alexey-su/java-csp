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
package org.company.security.csp;

import java.io.InputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.util.Collection;

/**
 * На самом деле, всё управление передается в BouncyCastle
 * 
 * @author Aleksey
 */
public class CSPCertificateFactory extends CertificateFactorySpi {
	private org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory delegate =
			new org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory();

	@Override
	public Certificate engineGenerateCertificate(InputStream inStream) throws CertificateException {
		return delegate.engineGenerateCertificate(inStream);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Collection<? extends Certificate> engineGenerateCertificates(InputStream inStream) throws CertificateException {
		return delegate.engineGenerateCertificates(inStream);
	}

	@Override
	public CRL engineGenerateCRL(InputStream inStream) throws CRLException {
		return delegate.engineGenerateCRL(inStream);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Collection<? extends CRL> engineGenerateCRLs(InputStream inStream) throws CRLException {
		return delegate.engineGenerateCRLs(inStream);
	}

}
