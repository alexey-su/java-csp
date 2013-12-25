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
/*
 * cspKey.c
 *
 *      Author: Alexey
 */
#include "cspProvider.h"
#include "org_company_security_csp_NativeCrypto.h"

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    getKeyParam
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_company_security_csp_NativeCrypto_getKeyParam(
		JNIEnv *env, jclass clazz, jlong hKey, jint jParam) {
	DWORD dwKeyParam = 0;
	DWORD dwKeyParamLen = sizeof(DWORD);
	DWORD dwParam = (DWORD) jParam;	// KP_KEYLEN, KP_BLOCKLEN and more

	{
		// Get key length (in bits)
		//TODO - may need to use KP_BLOCKLEN instead?
		if (! CryptGetKeyParam((HCRYPTKEY) hKey, dwParam, (BYTE *) &dwKeyParam, &dwKeyParamLen, 0)) {
			ThrowException(env, INVALID_KEY_EXCEPTION, GetLastError());
			goto _m_leave;
		}
	}
	_m_leave:
	{
		// no cleanup required
	}

	return (jint) dwKeyParam;
}


JNIEXPORT jstring JNICALL Java_org_company_security_csp_NativeCrypto_getKeyAlgOID(
		JNIEnv *env, jclass clazz, jlong hKey) {
	DWORD dwKeyParam = 0;
	DWORD dwKeyParamLen = sizeof(DWORD);
	const char* szOID = NULL;
	jstring result = NULL;

	{
		if (! CryptGetKeyParam((HCRYPTKEY) hKey, KP_ALGID, (BYTE *) &dwKeyParam, &dwKeyParamLen, 0)) {
			ThrowException(env, INVALID_KEY_EXCEPTION, GetLastError());
			goto _m_leave;
		}
		szOID = CertAlgIdToOID(dwKeyParam);
	}
	_m_leave:
	{
		// no cleanup required
	}

	if(szOID) {
		result = (*env)->NewStringUTF(env, szOID);
	}
	return result;
}

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    keyDestroy
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_keyDestroy(
JNIEnv *env, jclass clazz, jlong hCryptProv, jlong hCryptKey) {
	if (hCryptKey)
		CryptDestroyKey((HCRYPTKEY) hCryptKey);

	if (hCryptProv)
		CryptReleaseContext((HCRYPTPROV) hCryptProv, 0);
}

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    initPublicKey
 * Signature: ([BI)org/company/security/csp/CSPPublicKey;
 */
JNIEXPORT jobject JNICALL Java_org_company_security_csp_NativeCrypto_initPublicKey(
		JNIEnv *env, jclass clazz, jbyteArray jKeyEncoding, jint jKeyEncodingSize) {

	HCRYPTPROV hCryptProv = (HCRYPTPROV) NULL;
	HCRYPTKEY hPublicKey = (HCRYPTKEY) NULL;
	DWORD dwProvId;
	DWORD dwKeySize;
	BYTE* pbEncoding = NULL;
	jobject publicKey = NULL;
	CERT_PUBLIC_KEY_INFO *pKeyInfo = NULL;
	DWORD keyInfoSize;
	jclass clazzCSPPublicKey;
	jmethodID mNewCSPPublicKey;

	pbEncoding = (BYTE *) (*env)->GetByteArrayElements(env, jKeyEncoding, 0);

	{
		// определяем размер буфера для размещения CERT_PUBLIC_KEY_INFO
		if(! CryptDecodeObject(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				X509_PUBLIC_KEY_INFO,
				pbEncoding,
				(DWORD) jKeyEncodingSize,
				CRYPT_DECODE_NOCOPY_FLAG,
				NULL,
				&keyInfoSize)) {
			ThrowException(env, INVALID_KEY_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		pKeyInfo = (CERT_PUBLIC_KEY_INFO*) malloc(keyInfoSize);

		// декодируем ASN.1 to CERT_PUBLIC_KEY_INFO
		if(! CryptDecodeObject(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				X509_PUBLIC_KEY_INFO,
				pbEncoding,
				(DWORD) jKeyEncodingSize,
				CRYPT_DECODE_NOCOPY_FLAG,
				pKeyInfo,
				&keyInfoSize)) {
			ThrowException(env, INVALID_KEY_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		if(! FindProviderByAlg(env, pKeyInfo->Algorithm.pszObjId, 0, &dwProvId, &dwKeySize)) {
			goto _m_leave;
		}

		if(! CryptAcquireContext(&hCryptProv, NULL, NULL, dwProvId, CRYPT_VERIFYCONTEXT)) {
			ThrowException(env, INVALID_KEY_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Import the certificate's public key into the key container
		if (! CryptImportPublicKeyInfo(hCryptProv, X509_ASN_ENCODING, pKeyInfo, &hPublicKey)) {
			ThrowException(env, INVALID_KEY_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Get the method ID for the CSPPublicKey constructor
		clazzCSPPublicKey =
				(*env)->FindClass(env, "org/company/security/csp/CSPPublicKey");

		mNewCSPPublicKey =
				(*env)->GetMethodID(env, clazzCSPPublicKey, "<init>", "(JJI[B)V");

		// Create a new CSP public key
		publicKey = (*env)->NewObject(env, clazzCSPPublicKey, mNewCSPPublicKey,
				(jlong) hCryptProv, (jlong) hPublicKey, (jint) dwKeySize, jKeyEncoding);
	}
	_m_leave:
	{
		if(pKeyInfo)
			free(pKeyInfo);

		if (pbEncoding)
			(*env)->ReleaseByteArrayElements(env, jKeyEncoding, (jbyte *) pbEncoding, JNI_ABORT);

		if(! publicKey) {
			if(hPublicKey)
				CryptDestroyKey(hPublicKey);

			if(hCryptProv)
				CryptReleaseContext(hCryptProv, 0);
		}
	}

	return publicKey;
}

JNIEXPORT jstring JNICALL Java_org_company_security_csp_NativeCrypto_getContainerName(
		JNIEnv *env, jclass clazz, jlong hCryptProv) {
	DWORD cbData = 1024;
	BYTE pbData[1024];
	pbData[0] = '\0';

	if(! CryptGetProvParam((HCRYPTPROV) hCryptProv, PP_CONTAINER, NULL, &cbData, 0)) {
		ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
		return NULL;
	}

	if(! CryptGetProvParam((HCRYPTPROV) hCryptProv, PP_CONTAINER, (BYTE *)pbData, &cbData, 0)) {
		ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
		return NULL;
	}

	return (*env)->NewStringUTF(env, (const char*)pbData);
}

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    getPublicKeyEncode
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_company_security_csp_NativeCrypto_getPublicKeyEncode(
		JNIEnv *env, jclass clazz, jlong hCryptProv, jlong hCryptKey) {

	return NULL;
}
