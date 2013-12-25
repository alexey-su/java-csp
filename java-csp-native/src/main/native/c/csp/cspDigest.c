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
 * cspDigest.c
 *
 *      Author: Alexey
 */
#include "cspProvider.h"
#include "org_company_security_csp_NativeCrypto.h"

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    digestInit
 * Signature: (Lorg/company/security/csp/CSPDigest;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_digestInit(
		JNIEnv *env, jclass clazz, jobject jMessageDigest, jstring jHashAlgorithm) {

	HCRYPTPROV hCryptProv = (HCRYPTPROV) NULL;
	HCRYPTHASH hCryptHash = (HCRYPTHASH) NULL;
	DWORD dwBlockSize;
	BOOL result = FALSE;

	{
		ALG_ID algId = MapHashAlgorithm(env, jHashAlgorithm);
		DWORD dwProvId;
		jclass clazzCSPDigest;
		jmethodID mCSPPublicKeyInit;

		if(! FindProviderByAlg(env, NULL, algId, &dwProvId, &dwBlockSize)) {
			goto _m_leave;
		}

		if(! CryptAcquireContext(&hCryptProv, NULL, NULL, dwProvId, CRYPT_VERIFYCONTEXT)) {
			ThrowException(env, PROVIDER_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// выделяем контекст хеш функции
		if(! CryptCreateHash(hCryptProv, algId, 0, 0, &hCryptHash)) {
			ThrowException(env, DIGEST_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Get the method ID for the CSPPublicKey constructor
		clazzCSPDigest =
				(*env)->FindClass(env, "org/company/security/csp/CSPDigest");

		mCSPPublicKeyInit =
				(*env)->GetMethodID(env, clazzCSPDigest, "initDigest", "(JJI)V");

		// Create a new CSP public key
		(*env)->CallVoidMethod(env, jMessageDigest, mCSPPublicKeyInit,
				(jlong) hCryptProv, (jlong) hCryptHash, (jint) dwBlockSize);

		result = TRUE;
	}
	_m_leave:
	{
		if(! result) {
			if (hCryptHash)
				CryptDestroyHash((HCRYPTHASH) hCryptHash);

			if(hCryptProv)
				CryptReleaseContext((HCRYPTPROV) hCryptProv, 0);
		}
	}
}
/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    digestDestroy
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_digestDestroy(
		JNIEnv *env, jclass clazz, jlong hCryptProv, jlong hCryptHash) {

	if (hCryptHash)
		CryptDestroyHash((HCRYPTHASH) hCryptHash);

	if(hCryptProv)
		CryptReleaseContext((HCRYPTPROV) hCryptProv, 0);
}

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    digestEngineUpdateByte
 * Signature: (JB)V
 */
JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_digestEngineUpdateByte(
		JNIEnv *env, jclass clazz, jlong hCryptHash, jbyte jByte) {

	if(hCryptHash) {
		BYTE buffer[1];
		buffer[0] = (BYTE) jByte;

		if(! CryptHashData((HCRYPTHASH) hCryptHash, buffer, 1, 0)) {
			ThrowException(env, DIGEST_EXCEPTION, GetLastError());
		}
	}
}

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    digestEngineUpdateBytes
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_digestEngineUpdateBytes(
		JNIEnv *env, jclass clazz, jlong hCryptHash, jbyteArray jBytes, jint offset, jint len) {

	if(hCryptHash) {
		jbyte *buffer = (jbyte*) malloc(len * sizeof(jbyte));
		(*env)->GetByteArrayRegion(env, jBytes, offset, len, buffer);

		if(!CryptHashData((HCRYPTHASH) hCryptHash, (BYTE*) buffer, len, 0)) {
			ThrowException(env, DIGEST_EXCEPTION, GetLastError());
		}

		free(buffer);
	}
}

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    digestEngineDigest
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_company_security_csp_NativeCrypto_digestEngineDigest(
		JNIEnv *env, jclass clazz, jlong hCryptHash) {

	jbyteArray buffer = NULL;
	BYTE *rgbHash = NULL;

	{
		DWORD cbSize;
		DWORD cbSizeLen = sizeof(DWORD);

		if(!CryptGetHashParam((HCRYPTHASH) hCryptHash, HP_HASHSIZE, (BYTE *) &cbSize, &cbSizeLen, 0)) {
			ThrowException(env, DIGEST_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		rgbHash = (BYTE*) malloc(cbSize);

		if(! CryptGetHashParam((HCRYPTHASH) hCryptHash, HP_HASHVAL, rgbHash, &cbSize, 0)) {
			ThrowException(env, DIGEST_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		buffer = (*env)->NewByteArray(env, cbSize);

		if(buffer)
			(*env)->SetByteArrayRegion(env, buffer, 0, cbSize, (jbyte *) rgbHash);
	}
	_m_leave:
	{
		if(rgbHash)
			free(rgbHash);
	}
	return buffer;
}

JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_digestSetParameter(
		JNIEnv *env, jclass clazz, jlong hCryptHash, jint param, jbyteArray jBytes, jint offset, jint len) {

	if(hCryptHash) {
		jbyte *buffer = (jbyte*) malloc(len * sizeof(jbyte));
		(*env)->GetByteArrayRegion(env, jBytes, offset, len, buffer);

		if(!CryptSetHashParam((HCRYPTHASH) hCryptHash, (DWORD) param, (BYTE*) buffer, 0)) {
			ThrowException(env, DIGEST_EXCEPTION, GetLastError());
		}

		free(buffer);
	}
}

