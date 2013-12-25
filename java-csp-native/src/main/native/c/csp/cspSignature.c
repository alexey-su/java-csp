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
 * cspSignature.c
 *
 *      Author: alexey
 */
#include "cspProvider.h"
#include "org_company_security_csp_NativeCrypto.h"

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    signHash
 * Signature: (Z[BILjava/lang/String;Ljava/lang/String;JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_company_security_csp_NativeCrypto_sign(
		JNIEnv *env, jclass clazz, jobject jSignature,
		jboolean noHashOID,
		jbyteArray jHash, jint jHashSize,
		jstring jHashAlgorithm,
		jint jProviderId,
		jstring jContainer) {

	const char* pszContainer = NULL; // certificate's friendly name
	HCRYPTPROV hCryptProv = (HCRYPTPROV) NULL;
	HCRYPTKEY hCryptKey = (HCRYPTKEY) NULL;
	HCRYPTHASH hCryptHash = (HCRYPTHASH) NULL;
	jbyte* pHashBuffer = NULL;
	jbyteArray jSignedHash = NULL;
	jbyte* pSignedHashBuffer = NULL;
	DWORD dwBufLen = sizeof(DWORD);
	DWORD dwProviderImpl;

	{
		ALG_ID hashAlgId;
		DWORD cbHash;
		DWORD cbHashLen;
		DWORD dwFlags;
		jclass clazzCSPSignature;
		jmethodID mCSPInitDigestParameters;

		// название контейнера закрытого ключа
		pszContainer = (*env)->GetStringUTFChars(env, jContainer, NULL );

#ifdef DEBUG
		fprintf(stderr, "init context \"%s\"\n", pszContainer);
#endif

		if(! CryptAcquireContext(&hCryptProv,
				pszContainer,
				NULL, jProviderId, 0)) {
			ThrowException(env, PROVIDER_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		if(! CryptGetUserKey(hCryptProv, AT_SIGNATURE, &hCryptKey)) {
			// нет ключа подписи, берем ключ обмена
			if(! CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hCryptKey)) {
				ThrowException(env, INVALID_KEY_EXCEPTION, GetLastError());
				goto _m_leave;
			}
			dwProviderImpl = AT_KEYEXCHANGE;
		}
		else
			dwProviderImpl = AT_SIGNATURE;

		// получаем идентификатор алгоритма хеш функции
		hashAlgId = MapHashAlgorithm(env, jHashAlgorithm);
		cbHashLen = sizeof(DWORD);


		// выделяем контекст хеш функции
		if(! CryptCreateHash((HCRYPTPROV) hCryptProv, hashAlgId, 0, 0, &hCryptHash)) {
			ThrowException(env, SIGNATURE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Get the method ID for the CSPPublicKey constructor
		clazzCSPSignature =
				(*env)->FindClass(env, "org/company/security/csp/CSPSignature");

		mCSPInitDigestParameters =
				(*env)->GetMethodID(env, clazzCSPSignature, "initDigestParameters", "(JJ)V");

		// Create a new CSP public key
		(*env)->CallVoidMethod(env, jSignature, mCSPInitDigestParameters,
				(jlong) hCryptProv, (jlong) hCryptHash);


		// Определение размера BLOBа и распределение памяти.
		if(! CryptGetHashParam(hCryptHash, HP_HASHSIZE, (BYTE*) &cbHash, &cbHashLen, 0)) {
			ThrowException(env, DIGEST_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// копируем хеш из Java в нативный буфер
		pHashBuffer = (jbyte*) malloc(jHashSize);
		(*env)->GetByteArrayRegion(env, jHash, 0, jHashSize, pHashBuffer);

		// устанавливаем значение хеш функции
		if(! CryptSetHashParam(hCryptHash, HP_HASHVAL, (BYTE*)pHashBuffer, 0)) {
			ThrowException(env, SIGNATURE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Определяем размер подписи
		dwFlags = 0;

		if (noHashOID == JNI_TRUE) {
			dwFlags = CRYPT_NOHASHOID; // omit hash OID in NONEwithXXXX signature
		}

		// Определяем размер подписи
		if(! CryptSignHash(hCryptHash, dwProviderImpl, NULL, dwFlags, NULL, &dwBufLen)) {
			ThrowException(env, SIGNATURE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		pSignedHashBuffer = (jbyte*) malloc(dwBufLen);
		if(! CryptSignHash(hCryptHash, dwProviderImpl, NULL, dwFlags, (BYTE*)pSignedHashBuffer, &dwBufLen)) {
			ThrowException(env, SIGNATURE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Create new byte array
		jSignedHash = (*env)->NewByteArray(env, dwBufLen);

		// Копируем данные из нативного буфера
		(*env)->SetByteArrayRegion(env, jSignedHash, 0, dwBufLen, pSignedHashBuffer);
	}
	_m_leave:
	{
		if (pSignedHashBuffer)
			free(pSignedHashBuffer);

		if (pszContainer)
			(*env)->ReleaseStringUTFChars(env, jContainer, pszContainer);

		if(hCryptKey)
			CryptDestroyKey(hCryptKey);

		if(hCryptHash)
			CryptDestroyHash(hCryptHash);

		if(hCryptProv)
			CryptReleaseContext(hCryptProv, 0);
	}
	return jSignedHash;
}

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    verifySignedHash
 * Signature: ([BILjava/lang/String;Ljava/lang/String;[BIJJ)Z
 */
JNIEXPORT jboolean JNICALL Java_org_company_security_csp_NativeCrypto_verifySignedHash(
		JNIEnv *env, jclass clazz, jbyteArray jHash, jint jHashSize,
		jstring jHashAlgorithm, jbyteArray jSignedHash, jint jSignedHashSize,
		jlong hCryptProv, jlong hCryptKey) {
	HCRYPTHASH hHash = (HCRYPTHASH) NULL;
	jbyte* pHashBuffer = NULL;
	jbyte* pSignedHashBuffer = NULL;
	DWORD dwSignedHashBufferLen = jSignedHashSize;
	jboolean result = JNI_FALSE;
	HCRYPTPROV hCryptProvAlt = (HCRYPTPROV) NULL;

	{
		// Получить алгоритм хеш функции
		ALG_ID algId = MapHashAlgorithm(env, jHashAlgorithm);

		// Получить объект хеш функции
		if(! CryptCreateHash((HCRYPTPROV) hCryptProv, algId, 0, 0, &hHash)) {
			ThrowException(env, SIGNATURE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Перенос хеша и подписи в нитивные буфера
		pHashBuffer = (jbyte*) malloc(jHashSize);
		(*env)->GetByteArrayRegion(env, jHash, 0, jHashSize, pHashBuffer);
		pSignedHashBuffer = (jbyte*) malloc(jSignedHashSize);
		(*env)->GetByteArrayRegion(env, jSignedHash, 0, jSignedHashSize,
				pSignedHashBuffer);

		// Устанавливаем значение хеш функции
		if(! CryptSetHashParam(hHash, HP_HASHVAL, (BYTE*) pHashBuffer, 0)) {
			ThrowException(env, SIGNATURE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// For RSA, the hash encryption algorithm is normally the same as the
		// public key algorithm, so AT_SIGNATURE is used.

		// Проверка подписи
		if (CryptVerifySignature(hHash, (BYTE*) pSignedHashBuffer,
				dwSignedHashBufferLen, (HCRYPTKEY) hCryptKey, NULL, 0) == TRUE) {
			result = JNI_TRUE;
		}
	}
	_m_leave:
	{
		if (hHash)
			CryptDestroyHash(hHash);

		if (hCryptProvAlt)
			CryptReleaseContext(hCryptProvAlt, 0);

		if (pSignedHashBuffer)
			free(pSignedHashBuffer);

		if (pHashBuffer)
			free(pHashBuffer);
	}

	return result;
}
