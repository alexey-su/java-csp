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
 * cspUtil.c
 *
 *      Author: alexey
 */

#include "cspProvider.h"


/*
 * Throws an arbitrary Java exception.
 * The exception message is a Windows system error message.
 */
void ThrowException(JNIEnv *env, char *exceptionName, DWORD dwError) {
	jclass exceptionClazz;
	char szMessage[1024];
	szMessage[0] = '\0';

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwError, 0, szMessage, 1024, NULL);

#ifdef DEBUG
	fprintf(stderr, "ThrowException (%s) %x \"%s\"\n", exceptionName, dwError, szMessage);
#endif

#if defined(_MSC_VER) && _MSC_VER > 1310
	// переводим текст из текущей локали в Unicode и далее в UTF-8
	if(*szMessage) {
		char unicode[2048];
		char szUtf8[1024];

		MultiByteToWideChar(CP_ACP, 0, szMessage, -1, (LPCWSTR) unicode, 1024);
		WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR) unicode, -1, szUtf8, 1024, NULL, NULL);

		if(*szUtf8) {
			strcpy(szMessage, szUtf8);
		}
	}
#endif

	exceptionClazz = (*env)->FindClass(env, exceptionName);
	(*env)->ThrowNew(env, exceptionClazz, szMessage);
}

/*
 * Maps the name of a hash algorithm to an algorithm identifier.
 */
ALG_ID MapHashAlgorithm(JNIEnv *env, jstring jAlgorithm) {
	const char* pszAlgorithm = NULL;
	ALG_ID algId = 0;

	pszAlgorithm = (*env)->GetStringUTFChars(env, jAlgorithm, NULL);

	if ((strcmp("SHA", pszAlgorithm) == 0) ||
		(strcmp("SHA1", pszAlgorithm) == 0) ||
		(strcmp("SHA-1", pszAlgorithm) == 0)) {

		algId = CALG_SHA1;
	} else if (strcmp("SHA1+MD5", pszAlgorithm) == 0) {
		algId = CALG_SSL3_SHAMD5; // a 36-byte concatenation of SHA-1 and MD5
	} else if (strcmp("SHA-256", pszAlgorithm) == 0) {
		algId = CALG_SHA_256;
	} else if (strcmp("SHA-384", pszAlgorithm) == 0) {
		algId = CALG_SHA_384;
	} else if (strcmp("SHA-512", pszAlgorithm) == 0) {
		algId = CALG_SHA_512;
	} else if (strcmp("MD5", pszAlgorithm) == 0) {
		algId = CALG_MD5;
	} else if (strcmp("MD2", pszAlgorithm) == 0) {
		algId = CALG_MD2;
	} else if (strcmp("GOST3411", pszAlgorithm) == 0) {
		algId = CALG_GR3411;	// 0000801eh Hash "GOST R 34.11-94" (256 bits)
	} else if (strcmp("GOST28147", pszAlgorithm) == 0) {
		algId = CALG_G28147;	// 0000661eh Encrypt "GOST 28147-89" (256 bits)
	} else if (strcmp("GOST3410EL", pszAlgorithm) == 0) {
		algId = CALG_GR3410EL;	// 00002e23h Signature "GOST R 34.10-2001" (512 bits)
	} else if (strcmp("GOST3410DH", pszAlgorithm) == 0) {
			algId = CALG_DH_EL_SF;	// 0000aa24h Exchange "Diffie-Hellman EL" (512 bits)
	} else if (strcmp("GOST3410DHEL", pszAlgorithm) == 0) {
		algId = CALG_DH_EL_EPHEM;	// 0000aa25h Exchange "Diffie-Hellman EL" (512 bits)
	} else if (strcmp("GOST3410DH", pszAlgorithm) == 0) {
		algId = CALG_G28147_MAC;	// 0000801fh Hash HMAC "GOST 28147-89" (32 bits)
	}

	if (pszAlgorithm)
		(*env)->ReleaseStringUTFChars(env, jAlgorithm, pszAlgorithm);

	return algId;
}

ALG_ID MapSignAlgorithm(JNIEnv *env, jstring jAlgorithm) {
	const char* pszAlgorithm = NULL;
	ALG_ID algId = 0;

	pszAlgorithm = (*env)->GetStringUTFChars(env, jAlgorithm, NULL);

	if (strcmp("GOST3410EL", pszAlgorithm) == 0) {
		algId = CALG_GR3410EL;	// 00002e23h Signature "GOST R 34.10-2001" (512 bits)
	}

	if (pszAlgorithm)
		(*env)->ReleaseStringUTFChars(env, jAlgorithm, pszAlgorithm);

	return algId;
}

ALG_ID MapEncryptAlgorithm(JNIEnv *env, jstring jAlgorithm) {
	const char* pszAlgorithm = NULL;
	ALG_ID algId = 0;

	pszAlgorithm = (*env)->GetStringUTFChars(env, jAlgorithm, NULL);

	if (strcmp("GOST28147", pszAlgorithm) == 0) {
		algId = CALG_G28147;	// 0000661eh Encrypt "GOST 28147-89" (256 bits)
	}

	if (pszAlgorithm)
		(*env)->ReleaseStringUTFChars(env, jAlgorithm, pszAlgorithm);

	return algId;
}

ALG_ID MapExchangeAlgorithm(JNIEnv *env, jstring jAlgorithm) {
	const char* pszAlgorithm = NULL;
	ALG_ID algId = 0;

	pszAlgorithm = (*env)->GetStringUTFChars(env, jAlgorithm, NULL);

	if (strcmp("GOST3410DH", pszAlgorithm) == 0) {
		algId = CALG_DH_EL_SF;	// 0000aa24h Exchange "Diffie-Hellman EL" (512 bits)
	} else if (strcmp("GOST3410DHEL", pszAlgorithm) == 0) {
		algId = CALG_DH_EL_EPHEM;	// 0000aa25h Exchange "Diffie-Hellman EL" (512 bits)
	}

	if (pszAlgorithm)
		(*env)->ReleaseStringUTFChars(env, jAlgorithm, pszAlgorithm);

	return algId;
}
ALG_ID MapMacHashAlgorithm(JNIEnv *env, jstring jAlgorithm) {
	const char* pszAlgorithm = NULL;
	ALG_ID algId = 0;

	pszAlgorithm = (*env)->GetStringUTFChars(env, jAlgorithm, NULL);

	if (strcmp("GOST3410DH", pszAlgorithm) == 0) {
		algId = CALG_G28147_MAC;	// 0000801fh Hash HMAC "GOST 28147-89" (32 bits)
	}

	if (pszAlgorithm)
		(*env)->ReleaseStringUTFChars(env, jAlgorithm, pszAlgorithm);

	return algId;
}


BOOL FindProviderByAlg(JNIEnv *env, const char* pszAlgOID, ALG_ID algId, DWORD *pdwProvId, DWORD *pdwBitLen) {
	HCRYPTPROV    hProv = (HCRYPTPROV) NULL;
	DWORD         dwIndex;
	DWORD         dwType;
	DWORD         cbName;
	PROV_ENUMALGS provEnumAlgs;
	DWORD         cbData;
	DWORD         dwFlags = CRYPT_FIRST;
	BOOL          result = TRUE;

	if(pdwProvId) {
		*pdwProvId = 0;
	}

	{
		// Цикл по перечисляемым типам провайдеров.
		dwIndex = 0;
		while (CryptEnumProviderTypes(dwIndex++, NULL, 0, &dwType, NULL, &cbName)) {

			if(!CryptAcquireContext(&hProv, NULL, NULL, dwType, CRYPT_VERIFYCONTEXT)) {
				ThrowException(env, PROVIDER_EXCEPTION, GetLastError());
				result = FALSE;
				goto _m_leave;
			}

			cbData = sizeof(PROV_ENUMALGS);
			dwFlags = CRYPT_FIRST;
			while(CryptGetProvParam(hProv, PP_ENUMALGS, (BYTE*) &provEnumAlgs, &cbData, dwFlags)) {
				BOOL find;
				dwFlags = CRYPT_NEXT;
				cbData = sizeof(PROV_ENUMALGS);

				if(pszAlgOID) {
					// поиск по OID алгоритма
					const char* pszEnumAlgOID = CertAlgIdToOID(provEnumAlgs.aiAlgid);
					find = pszEnumAlgOID != NULL && strcmp(pszAlgOID, pszEnumAlgOID) == 0;
				}
				else {
					// поиск по ALG_ID
					find = provEnumAlgs.aiAlgid == algId;
				}

				if(find) {
					if(pdwProvId)
						*pdwProvId = dwType;

					if(pdwBitLen)
						*pdwBitLen = provEnumAlgs.dwBitLen;
					break;
				}
			}

			if(hProv) {
				CryptReleaseContext(hProv, 0);
				hProv = (HCRYPTPROV) NULL;
			}
		}
	}
	_m_leave:
	{
		if(hProv)
			CryptReleaseContext(hProv, 0);
	}
	if(result && pdwProvId && *pdwProvId == 0) {
#ifdef DEBUF
		fprintf(stderr, "FindProviderByAlg not find algoritm OID: %s algId: %x\n", pszAlgOID, algId);
#endif

		ThrowException(env, NOSUCHALGORITHM_EXCEPTION, NTE_BAD_ALGID);
		result = FALSE;
	}
	return result;
}
