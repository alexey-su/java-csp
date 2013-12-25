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
 * cspKeyStore.c
 *
 *      Author: alexey
 */
#include "cspProvider.h"
#include "org_company_security_csp_NativeCrypto.h"

/*
 * Returns a certificate chain context given a certificate context and key
 * usage identifier.
 */
BOOL GetCertificateChain(LPSTR lpszKeyUsageIdentifier, PCCERT_CONTEXT pCertContext, PCCERT_CHAIN_CONTEXT* ppChainContext)
{
    CERT_ENHKEY_USAGE        EnhkeyUsage;
    CERT_USAGE_MATCH         CertUsage;
    CERT_CHAIN_PARA          ChainPara;
    DWORD                    dwFlags = 0;
    LPSTR                    szUsageIdentifierArray[1];

    szUsageIdentifierArray[0] = lpszKeyUsageIdentifier;
    EnhkeyUsage.cUsageIdentifier = 1;
    EnhkeyUsage.rgpszUsageIdentifier = szUsageIdentifierArray;
    CertUsage.dwType = USAGE_MATCH_TYPE_AND;
    CertUsage.Usage  = EnhkeyUsage;
    ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    ChainPara.RequestedUsage=CertUsage;

    // Build a chain using CertGetCertificateChain
    // and the certificate retrieved.
    return (CertGetCertificateChain(NULL,     // use the default chain engine
                pCertContext,   // pointer to the end certificate
                NULL,           // use the default time
                NULL,           // search no additional stores
                &ChainPara,     // use AND logic and enhanced key usage
                                //  as indicated in the ChainPara
                                //  data structure
                dwFlags,
                NULL,           // currently reserved
                ppChainContext) == TRUE);       // return a pointer to the chain created
}

/*
JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_openKeyStore(
		JNIEnv *env, jclass clazz, jobject jKeyStore, jstring jCertStoreName,
		jboolean jSystem, jint jProviderId) {

	const char* pszCertStoreName = NULL;
	HCERTSTORE hCertStore = NULL;
	HCRYPTPROV hStoreProv = (HCRYPTPROV) NULL;
	BOOL result = TRUE;

	{
		// Open a system certificate store.
		pszCertStoreName = (*env)->GetStringUTFChars(env, jCertStoreName, NULL );

		if(jProviderId) {
			if(! (CryptAcquireContext(&hStoreProv, 0, NULL, jProviderId, CRYPT_VERIFYCONTEXT))) {
				ThrowException(env, PROVIDER_EXCEPTION, GetLastError());
				result = FALSE;
				goto _m_leave;
			}
		}

		if(jSystem == JNI_TRUE) {
			hCertStore = CertOpenSystemStore(hStoreProv, pszCertStoreName);
		}
		else {
			hCertStore = CertOpenStore(CERT_STORE_PROV_FILE, 0, hStoreProv,0, pszCertStoreName);
		}
		if(hCertStore == NULL) {
			ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
			result = FALSE;
			goto _m_leave;
		}

		jmethodID mCallbackInitKeyStore = (*env)->GetMethodID(env,
				(*env)->GetObjectClass(env, jKeyStore), "callbackInitKeyStore",
				"(JJ)V");

		(*env)->CallVoidMethod(env, jKeyStore, mCallbackInitKeyStore, hStoreProv, hCertStore);
	}
	_m_leave:
	{
		if(! result) {
			if (hCertStore)
				CertCloseStore(hCertStore, 0);

			if (hStoreProv)
				CryptReleaseContext((HCRYPTPROV) hStoreProv, 0);

			if (pszCertStoreName)
				(*env)->ReleaseStringUTFChars(env, jCertStoreName, pszCertStoreName);
		}
	}
}

JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_closeKeyStore(
		JNIEnv *env, jclass clazz, jlong hCryptProv, jlong hCertStore) {

	if (hCertStore)
		CertCloseStore((HCERTSTORE) hCertStore, 0);

	if (hCryptProv)
		CryptReleaseContext((HCRYPTPROV) hCryptProv, 0);
}
*/

/**
 * Загрузить цепочку сертификатов
 */
JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_loadKeysOrCertificateChains(
		JNIEnv *env, jclass clazz, jobject jKeyStore, jstring jCertStoreName,
		jobject jCollections, jboolean jSystem, jint jProviderId) {

	const char* pszCertStoreName = NULL;
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	char* pszNameString = NULL; // certificate's friendly name
	DWORD cchNameString = 0;
	HCRYPTPROV hStoreProv = (HCRYPTPROV) NULL;

	{
		jclass clazzArrayList;
		jmethodID mNewArrayList;
		jmethodID mGenCert;
		jmethodID mGenCertChain;
		jmethodID mGenCSPKeyAndCertChain;

		// нет названия хранилища - выход
		if(!jCertStoreName) {
			ThrowException(env, KEYSTORE_EXCEPTION, ERROR_FILE_NOT_FOUND);
			goto _m_leave;
		}

		// Open a system certificate store.
		pszCertStoreName = (*env)->GetStringUTFChars(env, jCertStoreName, NULL );

		if(jProviderId) {
			if(! (CryptAcquireContext(&hStoreProv, 0, NULL, jProviderId, CRYPT_VERIFYCONTEXT))) {
				ThrowException(env, PROVIDER_EXCEPTION, GetLastError());
				goto _m_leave;
			}
		}

		if(jSystem == JNI_TRUE) {
#ifdef DEBUG
			fprintf(stderr, "CertOpenSystemStore %s\n", pszCertStoreName);
#endif
			hCertStore = CertOpenSystemStore(hStoreProv, pszCertStoreName);
		}
		else {
			LPCSTR lpszStoreProvider = CERT_STORE_PROV_FILENAME_A;
			DWORD dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
			DWORD dwFlags =
					CERT_STORE_NO_CRYPT_RELEASE_FLAG |
					CERT_STORE_SET_LOCALIZED_NAME_FLAG |
					CERT_STORE_READONLY_FLAG;

#ifdef DEBUG
			fprintf(stderr, "CertOpenStore %s\n", pszCertStoreName);
#endif
			hCertStore = CertOpenStore(
					lpszStoreProvider,
					dwMsgAndCertEncodingType,
					hStoreProv,
					dwFlags,
					pszCertStoreName);
		}
		if(hCertStore == NULL) {
			ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Determine clazz and method ID to generate certificate
		clazzArrayList = (*env)->FindClass(env, "java/util/ArrayList");

		mNewArrayList = (*env)->GetMethodID(env, clazzArrayList,
				"<init>", "()V");

		mGenCert = (*env)->GetMethodID(env,
				(*env)->GetObjectClass(env, jKeyStore), "generateCertificate",
				"([BLjava/util/Collection;)V");

		// Determine method ID to generate certificate chain
		mGenCertChain =
				(*env)->GetMethodID(env, (*env)->GetObjectClass(env, jKeyStore),
						"generateCertificateChain",
						"(Ljava/lang/String;Ljava/util/Collection;Ljava/util/Collection;)V");

		// Determine method ID to generate RSA certificate chain
		mGenCSPKeyAndCertChain =
				(*env)->GetMethodID(env, (*env)->GetObjectClass(env, jKeyStore),
						"generateCSPKeyAndCertificateChain",
						"(Ljava/lang/String;Ljava/lang/String;IJJILjava/util/Collection;Ljava/util/Collection;)V");

		// Use CertEnumCertificatesInStore to get the certificates
		// from the open store. pCertContext must be reset to
		// NULL to retrieve the first certificate in the store.
		while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != NULL) {
			// Check if private key available - client authentication certificate
			// must have private key available.
			HCRYPTPROV hCryptProv = (HCRYPTPROV) NULL;
			DWORD dwKeySpec = 0;
			HCRYPTKEY hUserKey = (HCRYPTKEY) NULL;
			DWORD dwKeyId = 0;
			BOOL bCallerFreeProv = FALSE;
			BOOL bHasNoPrivateKey = FALSE;
			DWORD dwPublicKeyLength = 0;
			char szContainer[1024];			// название контейнера закрытого ключа
			DWORD cbContainerLen = 1024l;	// максимальный размер буфера названия контейнера
			char szUniqueContainer[1024];		// название контейнера закрытого ключа для CryptAcquireContext
			DWORD cbUniqueContainerLen = 1024l;	// максимальный размер буфера названия контейнера
			DWORD dwProviderId;
			DWORD cbProviderIdLen = sizeof(DWORD);
			PCCERT_CHAIN_CONTEXT pCertChainContext = NULL;

			szContainer[0] = '\0';

#ifdef DEBUG
			{
				CERT_PUBLIC_KEY_INFO publicKeyInfo =((PCCERT_CONTEXT) pCertContext)->pCertInfo->SubjectPublicKeyInfo;

				fprintf(stderr, "loadKeysOrCertificateChains algId: %s publicKey.size: %d\n",
						publicKeyInfo.Algorithm.pszObjId,
						publicKeyInfo.PublicKey.cbData
						);
			}
#endif

			// определяем наличие приватного ключа
			if (CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL,
					&hCryptProv, &dwKeySpec, &bCallerFreeProv) == FALSE) {
				bHasNoPrivateKey = TRUE;
			}
			else {
				BOOL bGetUserKey;

				// получаем название контейнера закрытого ключа для псевдонима ключа
				if(! CryptGetProvParam((HCRYPTPROV) hCryptProv, PP_CONTAINER, (BYTE*) szContainer, &cbContainerLen, 0)) {
					ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
					goto _m_leave;
				}

				// получаем название контейнера закрытого ключа для CryptAcquireContext
				if(! CryptGetProvParam((HCRYPTPROV) hCryptProv, PP_UNIQUE_CONTAINER, (BYTE*) szUniqueContainer, &cbUniqueContainerLen, 0)) {
					ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
					goto _m_leave;
				}

				// получаем идентификатор провайдера
				if(! CryptGetProvParam((HCRYPTPROV) hCryptProv, PP_PROVTYPE, (BYTE*) &dwProviderId, &cbProviderIdLen, 0)) {
					ThrowException(env, PROVIDER_EXCEPTION, GetLastError());
					goto _m_leave;
				}

				// присутствует закрытый ключ
				bGetUserKey = CryptGetUserKey(hCryptProv, dwKeySpec, &hUserKey);

				dwPublicKeyLength = CertGetPublicKeyLength(
						X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
						&(pCertContext->pCertInfo->SubjectPublicKeyInfo));

#ifdef DEBUG
				if(bGetUserKey) {
					DWORD cbSize = sizeof(DWORD);
					DWORD algId;
					const char* alg = "N/A";

					CryptGetKeyParam(hUserKey, KP_ALGID, (BYTE*)&dwKeyId, &cbSize, 0);
					algId = dwKeyId;

					if(algId == CALG_G28147) alg = "CALG_G28147";
					else if(algId == CALG_GR3410EL) alg = "CALG_GR3410EL";
					else if(algId == CALG_DH_EL_SF) alg = "CALG_DH_EL_SF";
					else if(algId == CALG_DH_EL_EPHEM) alg = "CALG_DH_EL_EPHEM";

					fprintf(stderr, "loadKeysOrCertificateChains read key ALG_ID = %x (%s) OID: %s\n", dwKeyId, alg, CertAlgIdToOID(dwKeyId));
				}
				fprintf(stderr, "loadKeysOrCertificateChains container: %s  uniqueContainer: %s\n", szContainer, szUniqueContainer);
#endif
			}

			// Build certificate chain by using system certificate store.
			// Add cert chain into collection for any key usage.
			//
			if (GetCertificateChain(OID_EKU_ANY, pCertContext, &pCertChainContext)) {
				unsigned int i, j;
#ifdef DEBUG
				fprintf(stderr, "CertificateChain.size=%d\n", pCertChainContext->cChain);
#endif
				for (i = 0; i < pCertChainContext->cChain; i++) {
					// Found cert chain
					PCERT_SIMPLE_CHAIN rgpChain = pCertChainContext->rgpChain[i];

					// Create ArrayList to store certs in each chain
					jobject jArrayList = (*env)->NewObject(env, clazzArrayList, mNewArrayList);

#ifdef DEBUG
					fprintf(stderr, "CertificateChain element[%d] have elements %d\n", i, rgpChain->cElement);
#endif
					for (j = 0; j < rgpChain->cElement; j++) {
						BYTE* pbCertEncoded;
						DWORD cbCertEncoded;
						jbyteArray byteArray;

						PCERT_CHAIN_ELEMENT rgpElement = rgpChain->rgpElement[j];
						PCCERT_CONTEXT pc = rgpElement->pCertContext;

						// Retrieve the friendly name of the first certificate
						// in the chain
						if (j == 0) {

							// If the cert's name cannot be retrieved then
							// pszNameString remains set to NULL.
							// (An alias name will be generated automatically
							// when storing this cert in the keystore.)

							// Get length of friendly name
							if ((cchNameString = CertGetNameString(pc,
									CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL,
									NULL, 0)) > 1) {

								// Found friendly name
								pszNameString = malloc(cchNameString);
								CertGetNameString(pc,
										CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0,
										NULL, pszNameString, cchNameString);

#if defined(_MSC_VER) && _MSC_VER > 1310
								// переводим текст из текущей локали в Unicode и далее в UTF-8
								if(pszNameString && *pszNameString) {
									char unicode[2048];
									char szUtf8[1024];

									MultiByteToWideChar(CP_ACP, 0, pszNameString, -1, (LPCWSTR) unicode, 1024);
									WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR) unicode, -1, szUtf8, 1024, NULL, NULL);

									if(*szUtf8) {
										cchNameString = strlen(szUtf8) + 1;

										free(pszNameString);
										pszNameString = malloc(cchNameString);

										strcpy(pszNameString, szUtf8);
									}
								}
#endif
							}

							// нет названия сертификата, берем его из названия контейнера
							if(pszNameString == NULL && !bHasNoPrivateKey) {
								pszNameString = malloc(cbContainerLen);
								strcpy(pszNameString, szContainer);
							}
						}

						pbCertEncoded = pc->pbCertEncoded;
						cbCertEncoded = pc->cbCertEncoded;

						// Allocate and populate byte array
						byteArray = (*env)->NewByteArray(env, cbCertEncoded);
						(*env)->SetByteArrayRegion(env, byteArray, 0, cbCertEncoded, (jbyte*) pbCertEncoded);

						// Generate certificate from byte array and store into
						// cert collection
						(*env)->CallVoidMethod(env, jKeyStore, mGenCert, byteArray, jArrayList);
					}
					if (bHasNoPrivateKey) {
#ifdef DEBUG
						fprintf(stderr, "call generateCertificateChain\n");
#endif
						// Generate certificate chain and store into cert chain
						// collection
						(*env)->CallVoidMethod(env, jKeyStore, mGenCertChain,
								(*env)->NewStringUTF(env, pszNameString),
								jArrayList, jCollections);
					} else {
#ifdef DEBUG
						fprintf(stderr, "call generateCSPKeyAndCertificateChain\n");
#endif
						(*env)->CallVoidMethod(env, jKeyStore, mGenCSPKeyAndCertChain,
								(*env)->NewStringUTF(env, pszNameString),
								(*env)->NewStringUTF(env, szUniqueContainer),
								dwProviderId,
								(jlong) hCryptProv, (jlong) hUserKey,
								dwPublicKeyLength, jArrayList, jCollections);
					}
				}

				// Free cert chain
				if (pCertChainContext)
					CertFreeCertificateChain(pCertChainContext);
			}
#ifdef DEBUG
			else {
				fprintf(stderr, "GetCertificateChain return false\n");
			}
#endif
		}
	}
	_m_leave:
	{
		if (hCertStore)
			CertCloseStore(hCertStore, 0);

		if (hStoreProv)
			CryptReleaseContext((HCRYPTPROV) hStoreProv, 0);

		if (pszCertStoreName)
			(*env)->ReleaseStringUTFChars(env, jCertStoreName, pszCertStoreName);

		if (pszNameString)
			free(pszNameString);
	}
}

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    storeCertificate
 * Signature: (Ljava/lang/String;Ljava/lang/String;[BIJJ)V
 */
JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_storeCertificate(
		JNIEnv *env, jclass clazz, jstring jCertStoreName,
		jstring jCertAliasName, jbyteArray jCertEncoding,
		jint jCertEncodingSize, jlong hCryptProv, jlong hCryptKey) {

	const char* pszCertStoreName = NULL;
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	WCHAR * pszCertAliasName = NULL;
	jbyte* pbCertEncoding = NULL;
	const jchar* jCertAliasChars = NULL;
	char* pszContainerName = NULL;
	char* pszProviderName = NULL;
	WCHAR * pwszContainerName = NULL;
	WCHAR * pwszProviderName = NULL;

	{
		int size;
		CRYPT_DATA_BLOB friendlyName;

		// Open a system certificate store.
		pszCertStoreName = (*env)->GetStringUTFChars(env, jCertStoreName,
				NULL );
		if ((hCertStore = CertOpenSystemStore((HCRYPTPROV) NULL,
				pszCertStoreName)) == NULL ) {
			ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Copy encoding from Java to native buffer
		pbCertEncoding = (jbyte*) malloc(jCertEncodingSize);
		(*env)->GetByteArrayRegion(env, jCertEncoding, 0, jCertEncodingSize,
				pbCertEncoding);

		// Create a certificate context from the encoded cert
		if (!(pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING,
				(BYTE*) pbCertEncoding, jCertEncodingSize))) {

			ThrowException(env, CERTIFICATE_PARSING_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Set the certificate's friendly name
		size = (*env)->GetStringLength(env, jCertAliasName);
		pszCertAliasName = (WCHAR*) malloc((size + 1) * sizeof(WCHAR));

		jCertAliasChars = (*env)->GetStringChars(env, jCertAliasName, NULL );
		memcpy(pszCertAliasName, jCertAliasChars, size * sizeof(WCHAR));
		pszCertAliasName[size] = 0; // append the string terminator

		friendlyName.cbData = sizeof(WCHAR) * (size + 1);
		friendlyName.pbData = (BYTE *) pszCertAliasName;

		(*env)->ReleaseStringChars(env, jCertAliasName, jCertAliasChars);

		if (!CertSetCertificateContextProperty(pCertContext,
				CERT_FRIENDLY_NAME_PROP_ID, 0, &friendlyName)) {

			ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Attach the certificate's private key (if supplied)
		if (hCryptProv != 0 && hCryptKey != 0) {

			CRYPT_KEY_PROV_INFO keyProviderInfo;
			DWORD dwDataLen;

			// Get the name of the key container
			if (!CryptGetProvParam((HCRYPTPROV) hCryptProv, PP_CONTAINER, NULL,
					&dwDataLen, 0)) {

				ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
				goto _m_leave;
			}

			pszContainerName = malloc(dwDataLen);

			if (!CryptGetProvParam((HCRYPTPROV) hCryptProv, PP_CONTAINER,
					(BYTE *) pszContainerName, &dwDataLen, 0)) {

				ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
				goto _m_leave;
			}

			// Convert to a wide char string
			pwszContainerName = (WCHAR*) malloc(dwDataLen * sizeof(WCHAR));

			if (mbstowcs(pwszContainerName, pszContainerName, dwDataLen) == 0) {
				ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
				goto _m_leave;
			}

			// Set the name of the key container
			keyProviderInfo.pwszContainerName = pwszContainerName;

			// Get the name of the provider
			if (!CryptGetProvParam((HCRYPTPROV) hCryptProv, PP_NAME, NULL,
					&dwDataLen, 0)) {

				ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
				goto _m_leave;
			}

			pszProviderName = malloc(dwDataLen);

			if (!CryptGetProvParam((HCRYPTPROV) hCryptProv, PP_NAME,
					(BYTE *) pszProviderName, &dwDataLen, 0)) {

				ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
				goto _m_leave;
			}

			// Convert to a wide char string
			pwszProviderName = (WCHAR*) malloc(dwDataLen * sizeof(WCHAR));

			if (mbstowcs(pwszProviderName, pszProviderName, dwDataLen) == 0) {
				ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
				goto _m_leave;
			}

			// Set the name of the provider
			keyProviderInfo.pwszProvName = pwszProviderName;

			// Get and set the type of the provider
			if (!CryptGetProvParam((HCRYPTPROV) hCryptProv, PP_PROVTYPE,
					(LPBYTE) &keyProviderInfo.dwProvType, &dwDataLen, 0)) {

				ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
				goto _m_leave;
			}

			// Set no provider flags
			keyProviderInfo.dwFlags = 0;

			// Set no provider parameters
			keyProviderInfo.cProvParam = 0;
			keyProviderInfo.rgProvParam = NULL;

			// Get the key's algorithm ID
			if (!CryptGetKeyParam((HCRYPTKEY) hCryptKey, KP_ALGID,
					(LPBYTE) &keyProviderInfo.dwKeySpec, &dwDataLen, 0)) {

				ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
				goto _m_leave;
			}
			// Set the key spec (using the algorithm ID).
			switch (keyProviderInfo.dwKeySpec) {
			case CALG_RSA_KEYX:
			case CALG_DH_SF:
				keyProviderInfo.dwKeySpec = AT_KEYEXCHANGE;
				break;

			case CALG_RSA_SIGN:
			case CALG_DSS_SIGN:
				keyProviderInfo.dwKeySpec = AT_SIGNATURE;
				break;

			default:
				ThrowException(env, KEYSTORE_EXCEPTION, NTE_BAD_ALGID );
				goto _m_leave;
			}

			if (!CertSetCertificateContextProperty(pCertContext,
					CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProviderInfo)) {

				ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
				goto _m_leave;
			}
		}

		// Import encoded certificate
		if (!CertAddCertificateContextToStore(hCertStore, pCertContext,
				CERT_STORE_ADD_REPLACE_EXISTING, NULL )) {
			ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

	}
	_m_leave: {
		//--------------------------------------------------------------------
		// Clean up.

		if (hCertStore)
			CertCloseStore(hCertStore, 0);

		if (pszCertStoreName)
			(*env)->ReleaseStringUTFChars(env, jCertStoreName,
					pszCertStoreName);

		if (pbCertEncoding)
			free(pbCertEncoding);

		if (pszCertAliasName)
			free(pszCertAliasName);

		if (pszContainerName)
			free(pszContainerName);

		if (pwszContainerName)
			free(pwszContainerName);

		if (pszProviderName)
			free(pszProviderName);

		if (pwszProviderName)
			free(pwszProviderName);

		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
	}
}

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    removeCertificate
 * Signature: (Ljava/lang/String;Ljava/lang/String;[BI)V
 */
JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_removeCertificate(
		JNIEnv *env, jclass clazz,
		jstring jCertStoreName, jstring jCertAliasName,
		jbyteArray jCertEncoding, jint jCertEncodingSize) {

	const char* pszCertStoreName = NULL;
	const char* pszCertAliasName = NULL;
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	PCCERT_CONTEXT pTBDCertContext = NULL;
	jbyte* pbCertEncoding = NULL;
	DWORD cchNameString = 0;
	char* pszNameString = NULL; // certificate's friendly name
	BOOL bDeleteAttempted = FALSE;

	{
		// Open a system certificate store.
		pszCertStoreName = (*env)->GetStringUTFChars(env, jCertStoreName, NULL);
		if ((hCertStore = CertOpenSystemStore((HCRYPTPROV) NULL, pszCertStoreName)) == NULL) {
			ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Copy encoding from Java to native buffer
		pbCertEncoding = (jbyte*) malloc(jCertEncodingSize);
		(*env)->GetByteArrayRegion(env, jCertEncoding, 0, jCertEncodingSize, pbCertEncoding);

		// Create a certificate context from the encoded cert
		if (!(pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING,
				(BYTE*) pbCertEncoding, jCertEncodingSize))) {

			ThrowException(env, CERTIFICATE_PARSING_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Find the certificate to be deleted
		if (!(pTBDCertContext = CertFindCertificateInStore(hCertStore,
				X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, pCertContext, NULL))) {

			ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Check that its friendly name matches the supplied alias
		if ((cchNameString = CertGetNameString(pTBDCertContext,
				CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, NULL, 0)) > 1) {

			pszNameString = malloc(cchNameString);

			CertGetNameString(pTBDCertContext,
					CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, pszNameString,
					cchNameString);

			// Compare the certificate's friendly name with supplied alias name
			pszCertAliasName = (*env)->GetStringUTFChars(env, jCertAliasName, NULL);
			if (strcmp(pszCertAliasName, pszNameString) == 0) {

				// Only delete the certificate if the alias names matches
				if (! CertDeleteCertificateFromStore(pTBDCertContext)) {

					// pTBDCertContext is always freed by the
					//  CertDeleteCertificateFromStore method
					bDeleteAttempted = TRUE;

					ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
					goto _m_leave;
				}
			}
		}

	}
	_m_leave:
	{
		//--------------------------------------------------------------------
		// Clean up.

		if (hCertStore)
			CertCloseStore(hCertStore, 0);

		if (pszCertStoreName)
			(*env)->ReleaseStringUTFChars(env, jCertStoreName, pszCertStoreName);

		if (pszCertAliasName)
			(*env)->ReleaseStringUTFChars(env, jCertAliasName, pszCertAliasName);

		if (pbCertEncoding)
			free(pbCertEncoding);

		if (pszNameString)
			free(pszNameString);

		if (pCertContext)
			CertFreeCertificateContext(pCertContext);

		if (bDeleteAttempted && pTBDCertContext)
			CertFreeCertificateContext(pTBDCertContext);
	}
}

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    destroyKeyContainer
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_org_company_security_csp_NativeCrypto_destroyKeyContainer(
		JNIEnv *env, jclass clazz, jint providerId, jstring storeName, jstring keyContainerName) {

	HCRYPTPROV hCryptProv = (HCRYPTPROV) NULL;
	const char* pszKeyContainerName = NULL;

	{
		pszKeyContainerName = (*env)->GetStringUTFChars(env, keyContainerName, NULL);

		// Destroying the default key container is not permitted
		// (because it may contain more one keypair).
		if (pszKeyContainerName == NULL ) {

			ThrowException(env, KEYSTORE_EXCEPTION, NTE_BAD_KEYSET_PARAM );
			goto _m_leave;
		}

		// Acquire a CSP context (to the key container).
		if (CryptAcquireContext(&hCryptProv, pszKeyContainerName, NULL,
				PROV_RSA_FULL, CRYPT_DELETEKEYSET) == FALSE) {
			ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

	}
	_m_leave:
	{
		//--------------------------------------------------------------------
		// Clean up.

		if (pszKeyContainerName)
			(*env)->ReleaseStringUTFChars(env, keyContainerName, pszKeyContainerName);
	}
}

/*
 * Class:     org_company_security_csp_NativeCrypto
 * Method:    findCertificateUsingAlias
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_company_security_csp_NativeCrypto_findCertificateUsingAlias(
		JNIEnv *env, jclass clazz, jstring jCertStoreName, jstring jCertAliasName) {
	const char* pszCertStoreName = NULL;
	const char* pszCertAliasName = NULL;
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	char* pszNameString = NULL; // certificate's friendly name
	DWORD cchNameString = 0;

	{
		pszCertStoreName = (*env)->GetStringUTFChars(env, jCertStoreName, NULL );
		pszCertAliasName = (*env)->GetStringUTFChars(env, jCertAliasName, NULL );

		// Open a system certificate store.
		if ((hCertStore = CertOpenSystemStore((HCRYPTPROV) NULL, pszCertStoreName)) == NULL ) {
			ThrowException(env, KEYSTORE_EXCEPTION, GetLastError());
			goto _m_leave;
		}

		// Use CertEnumCertificatesInStore to get the certificates
		// from the open store. pCertContext must be reset to
		// NULL to retrieve the first certificate in the store.
		while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != NULL) {
			if ((cchNameString = CertGetNameString(pCertContext,
					CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, NULL, 0)) == 1) {

				continue; // not found
			}

			pszNameString = malloc(cchNameString);

			if (CertGetNameString(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE,
					0, NULL, pszNameString, cchNameString) == 1) {

				continue; // not found
			}

			// Compare the certificate's friendly name with supplied alias name
			if (strcmp(pszCertAliasName, pszNameString) == 0) {
				free(pszNameString);
				break;

			} else {
				free(pszNameString);
			}
		}
	}
	_m_leave: {
		if (hCertStore)
			CertCloseStore(hCertStore, 0);

		if (pszCertStoreName)
			(*env)->ReleaseStringUTFChars(env, jCertStoreName,
					pszCertStoreName);

		if (pszCertAliasName)
			(*env)->ReleaseStringUTFChars(env, jCertAliasName,
					pszCertAliasName);
	}

	return (jlong) pCertContext;
}

