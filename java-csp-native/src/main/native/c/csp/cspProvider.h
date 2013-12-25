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
 * cspProvider.h
 *
 *      Author: alexey
 */

#ifndef CSPPROVIDER_H_
#define CSPPROVIDER_H_

#include <stdio.h>
#include <limits.h>
#if ( __WORDSIZE == 64 )
#  define SIZEOF_VOID_P 8
#else
#  define SIZEOF_VOID_P 4
#endif

#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include <string.h>
#   include <stdlib.h>
#   include <CSP_WinDef.h>
#   include <CSP_WinCrypt.h>
#endif
#include <WinCryptEx.h>
#include <jni.h>

#define OID_EKU_ANY         "2.5.29.37.0"

#define CERTIFICATE_PARSING_EXCEPTION \
                            "java/security/cert/CertificateParsingException"
#define DIGEST_EXCEPTION    "java/security/DigestException"
#define INVALID_KEY_EXCEPTION \
                            "java/security/InvalidKeyException"
#define INVALID_KEYSPEC_EXCEPTION \
                            "InvalidKeySpecException"
//#define KEY_EXCEPTION       "java/security/KeyException"
#define KEYSTORE_EXCEPTION  "java/security/KeyStoreException"
#define PROVIDER_EXCEPTION  "java/security/ProviderException"
#define SIGNATURE_EXCEPTION "java/security/SignatureException"
#define NOSUCHALGORITHM_EXCEPTION \
                            "java/security/NoSuchAlgorithmException"

/*
 * Throws an arbitrary Java exception.
 * The exception message is a Windows system error message.
 */
void ThrowException(JNIEnv *env, char *exceptionName, DWORD dwError);

/*
 * Maps the name of a hash algorithm to an algorithm identifier.
 */
ALG_ID MapHashAlgorithm(JNIEnv *env, jstring jAlgorithm);

ALG_ID MapSignAlgorithm(JNIEnv *env, jstring jAlgorithm);

ALG_ID MapEncryptAlgorithm(JNIEnv *env, jstring jAlgorithm);

ALG_ID MapExchangeAlgorithm(JNIEnv *env, jstring jAlgorithm);

BOOL FindProviderByAlg(JNIEnv *env, const char* pszAlgOID, ALG_ID algId, DWORD *pdwProvId, DWORD *pdwBitLen);

#endif /* CSPPROVIDER_H_ */
