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

import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;


public class NativeCrypto {

	//
	// Работа с хранилищем ключей
	//

	/**
	 * Загрузить цепочку сертификатов
	 * @param hCryptProv native HCRYPTPROV
	 * @param hCertStore native HCERTSTORE
	 * @param calcHashPropId value CERT_HASH_PROP_ID (SHA1)
	 * @return цепочка сертификатов
	 */
	public static native X509Certificate[] loadCertificateChain(long hCryptProv, long hCertStore, byte[] calcHashPropId);

	/**
	 * Загрузить сетрификаты из хранилища.
	 * 
	 * @param keyStore заполняемое хранилище
	 * @param name название хранилища
	 * @param entries заполняемый список ключей
	 * @param system признак использования системного хранилища
	 * @param providerId идентификатор провайдера
	 * @throws KeyStoreException
	 */
	public static native void loadKeysOrCertificateChains(CSPKeyStore keyStore, String name,
			Collection<CSPKeyStore.KeyEntry> entries, 
			boolean system, int providerId) 
					throws ProviderException, KeyStoreException;	

	public static native void storeCertificate(String name, String alias,
			byte[] encoding, int encodingLength, 
			long hCryptProvider, long hCryptKey) 
			throws CertificateException, KeyStoreException;

	public static native void removeCertificate(String name, String alias, byte[] encoding, int encodingLength) 
			throws CertificateException, KeyStoreException;

	/**
	 * Убрать сведения о контейнере закрытого ключа из хранилища
	 * @param providerId идентификатор провайдера
	 * @param storeName название хранилища
	 * @param keyContainerName название конейнера закрытого ключа
	 * @throws KeyStoreException
	 */
	public static native void destroyKeyContainer(int providerId, String storeName, String keyContainerName) throws KeyStoreException;

	@Deprecated
	public static native long findCertificateUsingAlias(String certStoreName, String certAliasName);

	@Deprecated
	public static native long getKeyFromCert(long pCertContext, boolean usePrivateKey);

	/**
	 * Получить числовой параметр ключа 
	 * @param hCryptoKey
	 * @param param KP_ALGID, 
	 * @return
	 */
	public static native int getKeyParam(long hCryptoKey, int param)
			throws InvalidKeyException;

	/**
	 * Получить OID идентификатор алгоритма ключа
	 * @param hCryptoKey
	 * @return
	 */
	public static native String getKeyAlgOID(long hCryptoKey)
			throws InvalidKeyException;

	/**
	 * Уничтожить ключ
	 */
	public static native void keyDestroy(long hProvider, long hKey);

	/**
	 * Название контейнера ключей
	 * @param hCryptoProv native HCRYPTPROV
	 */
	public static native String getContainerName(long hCryptoProv)
			throws KeyStoreException;

	public static native byte[] getPublicKeyEncode(long hCryptoProvider, long hCryptoKey);

	//
	// Шифрование
	//

	/**
	 * шифровать/расшифровать данные буфера
	 * @param data буфер данных
	 * @param dataSize размер буфера данных
	 * @param hCryptProvider native HCRYPTPROV
	 * @param hCryptKey native HCRYPTKEY
	 * @param doEncrypt шифровать/расшифровать
	 * @param paddingLength размер выравнивания блока шифрования
	 * @return 
	 */
	public static native byte[] encryptDecrypt(byte[] data, int dataOffset, int dataSize, long hCryptoKey, 
			boolean doEncrypt, boolean doFinal, int paddingLength)
					throws InvalidKeyException;

	//
	// Работа с подписями
	//

	/**
	 * Подписать данные
	 * @param noHashOID признак не использования хеш функции 
	 * @param hash значение ранее расчитанной хеш функции
	 * @param hashSize длина значения хеш функции
	 * @param messageDigestAlgorithm название алгоритма хеш функции
	 * @param signName название алгоритма подписи
	 * @param hCryptProvider native HCRYPTPROV
	 * @param hCryptKey native HCRYPTKEY
	 * @return 
	 */
	public static native byte[] signHash(CSPSignature cspSignature, boolean noHashOID, byte[] hash, int hashSize,
			String messageDigestAlgorithm,
			long hCryptoProvider, long hCryptoKey);

	public static native byte[] sign(CSPSignature cspSignature, boolean noHashOID, byte[] hash, int hashSize,
			String messageDigestAlgorithm, int providerId, String context);

	/**
	 * Проверить подпись
	 * @param hash значение ранее расчитанной хеш функции
	 * @param hashSize длина значения хеш функции
	 * @param messageDigestAlgorithm название алгоритма хеш функции
	 * @param signName название алгоритма подписи
	 * @param signature значение подписи
	 * @param signatureSize длина значения подписи
	 * @param hCryptProvider native HCRYPTPROV
	 * @param hCryptKey native HCRYPTKEY
	 * @param hCryptoProvider
	 * @param hCryptoKey
	 * @return 
	 */
	public static native boolean verifySignedHash(byte[] hash, int hashSize,
			String messageDigestAlgorithm, byte[] signature,
			int signatureSize, long hCryptoProvider, long hCryptoKey);

	public static native void digestInit(CSPDigest cspDigest, String algorithm) 
			throws DigestException, ProviderException, NoSuchAlgorithmException;

	public static native void digestDestroy(long hCryptoProvider, long hCryptoHash);

	public static native void digestEngineUpdateByte(long hCryptoHash, byte input)
			throws DigestException;

	public static native void digestEngineUpdateBytes(long hCryptoHash, byte[] input, int offset, int len)
			throws DigestException;

	public static native byte[] digestEngineDigest(long hCryptoHash)
			throws DigestException;

	/**
	 * Установить параметр для хеш функции. MS CryptoAPI функция CryptSetHashParam.
	 * @param hCryptoHash
	 * @param param идентификатор параметра
	 * @param bytes устанавливаемое значение
	 * @param offset смещение в массиве
	 * @param len длина данных
	 */
	public static native void digestSetParameter(long hCryptoHash, int param, byte[] bytes, int offset, int len);

	/**
	 * Создать открытый ключ по идетификатору алгоритма и содержимому ключа
	 * @param keyEncoded содержимое ключа
	 * @param length размер содержимого ключа
	 * @return
	 */
	public static native CSPPublicKey initPublicKey(byte[] keyEncoded, int length) 
			throws InvalidKeyException, NoSuchAlgorithmException;

	/**
	 * Формирование открытого ключа из X509 ASN1 (PKCS#8).
	 * То же самое, что и метод initPublicKey. Отличие - посылаемые типы исключений.
	 * @param algorithm
	 * @param encoded
	 * @param length 
	 * @return
	 */
	public static native CSPPublicKey generatePublic(byte[] keyEncoded, int length);

}
