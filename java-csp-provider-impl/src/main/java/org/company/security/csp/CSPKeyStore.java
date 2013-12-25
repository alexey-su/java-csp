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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.SecurityPermission;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of key store for Windows using the Microsoft Crypto API.
 * 
 * @since 1.6
 */
public class CSPKeyStore extends KeyStoreSpi {
	public static int DEFAULT_PROVIDER_ID = 75;	// TODO 75 - CryptoPro providerId in MS Crypto API
	private static transient Logger LOGGER = LoggerFactory.getLogger(CSPKeyStore.class);
	private static MessageDigest sha1;

	public static final class MY extends CSPKeyStore {
		public MY() {
			super("MY", true, DEFAULT_PROVIDER_ID);
		}
	}

	public static final class ROOT extends CSPKeyStore {
		public ROOT() {
			super("ROOT");
		}
	}

	public static final class CA extends CSPKeyStore {
		public CA() {
			super("CA");
		}
	}

	/**
	 * Linux CSP 3.6R3 "AddressBook" – для сертификатов других пользователей.
	 */
	public static final class AddressBook extends CSPKeyStore {
		public AddressBook() {
			super("AddressBook");
		}
	}

	public static final class FILE extends CSPKeyStore {
		public FILE() {
			super("FILE", false, DEFAULT_PROVIDER_ID);
		}

		@Override
		public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
			// не разрещаем загружать хрнилище, пока не будет указано название файла
			if(keyStoreLocation != null)
				super.engineLoad(stream, password);
		}
		
	}


//	public static final class HDImage extends KeyStore {
//		public HDImage() {
//			super("\\\\.\\HDIMAGE\\", true, DEFAULT_PROVIDER_ID);
////			super("HDIMAGE");
//		}
//	}
//
//	private static byte[] calcHashPropId(X509Certificate certificate) {
//		byte[] digest = null;
//		try {
//			digest = calcHashPropId(certificate.getEncoded());
//		}
//		catch(CertificateEncodingException e) {
//		}
//		return digest;
//	}

	private static byte[] calcHashPropId(byte[] encoded) {
		byte[] digest = null;

		if(encoded != null) {
			try {
				if(sha1 == null) {
					sha1 = MessageDigest.getInstance("SHA1");
				}
				try {
					digest = sha1.digest(encoded);
				}
				finally {
					sha1.reset();
				}
			}
			catch(NoSuchAlgorithmException e) {
			}
		}
		return digest;
	}


	class KeyEntry {
		private String alias;
		private CSPKey privateKey;
		private X509Certificate certChain[];

		KeyEntry(String alias, byte[] encoded) {
			this.alias = alias;
//			this.certificate = certificate;

			if(alias == null) {
				byte[] digest = calcHashPropId(encoded);
				this.alias = new BigInteger(1, digest).toString(16);
			}
		}

		KeyEntry(CSPKey key, X509Certificate[] chain) {
			this(null, key, chain);
		}

		KeyEntry(String alias, CSPKey key, X509Certificate[] chain) {
			this.privateKey = key;
			this.certChain = chain;

			// использовать только SHA1
			if(useAliasSHA1) {
				try {
					byte[] digest = calcHashPropId(chain[0].getEncoded());
					this.alias = new BigInteger(1, digest).toString(16);
				} catch (CertificateEncodingException ex) {
					// ошибка получения сведений о сертификате
					throw new IllegalArgumentException(ex.getMessage(), ex);
				}
			}
			else {
				/*
				 * The default alias for both entry types is derived from a hash
				 * value intrinsic to the first certificate in the chain.
				 */
				if(alias == null) {
					try {
						alias = CSPKey.getContainerName(key.getHCryptKey());
					} catch (KeyStoreException e) {
						// ошибка получения контейнера закрытого ключа
						try {
							byte[] digest = calcHashPropId(chain[0].getEncoded());
							this.alias = new BigInteger(1, digest).toString(16);
						} catch (CertificateEncodingException ex) {
							// ошибка получения сведений о сертификате
							throw new IllegalArgumentException(e.getMessage(), e);
						}
					}
				} else {
					this.alias = alias;
				}
			}
		}

		/**
		 * Gets the alias for the keystore entry.
		 */
		String getAlias() {
			return alias;
		}

		/**
		 * Sets the alias for the keystore entry.
		 */
		void setAlias(String alias) {
			// TODO - set friendly name prop in cert store
			this.alias = alias;
		}

		/**
		 * Gets the private key for the keystore entry.
		 */
		CSPKey getPrivateKey() {
			return privateKey;
		}

		/**
		 * Sets the private key for the keystore entry.
		 */
		void setPrivateKey(CSPPrivateKey key) throws InvalidKeyException, KeyStoreException {
			privateKey = key;
		}

		/**
		 * Gets the certificate chain for the keystore entry.
		 */
		X509Certificate[] getCertificateChain() {
			return certChain;
		}

		/**
		 * Sets the certificate chain for the keystore entry.
		 */
		void setCertificateChain(X509Certificate[] chain)
				throws CertificateException, KeyStoreException {
			for (int i = 0; i < chain.length; i++) {
				byte[] encoding = chain[i].getEncoded();
				if (i == 0 && privateKey != null) {
					storeCertificate(getName(), alias, encoding,
							encoding.length, privateKey.getHCryptProvider(),
							privateKey.getHCryptKey());

				} else {
					storeCertificate(getName(), alias, encoding,
							encoding.length, 0L, 0L); // no private key to
														// attach
				}
			}
			certChain = chain;
		}
	};

	/*
	 * An X.509 certificate factory. Used to create an X.509 certificate from
	 * its DER-encoding.
	 */
	private CertificateFactory certificateFactory = null;

	/*
	 * Compatibility mode: for applications that assume keystores are
	 * stream-based this mode tolerates (but ignores) a non-null stream or
	 * password parameter when passed to the load or store methods. The mode is
	 * enabled by default.
	 */
	private static final String KEYSTORE_COMPATIBILITY_MODE_PROP = "org.company.security.csp.keyStoreCompatibilityMode";
	private final boolean keyStoreCompatibilityMode;
	/**
	 * Для совместимости с MS CertStore
	 * использовать только SHA1
	 */
	private boolean useAliasSHA1 = true;

	/*
	 * The keystore entries.
	 */
	private Collection<KeyEntry> entries = new ArrayList<KeyEntry>();

	/*
	 * The keystore name. Case is not significant.
	 */
	private final String storeName;
	private final boolean system;
	private final int providerId;
	protected String keyStoreLocation = null;

	public CSPKeyStore(String storeName) {
		this(storeName, true, 0);
	}
	
	public CSPKeyStore(String storeName, boolean system, int providerId) {
		// Get the compatibility mode
		String prop = AccessController.doPrivileged(new PrivilegedAction<String>() {

			@Override
			public String run() {
				return System.getProperty(KEYSTORE_COMPATIBILITY_MODE_PROP);
			}
		});

		if ("false".equalsIgnoreCase(prop)) {
			keyStoreCompatibilityMode = false;
		} else {
			keyStoreCompatibilityMode = true;
		}

		this.storeName = storeName;
		this.system = system;
		this.providerId = providerId;
	}


	public String getKeyStoreLocation() {
		return keyStoreLocation;
	}

	public void setKeyStoreLocation(String keyStoreLocation) {
		this.keyStoreLocation = keyStoreLocation;
	}

	/**
	 * Returns the key associated with the given alias.
	 * <p>
	 * A compatibility mode is supported for applications that assume a password
	 * must be supplied. It permits (but ignores) a non-null
	 * <code>password</code>. The mode is enabled by default. Set the
	 * <code>sun.security.mscapi.keyStoreCompatibilityMode</code> system
	 * property to <code>false</code> to disable compatibility mode and reject a
	 * non-null <code>password</code>.
	 * 
	 * @param alias
	 *            the alias name
	 * @param password
	 *            the password, which should be <code>null</code>
	 * 
	 * @return the requested key, or null if the given alias does not exist or
	 *         does not identify a <i>key entry</i>.
	 * 
	 * @exception NoSuchAlgorithmException
	 *                if the algorithm for recovering the key cannot be found,
	 *                or if compatibility mode is disabled and
	 *                <code>password</code> is non-null.
	 * @exception UnrecoverableKeyException
	 *                if the key cannot be recovered.
	 */
	public java.security.Key engineGetKey(String alias, char[] password)
			throws NoSuchAlgorithmException, UnrecoverableKeyException {
		if (alias == null) {
			return null;
		}

		if (password != null && !keyStoreCompatibilityMode) {
			throw new UnrecoverableKeyException("Password must be null");
		}

		if (engineIsKeyEntry(alias) == false)
			return null;

		for (KeyEntry entry : entries) {
			if (alias.equals(entry.getAlias())) {
				return entry.getPrivateKey();
			}
		}

		return null;
	}

	/**
	 * Returns the certificate chain associated with the given alias.
	 * 
	 * @param alias
	 *            the alias name
	 * 
	 * @return the certificate chain (ordered with the user's certificate first
	 *         and the root certificate authority last), or null if the given
	 *         alias does not exist or does not contain a certificate chain
	 *         (i.e., the given alias identifies either a <i>trusted certificate
	 *         entry</i> or a <i>key entry</i> without a certificate chain).
	 */
	public Certificate[] engineGetCertificateChain(String alias) {
		if (alias == null) {
			return null;
		}

		for (KeyEntry entry : entries) {
			if (alias.equals(entry.getAlias())) {
				X509Certificate[] certChain = entry.getCertificateChain();

				return certChain.clone();
			}
		}

		return null;
	}

	/**
	 * Returns the certificate associated with the given alias.
	 * 
	 * <p>
	 * If the given alias name identifies a <i>trusted certificate entry</i>,
	 * the certificate associated with that entry is returned. If the given
	 * alias name identifies a <i>key entry</i>, the first element of the
	 * certificate chain of that entry is returned, or null if that entry does
	 * not have a certificate chain.
	 * 
	 * @param alias
	 *            the alias name
	 * 
	 * @return the certificate, or null if the given alias does not exist or
	 *         does not contain a certificate.
	 */
	public Certificate engineGetCertificate(String alias) {
		if (alias == null) {
			return null;
		}

		for (KeyEntry entry : entries) {
			if (alias.equals(entry.getAlias())) {
				X509Certificate[] certChain = entry.getCertificateChain();
				return certChain[0];
			}
		}

		return null;
	}

	/**
	 * Returns the creation date of the entry identified by the given alias.
	 * 
	 * @param alias
	 *            the alias name
	 * 
	 * @return the creation date of this entry, or null if the given alias does
	 *         not exist
	 */
	public Date engineGetCreationDate(String alias) {
		if (alias == null) {
			return null;
		}
		return new Date();
	}

	/**
	 * Stores the given private key and associated certificate chain in the
	 * keystore.
	 * 
	 * <p>
	 * The given java.security.PrivateKey <code>key</code> must be accompanied
	 * by a certificate chain certifying the corresponding public key.
	 * 
	 * <p>
	 * If the given alias already exists, the keystore information associated
	 * with it is overridden by the given key and certificate chain. Otherwise,
	 * a new entry is created.
	 * 
	 * <p>
	 * A compatibility mode is supported for applications that assume a password
	 * must be supplied. It permits (but ignores) a non-null
	 * <code>password</code>. The mode is enabled by default. Set the
	 * <code>sun.security.mscapi.keyStoreCompatibilityMode</code> system
	 * property to <code>false</code> to disable compatibility mode and reject a
	 * non-null <code>password</code>.
	 * 
	 * @param alias
	 *            the alias name
	 * @param key
	 *            the private key to be associated with the alias
	 * @param password
	 *            the password, which should be <code>null</code>
	 * @param chain
	 *            the certificate chain for the corresponding public key (only
	 *            required if the given key is of type
	 *            <code>java.security.PrivateKey</code>).
	 * 
	 * @exception KeyStoreException
	 *                if the given key is not a private key, cannot be
	 *                protected, or if compatibility mode is disabled and
	 *                <code>password</code> is non-null, or if this operation
	 *                fails for some other reason.
	 */
	public void engineSetKeyEntry(String alias, java.security.Key key,
			char[] password, Certificate[] chain) throws KeyStoreException {
		if (alias == null) {
			throw new KeyStoreException("alias must not be null");
		}

		if (password != null && !keyStoreCompatibilityMode) {
			throw new KeyStoreException("Password must be null");
		}

		if (key instanceof CSPPrivateKey) {

			KeyEntry entry = null;
			boolean found = false;

			for (KeyEntry e : entries) {
				if (alias.equals(e.getAlias())) {
					found = true;
					entry = e;
					break;
				}
			}

			if (!found) {
				entry =
				// TODO new KeyEntry(alias, key, (X509Certificate[]) chain);
				new KeyEntry(alias, null, (X509Certificate[]) chain);
				entries.add(entry);
			}

			entry.setAlias(alias);

			try {
				entry.setPrivateKey((CSPPrivateKey) key);
				entry.setCertificateChain((X509Certificate[]) chain);

			} catch (CertificateException ce) {
				throw new KeyStoreException(ce);

			} catch (InvalidKeyException ike) {
				throw new KeyStoreException(ike);
			}

		} else {
			throw new UnsupportedOperationException(
					"Cannot assign the key to the given alias.");
		}
	}

	/**
	 * Assigns the given key (that has already been protected) to the given
	 * alias.
	 * 
	 * <p>
	 * If the protected key is of type <code>java.security.PrivateKey</code>, it
	 * must be accompanied by a certificate chain certifying the corresponding
	 * public key. If the underlying keystore implementation is of type
	 * <code>jks</code>, <code>key</code> must be encoded as an
	 * <code>EncryptedPrivateKeyInfo</code> as defined in the PKCS #8 standard.
	 * 
	 * <p>
	 * If the given alias already exists, the keystore information associated
	 * with it is overridden by the given key (and possibly certificate chain).
	 * 
	 * @param alias
	 *            the alias name
	 * @param key
	 *            the key (in protected format) to be associated with the alias
	 * @param chain
	 *            the certificate chain for the corresponding public key (only
	 *            useful if the protected key is of type
	 *            <code>java.security.PrivateKey</code>).
	 * 
	 * @exception KeyStoreException
	 *                if this operation fails.
	 */
	public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
			throws KeyStoreException {
		throw new UnsupportedOperationException(
				"Cannot assign the encoded key to the given alias.");
	}

	/**
	 * Assigns the given certificate to the given alias.
	 * 
	 * <p>
	 * If the given alias already exists in this keystore and identifies a
	 * <i>trusted certificate entry</i>, the certificate associated with it is
	 * overridden by the given certificate.
	 * 
	 * @param alias
	 *            the alias name
	 * @param cert
	 *            the certificate
	 * 
	 * @exception KeyStoreException
	 *                if the given alias already exists and does not identify a
	 *                <i>trusted certificate entry</i>, or this operation fails
	 *                for some other reason.
	 */
	public void engineSetCertificateEntry(String alias, Certificate cert)
			throws KeyStoreException {
		if (alias == null) {
			throw new KeyStoreException("alias must not be null");
		}

		if (cert instanceof X509Certificate) {

			// TODO - build CryptoAPI chain?
			X509Certificate[] chain = new X509Certificate[] { (X509Certificate) cert };
			KeyEntry entry = null;
			boolean found = false;

			for (KeyEntry e : entries) {
				if (alias.equals(e.getAlias())) {
					found = true;
					entry = e;
					break;
				}
			}

			if (!found) {
				entry = new KeyEntry(alias, null, chain);
				entries.add(entry);

			}
			if (entry.getPrivateKey() == null) { // trusted-cert entry
				entry.setAlias(alias);

				try {
					entry.setCertificateChain(chain);

				} catch (CertificateException ce) {
					throw new KeyStoreException(ce);
				}
			}

		} else {
			throw new UnsupportedOperationException(
					"Cannot assign the certificate to the given alias.");
		}
	}

	/**
	 * Deletes the entry identified by the given alias from this keystore.
	 * 
	 * @param alias
	 *            the alias name
	 * 
	 * @exception KeyStoreException
	 *                if the entry cannot be removed.
	 */
	public void engineDeleteEntry(String alias) throws KeyStoreException {
		if (alias == null) {
			throw new KeyStoreException("alias must not be null");
		}

		for (KeyEntry entry : entries) {
			if (alias.equals(entry.getAlias())) {

				// Get end-entity certificate and remove from system cert store
				X509Certificate[] certChain = entry.getCertificateChain();
				if (certChain != null) {

					try {

						byte[] encoding = certChain[0].getEncoded();
						removeCertificate(getName(), alias, encoding,
								encoding.length);

					} catch (CertificateException e) {
						throw new KeyStoreException("Cannot remove entry: " + e);
					}
				}
				CSPKey privateKey = entry.getPrivateKey();
				if (privateKey != null) {
					destroyKeyContainer(
							privateKey.getProviderId(),
							storeName,
							CSPKey.getContainerName(privateKey.getHCryptProvider()));
				}

				entries.remove(entry);
				break;
			}
		}
	}

	/**
	 * Lists all the alias names of this keystore.
	 * 
	 * @return enumeration of the alias names
	 */
	public Enumeration<String> engineAliases() {

		final Iterator<KeyEntry> iter = entries.iterator();

		return new Enumeration<String>() {
			public boolean hasMoreElements() {
				return iter.hasNext();
			}

			public String nextElement() {
				KeyEntry entry = iter.next();
				return entry.getAlias();
			}
		};
	}

	/**
	 * Checks if the given alias exists in this keystore.
	 * 
	 * @param alias
	 *            the alias name
	 * 
	 * @return true if the alias exists, false otherwise
	 */
	public boolean engineContainsAlias(String alias) {
		for (Enumeration<String> enumerator = engineAliases(); enumerator.hasMoreElements();) {
			String a = enumerator.nextElement();

			if (a.equals(alias))
				return true;
		}
		return false;
	}

	/**
	 * Retrieves the number of entries in this keystore.
	 * 
	 * @return the number of entries in this keystore
	 */
	public int engineSize() {
		return entries.size();
	}

	/**
	 * Returns true if the entry identified by the given alias is a <i>key
	 * entry</i>, and false otherwise.
	 * 
	 * @return true if the entry identified by the given alias is a <i>key
	 *         entry</i>, false otherwise.
	 */
	public boolean engineIsKeyEntry(String alias) {

		if (alias == null) {
			return false;
		}

		for (KeyEntry entry : entries) {
			if (alias.equals(entry.getAlias())) {
				return entry.getPrivateKey() != null;
			}
		}

		return false;
	}

	/**
	 * Returns true if the entry identified by the given alias is a <i>trusted
	 * certificate entry</i>, and false otherwise.
	 * 
	 * @return true if the entry identified by the given alias is a <i>trusted
	 *         certificate entry</i>, false otherwise.
	 */
	public boolean engineIsCertificateEntry(String alias) {
		for (KeyEntry entry : entries) {
			if (alias.equals(entry.getAlias())) {
				return entry.getPrivateKey() == null;
			}
		}

		return false;
	}

	/**
	 * Returns the (alias) name of the first keystore entry whose certificate
	 * matches the given certificate.
	 * 
	 * <p>
	 * This method attempts to match the given certificate with each keystore
	 * entry. If the entry being considered is a <i>trusted certificate
	 * entry</i>, the given certificate is compared to that entry's certificate.
	 * If the entry being considered is a <i>key entry</i>, the given
	 * certificate is compared to the first element of that entry's certificate
	 * chain (if a chain exists).
	 * 
	 * @param cert
	 *            the certificate to match with.
	 * 
	 * @return the (alias) name of the first entry with matching certificate, or
	 *         null if no such entry exists in this keystore.
	 */
	public String engineGetCertificateAlias(Certificate cert) {
		for (KeyEntry entry : entries) {
			if (entry.certChain != null && entry.certChain[0].equals(cert)) {
				return entry.getAlias();
			}
		}

		return null;
	}

	/**
	 * engineStore is currently a no-op. Entries are stored during
	 * engineSetEntry.
	 * 
	 * A compatibility mode is supported for applications that assume keystores
	 * are stream-based. It permits (but ignores) a non-null <code>stream</code>
	 * or <code>password</code>. The mode is enabled by default. Set the
	 * <code>sun.security.mscapi.keyStoreCompatibilityMode</code> system
	 * property to <code>false</code> to disable compatibility mode and reject a
	 * non-null <code>stream</code> or <code>password</code>.
	 * 
	 * @param stream
	 *            the output stream, which should be <code>null</code>
	 * @param password
	 *            the password, which should be <code>null</code>
	 * 
	 * @exception IOException
	 *                if compatibility mode is disabled and either parameter is
	 *                non-null.
	 */
	public void engineStore(OutputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		if (stream != null && !keyStoreCompatibilityMode) {
			throw new IOException("Keystore output stream must be null");
		}

		if (password != null && !keyStoreCompatibilityMode) {
			throw new IOException("Keystore password must be null");
		}
	}

	/**
	 * Loads the keystore.
	 * 
	 * A compatibility mode is supported for applications that assume keystores
	 * are stream-based. It permits (but ignores) a non-null <code>stream</code>
	 * or <code>password</code>. The mode is enabled by default. Set the
	 * <code>sun.security.mscapi.keyStoreCompatibilityMode</code> system
	 * property to <code>false</code> to disable compatibility mode and reject a
	 * non-null <code>stream</code> or <code>password</code>.
	 * 
	 * @param stream
	 *            the input stream, which should be <code>null</code>.
	 * @param password
	 *            the password, which should be <code>null</code>.
	 * 
	 * @exception IOException
	 *                if there is an I/O or format problem with the keystore
	 *                data. Or if compatibility mode is disabled and either
	 *                parameter is non-null.
	 * @exception NoSuchAlgorithmException
	 *                if the algorithm used to check the integrity of the
	 *                keystore cannot be found
	 * @exception CertificateException
	 *                if any of the certificates in the keystore could not be
	 *                loaded
	 * @exception SecurityException
	 *                if the security check for
	 *                <code>SecurityPermission("authProvider.<i>name</i>")</code>
	 *                does not pass, where <i>name</i> is the value returned by
	 *                this provider's <code>getName</code> method.
	 */
	public void engineLoad(InputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		if (stream != null && !keyStoreCompatibilityMode) {
			throw new IOException("Keystore input stream must be null");
		}

		if (password != null && !keyStoreCompatibilityMode) {
			throw new IOException("Keystore password must be null");
		}

		/*
		 * Use the same security check as AuthProvider.login
		 */
		SecurityManager sm = System.getSecurityManager();
		if (sm != null) {
			sm.checkPermission(new SecurityPermission("authProvider.JavaCSPProvider"));
		}

		// Clear all key entries
		entries.clear();

		try {
			// Load keys and/or certificate chains
			loadKeysOrCertificateChains(getName(), entries, system, providerId);
		} catch (KeyStoreException e) {
			throw new IOException(e);
		}
	}

	/**
	 * Через данный метод происходит загрузка внешнего файла хранилища
	 */
	@Override
	public void engineLoad(LoadStoreParameter param) throws IOException,
			NoSuchAlgorithmException, CertificateException {
		
		if(param.getProtectionParameter() instanceof KeyStoreProtection) {
			KeyStoreProtection protection = (KeyStoreProtection) param.getProtectionParameter();
			
			keyStoreLocation = protection.keyStoreLocation;
			engineLoad(null, protection.getPassword());
		}
		else {
			super.engineLoad(param);
		}
	}

	/**
	 * Generates a certificate chain from the collection of certificates and
	 * stores the result into a key entry.
	 */
	private void generateCertificateChain(String alias,
			Collection<X509Certificate> certCollection, Collection<KeyEntry> entries) {
		try {
			X509Certificate[] certChain = new X509Certificate[certCollection
					.size()];

			int i = 0;
			for (Iterator<X509Certificate> iter = certCollection.iterator(); iter.hasNext(); i++) {
				certChain[i] = iter.next();
			}

			KeyEntry entry = new KeyEntry(alias, null, certChain);

			// Add cert chain
			entries.add(entry);
		} catch (Throwable e) {
			// Ignore the exception and skip this entry
			// TODO - throw CertificateException?
			LOGGER.error(e.getMessage(), e);
		}
	}

	/**
	 * Generates CSP key and certificate chain from the private key handle,
	 * collection of certificates and stores the result into key entries.
	 */
	private void generateCSPKeyAndCertificateChain(String alias, String container,
			int providerId,
			long hCryptProv, long hCryptKey, int keyLength,
			Collection<X509Certificate> certCollection, Collection<KeyEntry> entries) {
		try {
			X509Certificate[] certChain = new X509Certificate[certCollection.size()];

			int i = 0;
			for (Iterator<X509Certificate> iter = certCollection.iterator(); iter.hasNext(); i++) {
				certChain[i] = iter.next();
			}

			// если псевдоним ключа не задан, берем имя контейнера, как делает JCP
//			if(alias == null)
//				alias = container;

			CSPPrivateKey privateKey = new CSPPrivateKey(hCryptProv, hCryptKey, keyLength);
			privateKey.setContainer(container);
			privateKey.setProviderId(providerId);
			
			KeyEntry entry = new KeyEntry(alias, privateKey, certChain);

			// Add cert chain
			entries.add(entry);
		} catch (Throwable e) {
			// Ignore the exception and skip this entry
			// TODO - throw CertificateException?
			LOGGER.error(e.getMessage(), e);
		}
	}

	/**
	 * Generates certificates from byte data and stores into cert collection.
	 * 
	 * @param data
	 *            Byte data.
	 * @param certCollection
	 *            Collection of certificates.
	 */
	private void generateCertificate(byte[] data, Collection<X509Certificate> certCollection) {
		try {
			ByteArrayInputStream bis = new ByteArrayInputStream(data);

			// Obtain certificate factory
			if (certificateFactory == null) {
				certificateFactory = CertificateFactory.getInstance("X.509", CSPProvider.CSP_PROVIDER);
			}

			// Generate certificate
			Collection c = certificateFactory.generateCertificates(bis);
			certCollection.addAll(c);
		} catch (CertificateException e) {
			// Ignore the exception and skip this certificate
			// TODO - throw CertificateException?
			LOGGER.error(e.getMessage(), e);
		} catch (Throwable te) {
			// Ignore the exception and skip this certificate
			// TODO - throw CertificateException?
			LOGGER.error(te.getMessage(), te);
		}
	}

	/**
	 * Returns the name of the keystore.
	 */
	private String getName() {
		String location = storeName;
		
		if(keyStoreLocation != null && !keyStoreLocation.isEmpty())
			location = keyStoreLocation;
		return location;
	}

	/**
	 * Load keys and/or certificates from keystore into Collection.
	 * 
	 * @param name
	 *            Name of keystore.
	 * @param entries
	 *            Collection of key/certificate.
	 * @param providerId2 
	 * @param system2 
	 */
	private void loadKeysOrCertificateChains(String name, Collection<KeyEntry> entries, boolean system, int providerId) throws KeyStoreException {
		NativeCrypto.loadKeysOrCertificateChains(this, name, entries, system, providerId);
	}

	/**
	 * Stores a DER-encoded certificate into the certificate store
	 * 
	 * @param name
	 *            Name of the keystore.
	 * @param alias
	 *            Name of the certificate.
	 * @param encoding
	 *            DER-encoded certificate.
	 */
	private void storeCertificate(String name, String alias,
			byte[] encoding, int encodingLength, long hCryptProvider,
			long hCryptKey) throws CertificateException, KeyStoreException {
		NativeCrypto.storeCertificate(name, alias, encoding, encodingLength, hCryptProvider, hCryptKey);
	}

	/**
	 * Removes the certificate from the certificate store
	 * 
	 * @param name
	 *            Name of the keystore.
	 * @param alias
	 *            Name of the certificate.
	 * @param encoding
	 *            DER-encoded certificate.
	 */
	private void removeCertificate(String name, String alias, byte[] encoding, int encodingLength) 
			throws CertificateException, KeyStoreException {
		NativeCrypto.removeCertificate(name, alias, encoding, encodingLength);
	}

	/**
	 * Destroys the key container.
	 * 
	 * 
	 * @param keyContainerName
	 *            The name of the key container.
	 */
	private void destroyKeyContainer(int providerId, String storeName, String keyContainerName) throws KeyStoreException {
		NativeCrypto.destroyKeyContainer(providerId, storeName, keyContainerName);
	}

//	/**
//	 * Generates a private-key BLOB from a key's components.
//	 */
//	private native byte[] generatePrivateKeyBlob(int keyBitLength,
//			byte[] modulus, byte[] publicExponent, byte[] privateExponent,
//			byte[] primeP, byte[] primeQ, byte[] exponentP, byte[] exponentQ,
//			byte[] crtCoefficient) throws InvalidKeyException;
//
//	private native CSPPrivateKey storePrivateKey(byte[] keyBlob,
//			String keyContainerName, int keySize) throws KeyStoreException;

	public abstract static class Builder extends KeyStore.Builder {
		// maximum times to try the callbackhandler if the password is wrong
		static final int MAX_CALLBACK_TRIES = 3;

		public static Builder newInstance(String type, Provider provider, 
				String keyStoreLocation, char[] password) {
			if ((type == null) || (provider == null)) {
				throw new NullPointerException();
			}
			if (!"CSPProvider".equals(provider.getName())) {
				throw new IllegalArgumentException("Реализуется только для CSPProvider");
			}
			if (!"FILE".equals(type)) {
				throw new IllegalArgumentException("Реализуется только для хранилища FILE в CSPProvider");
			}

			File file = new File(keyStoreLocation);
			if (file.isFile() == false) {
				throw new IllegalArgumentException
				("File does not exist or it does not refer " +
						"to a normal file: " + file);
			}

			KeyStoreProtection protection = new KeyStoreProtection(type, provider,
					file.getAbsolutePath(), password);

			return new KeyStoreBuilder(protection, AccessController.getContext());
		}

		private static final class KeyStoreBuilder extends Builder {

			private KeyStoreProtection protection;
			private final AccessControlContext context;

			private KeyStore keyStore;

			private Throwable oldException;

			KeyStoreBuilder(KeyStoreProtection protection, AccessControlContext context) {
				this.protection = protection;
				this.context = context;
			}

			public synchronized KeyStore getKeyStore() throws KeyStoreException
			{
				if (keyStore != null) {
					return keyStore;
				}
				if (oldException != null) {
					throw new KeyStoreException
					("Previous KeyStore instantiation failed",
							oldException);
				}
				PrivilegedExceptionAction<Object> action = 
						new PrivilegedExceptionAction<Object>() {
					public Object run() throws Exception {
						// when using a CallbackHandler,
						// reprompt if the password is wrong
						int tries = 0;
						while (true) {
							tries++;
							try {
								return run0();
							} catch (IOException e) {
								if ((tries < MAX_CALLBACK_TRIES)
										&& (e.getCause() instanceof UnrecoverableKeyException)) {
									continue;
								}
								throw e;
							}
						}
					}
					public Object run0() throws Exception {
						KeyStore ks;
						if (protection.provider == null) {
							ks = KeyStore.getInstance(protection.type);
						} else {
							ks = KeyStore.getInstance(protection.type, protection.provider);
						}
						InputStream in = null;
						char[] password = null;
						try {
							ks.load(new SimpleLoadStoreParameter(protection));
							return ks;
						} finally {
							if (in != null) {
								in.close();
							}
						}
					}
				};
				try {
					keyStore = (KeyStore)AccessController.doPrivileged
							(action, context);
					return keyStore;
				} catch (PrivilegedActionException e) {
					oldException = e.getCause();
					throw new KeyStoreException
					("KeyStore instantiation failed", oldException);
				}
			}

			public synchronized ProtectionParameter 
			getProtectionParameter(String alias) {
				if (alias == null) {
					throw new NullPointerException();
				}
				if (keyStore == null) {
					throw new IllegalStateException
					("getKeyStore() must be called first");
				}
				return protection;
			}
		}
	}

	public static class KeyStoreProtection extends PasswordProtection {
		private String keyStoreLocation;
		private String type;
		private Provider provider;

		public KeyStoreProtection(String type, Provider provider,
				String keyStoreLocation, char[] password) {
			super(password);
			this.type = type;
			this.provider = provider;
			this.keyStoreLocation = keyStoreLocation;
		}

		public String getKeyStoreLocation() {
			return keyStoreLocation;
		}
	}

	public static class SimpleLoadStoreParameter implements LoadStoreParameter {

		private final ProtectionParameter protection;

		SimpleLoadStoreParameter(ProtectionParameter protection) {
			this.protection = protection;
		}

		public ProtectionParameter getProtectionParameter() {
			return protection;
		}
	}
}
