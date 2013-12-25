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

import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CSPNative {
	private static final Logger LOGGER = LoggerFactory.getLogger(CSPNative.class);

	private static final String MANIFEST_PATH = "/META-INF/MANIFEST.MF";
	private static boolean load = false;

	public static void init() {
		init(null, null);
	}

	public static void init(String nativePath, String bundleNativeCode) {
		if(load)
			return;

		load = new CSPNative().loadNativeLibraries(nativePath, bundleNativeCode);
	}

	private CSPNative() {
	}

	boolean loadNativeLibraries(String nativePath, String bundleNativeCode) {
		boolean result = false;

		// если не задана строка, берем ее из манифеста
		if(bundleNativeCode == null || bundleNativeCode.isEmpty())
			bundleNativeCode = findBundleNativeCode();

		if(bundleNativeCode != null) {
			// набор загружаемых библиотек
			List<String> nativeLibaries = findNativeLibraries(bundleNativeCode);
			
			for(String path : nativeLibaries) {
				LOGGER.debug("load library {}", path);
				
				if(! loadFromPath(nativePath, path))
					loadLibrary(nativePath, path);
			}
			result = true;
		}
		return result;
	}

	private String findBundleNativeCode() {
		String bundleNativeCode = null;

		// Надо получить доступ к манифесту текущего jar файла
		// http://stackoverflow.com/questions/1272648/reading-my-own-jars-manifest
		Class<CSPNative> clazz = CSPNative.class;
		String className = clazz.getSimpleName() + ".class";
		String classPath = clazz.getResource(className).toString();
		String manifestPath;

		// Стандартно, провайдер лежит в jar файле.
		// В сборке, провайдер берется из неупакованного каталога.
		if(classPath.startsWith("jar")) {
			manifestPath = classPath.substring(0, classPath.lastIndexOf("!") + 1) + MANIFEST_PATH;
		}
		else if(classPath.startsWith("file")) {
			String classNameFull = clazz.getName().replace('.', '/');
			manifestPath = classPath.substring(0, classPath.lastIndexOf(classNameFull) - 1) + MANIFEST_PATH;
		}
		else {
			System.out.format("Not find manifest for %s\n", classPath);
			return null;
		}
		InputStream manifestStream = null;

		try {
			manifestStream = new URL(manifestPath).openStream();
			
			Manifest manifest = new Manifest(manifestStream);
			Attributes attributes = manifest.getMainAttributes();
			bundleNativeCode = attributes.getValue("Bundle-NativeCode");
		}
		catch(IOException e) {
			e.printStackTrace();
		}
		finally {
			closeSilently(manifestStream);
		}

		return bundleNativeCode;
	}

	/**
	 * Определение списка загружаемых библиотек для текущей операционной системы
	 * @param bundleNativeCode содержимое параметра Bundle-NativeCode
	 * @return список библиотек
	 */
	private List<String> findNativeLibraries(String bundleNativeCode) {
		return new BundleNativeCode(bundleNativeCode, null).match();
	}


	private boolean loadFromPath(String nativePath, String path) {
		try {
			File file;

			if(nativePath != null && nativePath.isEmpty())
				file = new File(path);
			else
				file = new File(nativePath, path);

			System.load(file.getAbsolutePath());
			return true;
		} catch (Exception e) {
			return false;
		} catch (UnsatisfiedLinkError e) {
			return false;
		}
	}

	private boolean loadLibrary(String nativePath, String path) {
		URL url = CSPNative.class.getClassLoader().getResource(path);
		LOGGER.debug("url = {}",url);

		if (url == null) {
			return false;
		}

		File file = new File(url.getPath());

		if (file.canRead()) {
//			return loadFromPath(file.getAbsolutePath());
			System.load(file.getAbsolutePath());
			return true;
		}

		OutputStream os = null;
		InputStream is = null;
		boolean createTempFile = nativePath == null || nativePath.isEmpty();

		try {
			
			if(createTempFile) {
				file = File.createTempFile("java-csp-provider", "");
				file.deleteOnExit();
			}
			else {
				file = new File(nativePath, path);
				File parent = file.getParentFile();
				if(!parent.exists())
					parent.mkdirs();
			}
			LOGGER.debug("file = {}", file);

			is = url.openStream();
			os = new FileOutputStream(file);

			try {
				byte buffer[] = new byte[128 * 1024];

				int read = is.read(buffer);

				while (read > 0) {
					os.write(buffer, 0, read);
					read = is.read(buffer);
				}
				os.flush();
			}
			finally {
				closeSilently(os);
				closeSilently(is);
				
				os = null;
				is = null;
			}
			System.load(file.getAbsolutePath());

			return true;
		} catch (IOException e) {
			throw new RuntimeException("Unable to load native library.", e);
		} finally {
			if (createTempFile && file != null) {
				file.delete();
			}
			closeSilently(os);
			closeSilently(is);
		}
	}

	public static void closeSilently(Closeable closeable) {
		if (closeable == null) {
			return;
		}
		try {
			closeable.close();
		} catch (IOException e) {
			// ignore
		}
	}
}
