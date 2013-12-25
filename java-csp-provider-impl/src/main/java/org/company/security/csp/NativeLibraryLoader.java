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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.StringTokenizer;

public class NativeLibraryLoader {
	public static final String OPENSSL_CONF = "openssl.config";
//	public static final String DEFAULT_CONFIG = "/META-INF/hyjsse.properties";
	public static final String DEFAULT_CONFIG = "etc/cspprovider.properties";
	public static final String INTERNAL_CONFIG = "META-INF/cspprovider.properties";
	public static final String DEFAULT_LIBRARIES = "csp-provider-native";
	static Properties defaultConfig;

	public static Properties getDefaultConfig() {
		if(defaultConfig == null)
			defaultConfig = loadConfig(DEFAULT_CONFIG);
		return defaultConfig;
	}

	private static Properties loadConfig(String fileName) {
		Properties properties = new Properties();
//		ClassLoader cl = NativeLibraryLoader.class.getClassLoader();
//		Thread.currentThread().getContextClassLoader();
		InputStream is = null; 

		try {
			is = new FileInputStream(fileName);
			properties.load(is);
		} catch (IOException e) {
			try {
				ClassLoader cl = Thread.currentThread().getContextClassLoader();
				is = cl.getResourceAsStream(INTERNAL_CONFIG);
				properties.load(is);
			}
			catch(Exception exc) {
				// FIXME
				System.err.println(e.getMessage());
			}
		} finally {
			try {
				if(is != null)
					is.close();
			} catch (IOException ignore) {
			}
		}
		return properties;
	}

	public static void setDefaultConfig(Properties defaultConfig) {
		NativeLibraryLoader.defaultConfig = defaultConfig;
	}

	public static void setDefaultConfig(String fileName) {
		NativeLibraryLoader.defaultConfig = loadConfig(fileName);
	}

	public NativeLibraryLoader() {
	}

	public String getSSLCongig() {
		String config = getDefaultConfig().getProperty(OPENSSL_CONF, "openssl.cnf");
		return config;
	}
	
	public void loadLibraries() {
		loadLibraries(getDefaultConfig());
	}
	
	public void loadLibraries(String fileName) {
		Properties config = loadConfig(fileName);
		loadLibraries(config);
	}
	
	public void loadLibraries(Properties config) {
		String libraries = config.getProperty("library", DEFAULT_LIBRARIES);
		StringTokenizer st = new StringTokenizer(libraries, ",");
		
		while(st.hasMoreTokens()) {
			String librayName = st.nextToken().trim();

			loadLibrary(librayName, config);
		}
	}

	public void loadLibrary(String librayName, Properties config) {
		if(!dinamicLoadLibrary(librayName, config))
			System.loadLibrary(librayName);
	}

	private boolean dinamicLoadLibrary(String librayName, Properties config) {
		String osName = System.getProperty("os.name");
		StringBuilder name = new StringBuilder();
		String key = "path." + librayName;
		File dir = null;

		if("Windows".equals(osName)) {
			name.append(librayName).append(".dll");
		}
		else {
			name.append("lib").append(librayName).append(".so"); 
		}
		String osNameLibrary = name.toString(); 


		if(config.containsKey(key)) {
			String path = config.getProperty(key);
			dir = new File(path);

			if(dir.exists() && dir.isDirectory()) {
				File f = new File(dir.getAbsoluteFile(), osNameLibrary);
				
				if(f.exists()) {
					System.load(f.getAbsolutePath());
					return true;
				}
			}
		}
		else {
			dir = new File(System.getProperty("user.dir"));
			
			File f = new File(dir.getAbsoluteFile(), osNameLibrary);
			
			if(f.exists()) {
				System.load(f.getAbsolutePath());
				return true;
			}
		}
		return false;
	}
}
