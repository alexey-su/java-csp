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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BundleNativeCode {
	private static final Logger LOGGER = LoggerFactory.getLogger(BundleNativeCode.class);

	private static String[][] processorAliases = {
		{"Ignite", "psc1k"},
		{"x86", "pentium", "i386", "i486", "i586", "i686"},
		{"x86-64", "amd64", "em64t", "x86_64"}
	};

	private static String[][] osNameAliases = {
		{"Epoc32", "SymbianOS"},
		{"HPUX", "hp-ux"},
		{"MacOS", "Mac OS"},
		{"MacOSX", "Mac OS X"},
		{"OS2", "OS/2"},
		{"QNX", "procnto"},
		{"Windows95", "Win95", "Windows 95", "Win32"},
		{"Windows98", "Win98", "Windows 98", "Win32"},
		{"WindowsNT", "WinNT", "Windows NT", "Win32"},
		{"WindowsCE", "WinCE", "Windows CE"},
		{"Windows2000", "Win2000", "Windows 2000", "Win32"},
		{"Windows2003", "Win2003", "Windows 2003", "Win32"},
		{"WindowsXP", "WinXP", "Windows XP", "Win32"},
		{"WindowsVista", "WinVista", "Windows Vista", "Win32"},
		{"Windows7", "Win7", "Windows 7", "Win32"},
		{"WindowsServer2008", "Windows Server 2008"},
		{"Windows8", "Win8", "Windows 8", "Win32"}
	};

	private String bundleNativeCode;
	private String language;
	private String osArch;
	private String osName;
	private String osVersion;

	public BundleNativeCode(String bundleNativeCode, String language) {
		this.bundleNativeCode = bundleNativeCode;
		this.language = language;
		this.osArch = System.getProperty("os.arch");
		this.osName = System.getProperty("os.name");
		this.osVersion = System.getProperty("os.version");
		
	}

	public String getOsArch() {
		return osArch;
	}

	public void setOsArch(String osArch) {
		this.osArch = osArch;
	}

	public String getOsName() {
		return osName;
	}

	public void setOsName(String osName) {
		this.osName = osName;
	}

	public String getOsVersion() {
		return osVersion;
	}

	public void setOsVersion(String osVersion) {
		this.osVersion = osVersion;
	}

	private Set<String> getProcessorNames(String osarch) {
		Set<String> names = new HashSet<String>();
		
		for(String[] line : processorAliases) {
			for(String name : line) {
				if(osarch.equals(name))
					names.add(line[0]);
			}
		}
		
		if(names.isEmpty())
			names.add(osarch);

		return names;
	}

	private Set<String> getOsNames(String osname) {
		Set<String> names = new HashSet<String>();
		
		for(String[] line : osNameAliases) {
			for(String name : line) {
				if(osname.equals(name))
					names.add(line[0]);
			}
		}
		
		if(names.isEmpty())
			names.add(osname);

		return names;
	}


	public List<String> match() {
		ArrayList<String> list = new ArrayList<String>();
		StringTokenizer st = new StringTokenizer(bundleNativeCode, ",");
		
		if(LOGGER.isDebugEnabled()) {
			LOGGER.debug("os.name: {}, name:{}", this.osName, getOsNames(this.osName));
			LOGGER.debug("os.arch: {}, processor:{}", this.osArch, getProcessorNames(this.osArch));
			LOGGER.debug("os.version: {}", this.osVersion);
		}

		while(st.hasMoreTokens()) {
			String nativecode = st.nextToken();
			List<String> path = match(nativecode.trim());
			
			if(path != null)
				list.addAll(path);
		}
		return list;
	}

	private List<String> match(String nativecode) {
		List<String> path = new ArrayList<String>();
		Set<String> osnames = new HashSet<String>();
		Set<String> osversions = new HashSet<String>();
		Set<String> processors = new HashSet<String>();
		Set<String> langueges = new HashSet<String>();
		StringTokenizer st = new StringTokenizer(nativecode, ";");
		boolean haveParameter = false;

		while(st.hasMoreTokens()) {
			String value = st.nextToken();
			int paramSeparator = value.indexOf('=');
			
			if(!haveParameter && paramSeparator > 0)
				haveParameter = true;
			
			if(haveParameter) {
				if(paramSeparator > 0 && paramSeparator != value.length() - 1) {
					String key = value.substring(0, paramSeparator).trim();
					String val = value.substring(paramSeparator + 1).trim();
					
					if(!key.isEmpty() && !val.isEmpty()) {
						if(key.equals("osname")) {
							osnames.add(val);
						} else if(key.equals("osversion")) {
							osversions.add(val);
						} else if(key.equals("processor")) {
							processors.add(val);
						} else if(key.equals("language")) {
							langueges.add(val);
						}
					}
				}
			}
			else if(paramSeparator < 0) {
				path.add(value.trim());
			}
		}

		boolean filter = true;

		if(osName != null && !osName.isEmpty() && !osnames.isEmpty()) {
			Set<String> real = getOsNames(osName);
			Set<String> names = new HashSet<String>();
			boolean find = false;

			for(String val : osnames) {
				names.addAll(getOsNames(val));
			}
			for(String name : names) {
				find |= real.contains(name);
			}
			filter = find;
		}
		if(filter && osVersion != null && !osVersion.isEmpty() && !osversions.isEmpty()) {
			filter = osversions.isEmpty() || osversions.contains(osVersion);
		}
		if(filter && osArch != null && !osArch.isEmpty() && !processors.isEmpty()) {
			Set<String> real = getProcessorNames(osArch);
			Set<String> names = new HashSet<String>();
			boolean find = false;

			for(String val : processors) {
				names.addAll(getProcessorNames(val));
			}
			for(String name : names) {
				find |= real.contains(name);
			}
			filter = find;
		}
		if(filter && language != null && !language.isEmpty() && !langueges.isEmpty()) {
			filter = langueges.contains(language);
		}
		if(!filter)
			path.clear();


		if(LOGGER.isDebugEnabled()) {
			LOGGER.debug("match {} from native library {}", filter, nativecode);
		}
		return path;
	}
}
