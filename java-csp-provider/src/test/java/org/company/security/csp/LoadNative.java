package org.company.security.csp;

import java.security.Security;

public class LoadNative {
	private static final String CSP_PROVIDER = "CSPProvider";
	
	public static void loadProvider() {
		CSPNative.init("target/classes/native", 
				"lib/java-csp-platform-amd64-linux.so; osname=Linux; processor=x86-64," +
				"lib/java-csp-platform-x86-linux.so; osname=Linux; processor=x86," +
				"lib/java-csp-platform-amd64-windows.dll; osname=Win32; processor=x86-64," +
				"lib/java-csp-platform-x86-windows.dll; osname=Win32; processor=x86");
		
		if(Security.getProvider(CSP_PROVIDER) == null)
			Security.addProvider(new CSPProvider());
	}
}
