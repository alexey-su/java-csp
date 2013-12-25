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

import static org.junit.Assert.*;

import java.util.List;

import org.company.security.csp.BundleNativeCode;
import org.junit.Test;

public class TestBundleNativeCode {
	private static String BUNDLE_NATIVE = 
			"lib/java-csp-platform-amd64-linux.so; osname=Linux; processor=x86-64," +
			"lib/java-csp-platform-x86-linux.so; osname=Linux; processor=x86," +
			"lib/java-csp-platform-amd64-windows.dll; osname=Win32; processor=x86-64," +
			"lib/java-csp-platform-x86-windows.dll; osname=Win32; processor=x86";
 
	@Test
	public void test_01_x86_windows() {
		BundleNativeCode matcher = new BundleNativeCode(BUNDLE_NATIVE, null);
		List<String> list;

		matcher.setOsArch("x86");
		matcher.setOsName("Windows 7");
		matcher.setOsVersion(null);
		list = matcher.match();

		assertEquals("Надо найти одну библиотеку", 1, list.size());
		assertEquals("Нашли другую библиотеку", "lib/java-csp-platform-x86-windows.dll", list.get(0));
	}

	@Test
	public void test_02_amd64_windows() {
		BundleNativeCode matcher = new BundleNativeCode(BUNDLE_NATIVE, null);
		List<String> list;

		matcher.setOsArch("amd64");
		matcher.setOsName("Windows 7");
		matcher.setOsVersion(null);
		list = matcher.match();

		assertEquals("Надо найти одну библиотеку", 1, list.size());
		assertEquals("Нашли другую библиотеку", "lib/java-csp-platform-amd64-windows.dll", list.get(0));
	}

	@Test
	public void test_03_x86_linux() {
		BundleNativeCode matcher = new BundleNativeCode(BUNDLE_NATIVE, null);
		List<String> list;

		matcher.setOsArch("x86");
		matcher.setOsName("Linux");
		matcher.setOsVersion(null);
		list = matcher.match();

		assertEquals("Надо найти одну библиотеку", 1, list.size());
		assertEquals("Нашли другую библиотеку", "lib/java-csp-platform-x86-linux.so", list.get(0));
	}
	@Test
	public void test_04_amd64_linux() {
		BundleNativeCode matcher = new BundleNativeCode(BUNDLE_NATIVE, null);
		List<String> list;

		matcher.setOsArch("amd64");
		matcher.setOsName("Linux");
		matcher.setOsVersion(null);
		list = matcher.match();

		assertEquals("Надо найти одну библиотеку", 1, list.size());
		assertEquals("Нашли другую библиотеку", "lib/java-csp-platform-amd64-linux.so", list.get(0));
	}
}
