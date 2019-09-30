package com.smartdevicelink.sdlsecurity;

import java.io.File;

/**
 * Created by Bilal Alsharifi & Bretty on 2019-09-25.
 */
class NativeSSL {

	// Load C Library
	static {
		try {
			// For Android
			System.loadLibrary("security");
		} catch(java.lang.UnsatisfiedLinkError e){
			// For JavaSE
			File lib = new File("sdl_security_se/src/main/libs/" + System.mapLibraryName("security"));
			System.load(lib.getAbsolutePath());
		}
	}

	NativeSSL(){}
	
	native boolean initialize(byte[] certBuffer, boolean isClient);
	native int runHandshake(byte[] input, byte[] output);
	native int encryptData(byte[] input, byte[] output);
	native int decryptData(byte[] input, byte[] output);
	native void shutdown();
}
