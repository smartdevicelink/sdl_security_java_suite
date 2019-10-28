package com.smartdevicelink.sdlsecurity;

import java.io.IOException;

import cz.adamh.utils.NativeUtils;

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
			try {
				NativeUtils.loadLibraryFromJar("/libs/libsecurity.dylib");
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
	}

	NativeSSL(){}
	
	native boolean initialize(byte[] certBuffer, boolean isClient);
	native int runHandshake(byte[] input, byte[] output);
	native int encryptData(byte[] input, byte[] output);
	native int decryptData(byte[] input, byte[] output);
	native void shutdown();
}
