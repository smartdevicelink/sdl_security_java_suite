package com.smartdevicelink.sdlsecurity;

/**
 * Created by Bilal Alsharifi & Bretty on 2019-09-25.
 */
class NativeSSL {

	// Load C Library
	static {
		System.loadLibrary("security");
	}

	NativeSSL(){
		//initWithCertificate(certificate);
	}

	// initialize our TLS connection with a certificate we downloaded
	// This will initialize our handshake
	native boolean initialize(byte[] certBuffer, boolean isClient);
	native int runHandshake(byte[] input, byte[] output);
	native int encryptData(byte[] input, byte[] output);
	native int decryptData(byte[] input , byte[] output);
	// dispose of this session and reset variables
	native void shutdown();
}
