package com.smartdevicelink.security;

public class NativeSSL {

	// Load C Library
	static {
		System.loadLibrary("security");
	}

	// initialize our TLS connection with a certificate we downloaded
	// This will initialize our handshake
	public native boolean initialize(byte[] certBuffer, boolean isClient);
	public native int runHandshake(byte[] input, byte[] output);
	public native int encryptData(byte[] input, byte[] output);
	public native int decryptData(byte[] input , byte[] output);
	// dispose of this session and reset variables
	public native void shutdown();

	public NativeSSL(){
		//initWithCertificate(certificate);
	}


}
