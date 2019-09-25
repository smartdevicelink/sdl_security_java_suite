package com.smartdevicelink.sdlsecurity;

import android.util.Log;

import com.smartdevicelink.security.SdlSecurityBase;

/**
 * Created by Bilal Alsharifi & Bretty on 2019-09-25.
 */
public class SdlSecurity extends SdlSecurityBase {
    private final String TAG = "SdlSecurity";

    private final String CERT_URL = "https://sdl-temp.s3.amazonaws.com/server.pfx";
    private final int STATE_DISCONNECTED = 0;
    private final int STATE_INITIALIZED = 1;
    private int state;

    private NativeSSL nativeSSL = null;

    @Override
    public void initialize() {
        this.state = STATE_DISCONNECTED;

        nativeSSL = new NativeSSL();
        Log.i(TAG, "Downloading certificate");
        Tools.downloadCert(CERT_URL, new DownloadListener() {
            @Override
            public void onSuccess(byte[] certBuffer) {
                boolean success = nativeSSL.initialize(certBuffer, false);
                if (success) {
                    SdlSecurity.this.state = STATE_INITIALIZED;
                } else {
                    SdlSecurity.this.state = STATE_DISCONNECTED;
                    Log.e(TAG, "nativeSSL.initialize() failed");
                }
            }

            @Override
            public void onFail(String error) {
                SdlSecurity.this.state = STATE_DISCONNECTED;
                Log.e(TAG, "onFail: " + error);
            }
        });
    }

    @Override
    public Integer runHandshake(byte[] inputData, byte[] outputData) {
        if (this.state == STATE_DISCONNECTED){
            Log.e(TAG, "Security not initialized");
            return null;
        }
        return nativeSSL.runHandshake(inputData, outputData);
    }

    @Override
    public Integer encryptData(byte[] inputData, byte[] outputData) {
        if (this.state == STATE_DISCONNECTED){
            Log.e(TAG, "Security not initialized");
            return null;
        }
        return nativeSSL.encryptData(inputData, outputData);
    }

    @Override
    public Integer decryptData(byte[] inputData, byte[] outputData) {
        if (this.state == STATE_DISCONNECTED){
            Log.e(TAG, "Security not initialized");
            return null;
        }
        return nativeSSL.decryptData(inputData, outputData);

    }

    @Override
    public void shutDown() {
        if (this.state == STATE_DISCONNECTED){
            return;
        }
        nativeSSL.shutdown();
        this.state = STATE_DISCONNECTED;
    }
}
