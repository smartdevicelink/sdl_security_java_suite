package com.smartdevicelink.sdlsecurity;

import com.smartdevicelink.protocol.enums.SessionType;
import com.smartdevicelink.security.SdlSecurityBase;
import com.smartdevicelink.util.DebugTool;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by Bilal Alsharifi & Bretty on 2019-09-25.
 */
public class SdlSecurity extends SdlSecurityBase {
    private final String TAG = "SdlSecurity";

    private final int STATE_DISCONNECTED = 0;
    private final int STATE_INITIALIZED = 1;
    private int state;

    private NativeSSL nativeSSL = null;

    private List<SessionType> serviceList;

    @Override
    public void initialize() {
        this.state = STATE_DISCONNECTED;

        nativeSSL = new NativeSSL();
        DebugTool.logInfo(TAG, "Downloading certificate");
        CertificateManager.downloadCert(Constants.CERT_URL, getAppId(), new DownloadListener() {
            @Override
            public void onSuccess(byte[] certBuffer) {
                boolean success = nativeSSL.initialize(certBuffer, false);
                if (success) {
                    SdlSecurity.this.state = STATE_INITIALIZED;
                } else {
                    SdlSecurity.this.state = STATE_DISCONNECTED;
                    DebugTool.logError(TAG, "nativeSSL.initialize() failed");
                }
                handleInitResult(success);
            }

            @Override
            public void onFail(String error) {
                SdlSecurity.this.state = STATE_DISCONNECTED;
                handleInitResult(false);
                DebugTool.logError(TAG, "onFail: " + error);
            }
        });
    }

    @Override
    public Integer runHandshake(byte[] inputData, byte[] outputData) {
        if (this.state == STATE_DISCONNECTED){
            DebugTool.logError(TAG, "Security not initialized");
            return null;
        }
        return nativeSSL.runHandshake(inputData, outputData);
    }

    @Override
    public Integer encryptData(byte[] inputData, byte[] outputData) {
        if (this.state == STATE_DISCONNECTED){
            DebugTool.logError(TAG, "Security not initialized");
            return null;
        }
        return nativeSSL.encryptData(inputData, outputData);
    }

    @Override
    public Integer decryptData(byte[] inputData, byte[] outputData) {
        if (this.state == STATE_DISCONNECTED){
            DebugTool.logError(TAG, "Security not initialized");
            return null;
        }
        return nativeSSL.decryptData(inputData, outputData);

    }

    @Override
    public void shutDown() {
        if (this.state == STATE_DISCONNECTED) {
            return;
        }
        nativeSSL.shutdown();
        if (serviceList != null){
            serviceList.clear();
        }
        this.state = STATE_DISCONNECTED;
    }

    @Override
    public List<String> getMakeList() {
        return Constants.MAKE_LIST;
    }

    @Override
    public List<SessionType> getServiceList() {
        if (serviceList == null) {
            serviceList = new ArrayList<>();
        }
        return serviceList;
    }
}
