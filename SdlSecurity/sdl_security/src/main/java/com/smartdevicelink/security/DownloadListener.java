package com.smartdevicelink.security;

/**
 * Created by Bilal Alsharifi & Bretty on 2019-09-25.
 */
interface DownloadListener {
    void onSuccess(byte[] certBuffer);
    void onFail(String error);
}
