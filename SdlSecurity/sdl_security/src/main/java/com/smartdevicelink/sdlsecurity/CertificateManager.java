package com.smartdevicelink.sdlsecurity;

import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;


/**
 * Created by Bilal Alsharifi & Bretty on 2019-09-25.
 */
class CertificateManager {

    private static final String TAG = "SdlSecurity_CertManager";

    static void downloadCert(final String urlStr, final String appId, final DownloadListener listener) {
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                HttpURLConnection urlConnection = null;

                try {
                    JSONObject jsonRequest = new JSONObject();
                    jsonRequest.put("appId", appId);


                    URL url = new URL(urlStr);
                    urlConnection = (HttpURLConnection) url.openConnection();
                    urlConnection.setRequestMethod("GET");
                    urlConnection.setRequestProperty("content-type", "application/json");
                    urlConnection.setRequestProperty("accept", "application/json");
                    urlConnection.setUseCaches(false);
                    urlConnection.setInstanceFollowRedirects(false);
                    urlConnection.setDoOutput(true);
                    urlConnection.setDoInput(true);


                    DataOutputStream dataOutputStream = new DataOutputStream(urlConnection.getOutputStream());
                    dataOutputStream.writeBytes(jsonRequest.toString().replace("\\", ""));
                    dataOutputStream.flush();
                    dataOutputStream.close();


                    if (urlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                        Log.e(TAG, "Server error: " + urlConnection.getResponseCode());
                        listener.onFail("Failed to download the certificate");
                        return;
                    }


                    InputStream is = urlConnection.getInputStream();
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(is));
                    String line;
                    StringBuffer response = new StringBuffer();
                    while ((line = bufferedReader.readLine()) != null) {
                        response.append(line);
                        response.append('\r');
                    }
                    bufferedReader.close();


                    JSONObject jsonResponse = new JSONObject(response.toString());
                    JSONObject dataJsonObject = (JSONObject) jsonResponse.get("data");
                    String certStringBase64 = dataJsonObject.getString("certificate");
                    // If compiling library for use with Android SDK versions earlier than 26, use the android.utl.Base64 instead
                    // byte[] certBuffer = android.util.Base64.decode(certStringBase64.getBytes(), android.util.Base64.DEFAULT);
                    byte[] certBuffer = Base64.getDecoder().decode(certStringBase64);
                    listener.onSuccess(certBuffer);
                } catch (Exception e) {
                    e.printStackTrace();
                    Log.e(TAG, e.getMessage());
                    listener.onFail("Failed to download the certificate");
                } finally {
                    if (urlConnection != null) {
                        urlConnection.disconnect();
                    }
                }
            }
        });


        thread.start();
    }
}
