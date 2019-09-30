package com.smartdevicelink.sdlsecurity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

/**
 * Created by Bilal Alsharifi & Bretty on 2019-09-25.
 */
class CertificateManager {

    static byte[] toByteArray(InputStream in) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int len;
        // read bytes from the input stream and store them in buffer
        while ((len = in.read(buffer)) != -1) {
            // write bytes from the buffer into output stream
            os.write(buffer, 0, len);
        }
        return os.toByteArray();
    }

    static void downloadCert(final String urlStr, final DownloadListener listener) {
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    URL url = new URL(urlStr);
                    URLConnection connection = url.openConnection();
                    byte [] certBuffer = toByteArray(connection.getInputStream());
                    listener.onSuccess(certBuffer);
                } catch (IOException e) {
                    listener.onFail("Failed to download the certificate");
                }
            }
        });
        thread.start();
    }
}
