package com.smartdevicelink.sdlsecurity;

import java.util.Collections;
import java.util.List;

/**
 * Created by Bilal Alsharifi && Bretty on 2019-09-25.
 */
class Constants {
    final static String CERT_URL = "http://www.mocky.io/v2/5d9b565132000072002ae80f";
    final static List<String> MAKE_LIST = Collections.singletonList("SDL");
    final static int BUFFER_SIZE_MAX = 4096;
    final static String CERT_PASS = "password"; // This needs to be changed to the actual certificate password
    final static String CERT_ISSUER = "SDL"; // This needs to be changed to the actual certificate issuer

    static {
        System.loadLibrary("security");
    }
}
