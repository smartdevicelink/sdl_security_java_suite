#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <memory.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/pkcs12.h>
#include <jni.h>

#define LOG_TAG "SdlSecurity_Native"
#ifdef ANDROID
    #include <android/log.h>
    #define printf(...) ((void)__android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#else
    #define printf(...) printf("\n%s - %s", LOG_TAG, __VA_ARGS__); fflush(stdout);
#endif

// TLS engine error codes
const int TLS_ERROR_NONE = 0;
const int TLS_NOT_INITIALIZED = -1;
const int TLS_ERROR_SSL = -2;
const int TLS_ERROR_WANT_READ = -3;
const int TLS_ERROR_WANT_WRITE = -4;
const int TLS_WRITE_FAILED = -5;
const int TLS_GENERIC_ERROR = -6;
const int TLS_SESSION_NOT_FOUND = -7;


// TLS engine states
const int STATE_DISCONNECTED = 0;
const int STATE_INITIALIZED = 1;


int BUFFER_SIZE_MAX = 0;
const char *CERT_PASS = "";
const char *CERT_ISSUER = "";


SSL* ssl = NULL;
SSL_CTX *ctx;
BIO* in_bio;
BIO* out_bio;
int state;


// Created by Bilal Alsharifi
// Nice article to read: http://www.roxlu.com/2014/042/using-openssl-with-memory-bios

void shutdown() {
    printf("Shutting down \n");
    if (state != STATE_INITIALIZED)
    {
        return;
    }
    
    if (ssl != NULL)
    {
        int retry_count = 0;
        for (int i = 0; i < 4; i++)
        {
            retry_count = SSL_shutdown(ssl);
            if (retry_count > 0)
            {
                break;
            }
        }
        SSL_free(ssl);
    }
    
    if (ctx != NULL)
    {
        SSL_CTX_free(ctx);
    }
    
    CONF_modules_unload(1);
    ERR_remove_state(0);
    ERR_free_strings();

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    state = STATE_DISCONNECTED;
}

void clean_up_initialization(X509* cert, RSA* rsa, PKCS12* p12, BIO *pbio, EVP_PKEY* pkey) {
    if (cert != NULL)
    {
        X509_free(cert);
    }
    if (rsa != NULL)
    {
        RSA_free(rsa);
    }
    if (p12 != NULL)
    {
        PKCS12_free(p12);
    }
    if (pbio != NULL)
    {
        BIO_free(pbio);
    }
    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }
}

int get_date_component(const unsigned char *str, const int start, const int size) {
    char date_component[size + 1];
    memcpy(date_component, &str[start], size);
    date_component[size] = '\0';
    int date_component_num = (int) strtol(date_component, (char **)NULL, 10);
    return date_component_num;
}

bool cert_date_valid(X509 *certificateX509) {
    if (certificateX509 != NULL) {
        ASN1_TIME *time2 = X509_get_notAfter(certificateX509);
        if (time2 != NULL) {
            ASN1_GENERALIZEDTIME *time2_generalized = ASN1_TIME_to_generalizedtime(time2, NULL);
            if (time2_generalized != NULL) {
                const unsigned char *time2_data = ASN1_STRING_get0_data(time2_generalized);

                // ASN1 generalized times look like this: "20131114230046Z"
                //                                format:  YYYYMMDDHHMMSS
                //                               indices:  01234567890123
                //                                                   1111
                // There are other formats (e.g. specifying partial seconds or
                // time zones) but this is good enough for our purposes since
                // we only use the date and not the time.
                //
                // (Source: http://www.obj-sys.com/asn1tutorial/node14.html)

                int year2 = get_date_component(time2_data, 0, 4);
                int month2 = get_date_component(time2_data, 4, 2);
                int day2 = get_date_component(time2_data, 6, 2);

                time_t t = time(NULL);
                struct tm tm = *localtime(&t);
                int year = tm.tm_year + 1900;
                int month = tm.tm_mon + 1;
                int day = tm.tm_mday;

                if(year2 > year){
                    return true;
                } else if(year2 == year){
                    if(month2 > month){
                        return true;
                    } else if(month2 == month){
                        if(day2 > day){
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

bool initialize(JNIEnv* env, void* cert_buffer, int cert_len, bool is_client) {
    printf("initializing \n");

    //Get constants from java class
    jclass javaConstantsClass = env->FindClass("com/smartdevicelink/sdlsecurity/Constants");

    jfieldID bufferSizeFieldId = env->GetStaticFieldID(javaConstantsClass, "BUFFER_SIZE_MAX", "I");
    jfieldID certPassFieldId = env->GetStaticFieldID(javaConstantsClass, "CERT_PASS", "Ljava/lang/String;");
    jfieldID certIssuerFieldId = env->GetStaticFieldID(javaConstantsClass, "CERT_ISSUER", "Ljava/lang/String;");

    if (bufferSizeFieldId == NULL || certPassFieldId == NULL || certIssuerFieldId == NULL) {
        printf("fieldId == null");
        return false;
    } else {
        jint javaBufferSize = env->GetStaticIntField(javaConstantsClass, bufferSizeFieldId);
        jstring javaCertPass = (jstring) env->GetStaticObjectField(javaConstantsClass, certPassFieldId);
        jstring javaCertIssuer = (jstring) env->GetStaticObjectField(javaConstantsClass, certIssuerFieldId);

        BUFFER_SIZE_MAX = (int) javaBufferSize;
        CERT_PASS = env->GetStringUTFChars(javaCertPass, JNI_FALSE);
        CERT_ISSUER = env->GetStringUTFChars(javaCertIssuer, JNI_FALSE);
    }

    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *certX509 = NULL;
    RSA *rsa = NULL;  
    BIO *pbio = NULL;
    void *p12_buffer;
    bool success = false;  

    state = STATE_DISCONNECTED;

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    if (is_client)
    {
      ctx = SSL_CTX_new(DTLSv1_client_method());
    } else {
      ctx = SSL_CTX_new(DTLSv1_server_method());
    }

    if(!ctx) {
      printf("Error: cannot create SSL_CTX.\n");
      ERR_print_errors_fp(stderr);
      return false;
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE;
    SSL_CTX_set_options(ctx, options);

    pbio = BIO_new_mem_buf(cert_buffer, cert_len);
    p12 = d2i_PKCS12_bio(pbio, NULL);

    if (!p12)
    {
        printf("Error reading PKCS#12 file\n");
        clean_up_initialization(certX509, rsa, p12, pbio, pkey);
        return false;
    }

    PKCS12_parse(p12, CERT_PASS, &pkey, &certX509, NULL);
    if (certX509 == NULL || pkey == NULL)
    {
        printf("Error parsing PKCS#12 file\n");
        clean_up_initialization(certX509, rsa, p12, pbio, pkey);
        return false;
    }

    if (!cert_date_valid(certX509)) {
        printf("Error in validating the certificate. Certificate has expired!\n");
        clean_up_initialization(certX509, rsa, p12, pbio, pkey);
        return false;
    }

    char* cert_issuer = X509_NAME_oneline(X509_get_issuer_name(certX509), NULL, 0);
    if (strcmp(cert_issuer, CERT_ISSUER) != 0) {
        printf("Error in verifying issuer name. Expected %s but found %s\n", CERT_ISSUER, cert_issuer);
        // we are only printing error message in that case to make testing easier
        // it should stop initialization and return false in production libraries
    }
    
    rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL)
    {
        printf("Error in EVP_PKEY_get1_RSA\n");
        clean_up_initialization(certX509, rsa, p12, pbio, pkey);
        return false;
    }
    
    // Set up our SSL Context with the certificate and key
    success = SSL_CTX_use_certificate(ctx, certX509);
    if (!success)
    {
        printf("Error in SSL_CTX_use_certificate\n");
        clean_up_initialization(certX509, rsa, p12, pbio, pkey);
        return false;
    }
    
    success = SSL_CTX_use_RSAPrivateKey(ctx, rsa);
    if (!success)
    {
        printf("Error in SSL_CTX_use_RSAPrivateKey\n");
        clean_up_initialization(certX509, rsa, p12, pbio, pkey);
        return false;
    }
    
    success = SSL_CTX_check_private_key(ctx);
    if (!success)
    {
         printf("Error in SSL_CTX_check_private_key\n");
        clean_up_initialization(certX509, rsa, p12, pbio, pkey);
        return false;
    }
    
    success = SSL_CTX_set_cipher_list(ctx, "ALL");
    if (!success)
    {
        printf("Error in SSL_CTX_set_cipher_list\n");
        clean_up_initialization(certX509, rsa, p12, pbio, pkey);
        return false;
    }
    
    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        printf("Error in SSL_new\n");
        clean_up_initialization(certX509, rsa, p12, pbio, pkey);
        return false;
    }
    
    in_bio = BIO_new(BIO_s_mem());
    if(in_bio == NULL)
    {
      printf("Error: cannot allocate read bio.\n");
      return false;
    }
    BIO_set_mem_eof_return(in_bio, -1);

    out_bio = BIO_new(BIO_s_mem());
    if(out_bio == NULL) {
      printf("Error: cannot allocate write bio.\n");
      return false;
    }
    BIO_set_mem_eof_return(out_bio, -1);
    
    SSL_set_bio(ssl, in_bio, out_bio);

    if(is_client)
    {
        SSL_set_connect_state(ssl);
    }
    else
    {
        SSL_set_accept_state(ssl);
    }

    clean_up_initialization(certX509, rsa, p12, pbio, pkey);

    state = STATE_INITIALIZED;
    
    return true;
}

int error_code_from_ssl(int value, int len, bool is_write)
{
  int error = SSL_get_error(ssl, value);
  switch(error)
  {
    case SSL_ERROR_NONE:
      if(len != value && is_write)
        return TLS_WRITE_FAILED;
      else
        return TLS_ERROR_NONE;
    case SSL_ERROR_SSL:
      return TLS_ERROR_SSL;
    case SSL_ERROR_WANT_READ:
      return TLS_ERROR_WANT_READ;
    case SSL_ERROR_WANT_WRITE:
      return TLS_ERROR_WANT_WRITE;
    default:
      return TLS_GENERIC_ERROR;
  }
}

int ssl_read_data(void *buf, int len) {
    memset(buf, 0, BUFFER_SIZE_MAX);
    int bytes = SSL_read(ssl, buf, len);
    
    int errorCode = error_code_from_ssl(bytes, len, false);
    if (errorCode != SSL_ERROR_NONE)
    {
        return errorCode;
    }
    
    return bytes;
}

int bio_read_data(void *buf, int len) {
    memset(buf, 0, BUFFER_SIZE_MAX);;
    int bytes = BIO_read(out_bio, buf, len);

    int errorCode = error_code_from_ssl(bytes, len, false);
    if (errorCode != SSL_ERROR_NONE)
    {
        printf("error %d\n", errorCode);
        return errorCode;
    }

    return bytes;
}

int bio_write_data(void *buf, int len) {
    int bytes = BIO_write(in_bio, buf, len);

    int errorCode = error_code_from_ssl(bytes, len, true);
    if (errorCode != SSL_ERROR_NONE)
    {
        printf("error %d\n", errorCode);
        return errorCode;
    }

    return bytes;
}

int ssl_write_data(void *buf, int len) {
    int bytes = SSL_write(ssl, buf, len);

    int errorCode = error_code_from_ssl(bytes, len, true);
    if (errorCode != SSL_ERROR_NONE)
    {
        return errorCode;
    }

    return bytes;
}

bool tls_handshake()
{
    if (ssl == NULL) {
        printf("ssl is null \n");
        return false;
    }
    
    if (!SSL_is_init_finished(ssl))
    {
        SSL_do_handshake(ssl);
    }
    
    return SSL_is_init_finished(ssl);
}

int run_handshake(void *buf1, int len1, void *buf2, int len2) {
    printf("run_handshake \n");
    if (bio_write_data(buf1, len1) < 0)
    {
      return -1;
    }
    
    tls_handshake();

    return bio_read_data(buf2, len2);
}

int encrypt_data(void *buf1, int len1, void *buf2, int len2) {
    printf("encrypting data \n");
    if (!tls_handshake()) {
        printf ("TLS is not initialized \n");
        return -1;
    }
    
    if (ssl_write_data(buf1, len1) < 0)
    {
        return -1;
    }
    
    int bytes = bio_read_data(buf2, len2);
    if (bytes < 0)
    {
        return -1;
    }
    
    return bytes;
}

int decrypt_data(void *buf1, int len1, void *buf2, int len2) {
    printf("decrypting data \n");
    if (!tls_handshake())
    {
        printf ("TLS is not initialized \n");
        return -1;
    }
    
    if (bio_write_data(buf1, len1) < 0)
    {
        return -1;
    }
    
    int bytes = ssl_read_data(buf2, len2);
    if (bytes < 0)
    {
        return -1;
    }
    
    return bytes;
}