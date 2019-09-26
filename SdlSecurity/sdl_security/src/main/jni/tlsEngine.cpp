#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/pkcs12.h>

#ifdef ANDROID
    #include <android/log.h>
    #define printf(...) ((void)__android_log_print(ANDROID_LOG_INFO, "SdlSecurity_Native", __VA_ARGS__))
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


const int BUFFER_SIZE_MAX = 4096;
const char *CERT_PASS = "password"; // This needs to be changed to your own password


SSL* ssl = NULL;
SSL_CTX *ctx;
BIO* in_bio;
BIO* out_bio;
int state;


// Created by Bilal Alsharifi
// Nice article to read: http://www.roxlu.com/2014/042/using-openssl-with-memory-bios

void shutdown() {
    printf("Shutting down");
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

    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
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

bool initialize(void* cert_buffer, int cert_len, bool is_client) {
    printf("initializing");
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
    
    // To do: should check certificate date and issuer
    
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
    printf("run_handshake");
    if (bio_write_data(buf1, len1) < 0)
    {
      return -1;
    }
    
    tls_handshake();

    return bio_read_data(buf2, len2);
}

int encrypt_data(void *buf1, int len1, void *buf2, int len2) {
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
    if (!tls_handshake())
    {
        printf ("TLS is not initialzed \n");
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