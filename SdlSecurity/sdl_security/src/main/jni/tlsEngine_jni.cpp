#include <jni.h>
#include "tlsEngine.cpp"

 // Initialize
 extern "C"
 JNIEXPORT jboolean JNICALL
 Java_com_smartdevicelink_sdlsecurity_NativeSSL_initialize(JNIEnv *env, jobject thiz, jbyteArray cert_buffer, jboolean is_client) {
        jsize len = env->GetArrayLength (cert_buffer);
        jbyte *buf = env->GetByteArrayElements(cert_buffer, 0);

        bool success = initialize(buf, len, is_client);

        env->ReleaseByteArrayElements(cert_buffer, buf, 0);

        return success;
 }


// Call shutdown
extern "C"
JNIEXPORT void JNICALL
Java_com_smartdevicelink_sdlsecurity_NativeSSL_shutdown(JNIEnv *env, jobject thiz) {
        shutdown();
}

// Call runHandshake
extern "C"
JNIEXPORT jint JNICALL
Java_com_smartdevicelink_sdlsecurity_NativeSSL_runHandshake(JNIEnv *env, jobject thiz, jbyteArray input, jbyteArray output) {
        jsize input_len = env->GetArrayLength (input);
        jbyte *input_buf = env->GetByteArrayElements(input, 0);
        jsize output_len = env->GetArrayLength (output);
        jbyte *output_buf = env->GetByteArrayElements(output, 0);

        int result = run_handshake(input_buf, input_len, output_buf, output_len);

        env->ReleaseByteArrayElements(input, input_buf, 0);
        env->ReleaseByteArrayElements(output, output_buf, 0);

        return result;
}

// Call encryptData
extern "C"
JNIEXPORT jint JNICALL
Java_com_smartdevicelink_sdlsecurity_NativeSSL_encryptData(JNIEnv *env, jobject thiz, jbyteArray input, jbyteArray output) {
        jsize input_len = env->GetArrayLength (input);
        jbyte *input_buf = env->GetByteArrayElements(input, 0);
        jsize output_len = env->GetArrayLength (output);
        jbyte *output_buf = env->GetByteArrayElements(output, 0);

        int result = encrypt_data(input_buf, input_len, output_buf, output_len);

        env->ReleaseByteArrayElements(input, input_buf, 0);
        env->ReleaseByteArrayElements(output, output_buf, 0);

        return result;
}

// Call decryptData
extern "C"
JNIEXPORT jint JNICALL
Java_com_smartdevicelink_sdlsecurity_NativeSSL_decryptData(JNIEnv *env, jobject thiz, jbyteArray input, jbyteArray output) {
        jsize input_len = env->GetArrayLength (input);
        jbyte *input_buf = env->GetByteArrayElements(input, 0);
        jsize output_len = env->GetArrayLength (output);
        jbyte *output_buf = env->GetByteArrayElements(output, 0);

        int result = decrypt_data(input_buf, input_len, output_buf, output_len);

        env->ReleaseByteArrayElements(input, input_buf, 0);
        env->ReleaseByteArrayElements(output, output_buf, 0);

        return result;
}