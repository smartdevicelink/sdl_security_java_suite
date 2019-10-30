# SDL Security Java Suite

## Compile OpenSSL
### Android (Mobile Apps)
To compile OpenSSL for Android, please follow these [instructions](/resources/compile_openssl/compile_for_android/readme.md).

### MacOS (Cloud Apps)
To compile OpenSSL for macOS, please follow these [instructions](/resources/compile_openssl/compile_for_mac/).

## Compile TLSEngine
The native code in `tlsEngine` should be compiled for every architecture it is going to run on. The code is already compiled for most common architectures. However, if you want to run the library on other architectures or if you want to change the native code, you will need to recompile the native code again:

### Android (Mobile Apps)
Open the terminal and go to this path `sdl_security_java_suite/SdlSecurity/sdl_security/src/main/jni`, then run:
```
$ ndk-build
```
note:  you may need to modify the `Application.mk` file to specify any additional architectures to compile against

### Linux / macOS (Cloud Apps)
Open the terminal and go to this path `sdl_security_java_suite/SdlSecurity/sdl_security_se/src/main/jni`, then run:
```
$ make
```