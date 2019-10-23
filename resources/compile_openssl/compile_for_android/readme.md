# Build OpenSSL on MacOS for Android Architecture
### Preparing your computer
- Install NDK, CMake, and LLDB via the SDK manager in Android studio under the SDK Tools tab. 
- Take note of the SDK Location path, you need to open this and get the path of the NDK for the next step 
- Set appropriate environment paths for your machine in `.bash_profile`:
```
export ANDROID_SDK=~/Library/Android/sdk
export ANDROID_NDK=~/Library/Android/sdk/ndk/20.0.5594570
export PATH=$PATH:~/Library/Android/sdk/ndk/20.0.5594570/
```
- exit and re-enter the terminal for the new changes to take effect
- install WGET with brew: `brew install wget`

### Build OpenSSL
- create a folder and put `buildopenssl.sh` in it.
- `cd ` into the folder and run `sh buildopenssl.sh` Note: this step will take ~10-15 min
- It will create a folder called output. 
- in your jni folder in your app, create a directory called `precompiled`. In the output->openssl_111_android->lib folder, copy the compiled architecture folders into the `precompiled` folder in your project. 
- In the output->openssl_111_android->inc folder, choose an architecture (it doesn't matter which) and open the folder. copy the `openssl` folder containing the headers to your jni folder. 
- in your `Application.mk` file, you should have:

```c++
APP_STL := c++_static
APP_ABI := arm64-v8a x86 x86_64
APP_PLATFORM := android-21
```
- in your `Android.mk` file,  you should have something like this:

```c++
LOCAL_PATH := $(call my-dir)

# Prebuilt libssl

include $(CLEAR_VARS)
LOCAL_MODULE := ssl
LOCAL_SRC_FILES := precompiled/$(TARGET_ARCH_ABI)/libssl.a
include $(PREBUILT_STATIC_LIBRARY)

# Prebuilt libcrypto

include $(CLEAR_VARS)
LOCAL_MODULE := crypto
LOCAL_SRC_FILES := precompiled/$(TARGET_ARCH_ABI)/libcrypto.a
include $(PREBUILT_STATIC_LIBRARY)


include $(CLEAR_VARS)
c_includes := $(LOCAL_PATH)
cf_includes := includes
cf_includes := $(addprefix -Ijni/,$(cf_includes))
export_c_includes := $(c_includes)
LOCAL_MODULE := security
LOCAL_SRC_FILES := Your_apps_cpp_file_to_compile.cpp
LOCAL_LDLIBS := -llog
LOCAL_SHARED_LIBRARIES= ssl crypto
LOCAL_CFLAGS += $(cf_includes)
LOCAL_EXPORT_C_INCLUDES := $(export_c_includes)
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
include $(BUILD_SHARED_LIBRARY)
```

- `cd` to the jni folder and call `ndk-build`. It will compile these files into `.so` files located in the `libs` and `obj` folders. There may be deprecation warnings, but that is ok. Your app will now compile