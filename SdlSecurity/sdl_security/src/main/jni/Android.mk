
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
LOCAL_SRC_FILES := tlsEngine_jni.cpp
LOCAL_LDLIBS := -llog
LOCAL_SHARED_LIBRARIES= ssl crypto
LOCAL_CFLAGS += $(cf_includes)
LOCAL_EXPORT_C_INCLUDES := $(export_c_includes)
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
include $(BUILD_SHARED_LIBRARY)