INC=./
LIB=./precompiled/
JAVA_HOME:=`/usr/libexec/java_home`


all:
	g++ ../../../../sdl_security/src/main/jni/tlsEngine_jni.cpp -shared -o ../libs/libsecurity.dylib -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/darwin -I$(INC) -L$(LIB) -lssl -lcrypto -ldl -fpermissive