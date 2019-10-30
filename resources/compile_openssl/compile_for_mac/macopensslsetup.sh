#!/bin/bash

NEW_OPENSSL_VERSION="1.1.1d"

# Download
echo "Downloading!"
curl -O https://www.openssl.org/source/openssl-$NEW_OPENSSL_VERSION.tar.gz
echo "Download Completed!"
tar -xvzf openssl-$NEW_OPENSSL_VERSION.tar.gz
mv openssl-$NEW_OPENSSL_VERSION openssl_x86_64
# Build
cd openssl_x86_64
echo "Configure"
./Configure darwin64-x86_64-cc -shared
echo "Make"
make
# Clean
rm -r openssl_x86_64
rm openssl-$NEW_OPENSSL_VERSION.tar.gz

echo "Completed!"