cmake --build  build
rm -rf ./libparity_pkcs11.so
mv build/libparity_pkcs11.so ./
