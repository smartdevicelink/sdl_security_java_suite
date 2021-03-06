# SDL Security Java Suite

SDL Security is a TLS based security library built to interact with sdl_java_suite and provide TLS certificate authentication and encryption / decryption.

### When is this useful?
This library can be used to allow TLS authentication on a specific RPC service, for example the RPC or Video service.

### How do I use it?
This library is primarily for automotive OEMs to base their own proprietary library on. The OEM may change the URL to retrieve a certificate, and may want to provide additional protection to this library. Otherwise, it will be quite easy for an attacker to take the certificate and defeat the TLS protection.

The OEM must also rename this library and classes for the reasons seen below.

To use this library, the developer will pass the name of the class into the `SdlManager`'s builder' method:
```
List<Class<? extends SdlSecurityBase>> secList = new ArrayList<>();
secList.add(SdlSecurity.class);
builder.setSdlSecurity(secList, null);
```

They must also pass in the name of the Vehicle 'Makes' that library is used for, for example, a Ford library may be used for `["Ford", "Lincoln"]`. This must match what is passed through the `register app interface` RPC response. For more information on how to setup the library, please check the [resources folder](/resources/readme.md).

#### Rebuild Native Code
If you would like to rebuild the native code for OpenSSL or tlsEngine, please check the [instructions here](/resources/compile_native_code.md).

#### Security Note:
Anyone implementing this library should take care to add additional protections as this library is not cryptographically secure out-of-the box.