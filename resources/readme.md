# SDL Security Java Suite

## Sdl Core Setup
* Copy the sample `client.crt` & `client.key` to core's build `bin` folder and remove the existing `mycert.pem` & `mykey.pem` certificates

* Update `CertificatePath` & `KeyPath` in `smartDeviceLink.ini` to match the files names
```
CertificatePath = client.crt
KeyPath         = client.key
```

* Turn off `VerifyPeer` in `smartDeviceLink.ini`
```
VerifyPeer  = false
```

* Run `c_rehash` in core's build `bin` folder
```
$ c_rehash .
```

## Sdl App Setup
* Add `sdl_security` module to `build.gradle`
```
implementation (project(path: ':sdl_security')) {
    transitive = false
}
```
Note: Use `sdl_security_se` instead of `sdl_security` for cloud apps

* Set `SdlSecurity` class in the `SdlManager`'s builder
```
List<Class<? extends SdlSecurityBase>> secList = new ArrayList<>();
secList.add(SdlSecurity.class);
builder.setSdlSecurity(secList, null);
```

* Update the SDL Server endpoint in `Constants.java` to download the certificate. Also the certificate passphrase should be updated

Note: For testing purposes only, you can use the sample JSON response file with an api mocking service like `mocky.io`. If you want to use the sample response, the `appId` for your sdl app should be set to `caaf9c76-5a2e-4fa6-af4d-81279de9ca8c`. And the passphrase should be set to `CERT_PASS = "password"`

* Use a feature that uses encryption (like RPC protection or encrypted video streaming)

