# Write custom data to a signed file without breaking the signatures

Write custom data into a Microsoft Authenticode signed executable or MSI file without breaking the signature. Also write custom verifiable data into Linux ELF files. It does so by using magic and unicorns.

## Building

It can be built on Linux or cross-built for Linux from Windows. The target platform is **Linux**. It can be compiled for Windows, but a small part of the code path has not been finished, so it will not work as is.

* On Linux

        docker run --rm -e DOTNET_CLI_TELEMETRY_OPTOUT=true -v $PWD:/app --workdir /app mcr.microsoft.com/dotnet/sdk dotnet publish -c Release -r linux-x64

* On Windows for Linux (why tho? switch to Linux already)

Get the [dotnet sdk](https://download.visualstudio.microsoft.com/download/pr/78a6328f-f563-4a7f-a478-3ed0f2ce8ec6/5beb762f64d8a018a5b9e590bc1531e0/dotnet-sdk-5.0.201-win-x64.exe), then run.

        dotnet publish -c Release -r linux-x64

The executable will be stored under `/app/signreader/bin/Release/net5.0/win-x64/publish/`. It is a [self-contained executable](https://docs.microsoft.com/en-us/dotnet/core/deploying/single-file)

### Dependencies

#### Build time

The Linux build relies on [osslsigncode](https://github.com/mtrojnar/osslsigncode). The best way to get it is to

* Clone the [repo](https://github.com/mtrojnar/osslsigncode)
* Get teh build time dependencies - `apt-get install build-essential autoconf libtool libssl-dev python3-pkgconfig libcurl4-gnutls-dev`
* Get optional support for signing MSIs `apt install libgsf-dev`
* Then do the build dance:

```
./autogen.sh
./configure
make
```

The Windows build is using [signtool](https://docs.microsoft.com/en-us/windows/win32/seccrypto/signtool) from the [windows 10 sdk](https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk/)

#### Runtime

* dotnet from https://docs.microsoft.com/en-us/dotnet/core/install/linux-debian
* osslsigncode runtime dependencies: libgsf-1-114 libcurl.so.4
* libgssapi-krb5-2 and libssl1.1

> Note: libgssapi-krb5-2 and libssl1.1 come as a part of apt-transport-https required to install dotnet

## Running

* Windows: `./signwriter signedexec.exe <server> <reg key here> <some other data>`
* Linux `./signwriter somelinuxelf <server> <reg key here> <some other data>`

Don't expect good error messages, it's not a user friendly tool.

## Notes

* To build a docker container see [this](https://github.com/dotnet/dotnet-docker/tree/main/samples/dotnetapp)
* Could also use  signcode from mono-devel package - /usr/bin/mono /usr/lib/mono/4.5/signcode.exe "$@"

## References

* https://stackoverflow.com/questions/46096886/embed-user-specific-data-into-an-authenticode-signed-installer-on-download
* https://github.com/mgaffigan/passdata
