
## Coverity Scan Config & Run
Download the Coverity Scan Self-build from https://scan.coverity.com/download/ and untar it.

You will need to configure  ARM-NON-EABI- Compiler for it to use:

Configure

```sh
cov-configure --template --compiler arm-none-eabi-gcc --comptype gcc
```
If it's in a unusual location:

```sh
cov-configure --comptype gcc --compiler /opt/devkitpro/devkitARM/bin/arm-none-eabi-gcc
```

Run it

```sh
cov-build --dir cov-int make all
```

Make a tarball

```sh
tar czvf proxmark3.tgz cov-int
```

Upload it to scan.coverity.com
