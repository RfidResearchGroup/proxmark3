
## Coverity Scan Config & Run
Download the Coverity Scan Self-buld and install it.
You will need to configure  ARM-NON-EABI- Compiler for it to use:

 Configure

```sh
cov-configure --comptype gcc --compiler  /opt/devkitpro/devkitARM/bin/arm-none-eabi-gcc
```

Run it (I'm running on Ubuntu)

```sh
cov-build --dir cov-int make all
```

Make a tarball

```sh
tar czvf proxmark3.tgz cov-int
```

Upload it to scan.coverity.com
