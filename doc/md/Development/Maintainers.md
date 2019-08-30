Hi maintainers!

Here are some tips how to integrate this repo in some nice package for your distro.
Feel free to contact us via Github issues for any question, suggestion or if you want to share useful tricks in this file for other maintainers.

Makefile
========

`PREFIX` and `UDEV_PREFIX` can be provided by environment variable, else it defaults to `/usr/local/share` and `/etc/udev/rules.d`.

`DESTDIR` can be provided by environment variable, it can be a relative path and it will be prepended to `PREFIX`, so you can use e.g.:

`make install DESTDIR=build PREFIX=/usr UDEV_PREFIX=/lib/udev/rules.d`

and it will be deployed as

```
./build/lib/udev/rules.d/77-pm3-usb-device-blacklist.rules
./build/usr/bin/proxmark3 ...
./build/usr/share/doc/proxmark3/...
./build/usr/share/proxmark3/...
```

That should be a good start for you to create your package :)

For verbose usage and see the actual commands being executed, add `V=1`.

`CFLAGS` and `LDFLAGS` can be overriden by environment variables.

Default compiler is gcc but you can use clang for the non-ARM parts with e.g. `make client CC=clang CXX=clang++ LD=clang++`.

