---
name: Checklist for release
about: A template when making a release
title: "[RELEASE]"
labels: Release
assignees: doegox, iceman1001

---

Checklist

- [ ] CHANGELOG.md
- [ ] `make style`
- [ ] `make clean; make -j; ./pm3tests`
- [ ] `( cd client;mkdir build;cd build;cmake ..;make -j ); PM3BIN=./client/build/proxmark3 ./pm3test.sh client`
- [ ] `make clean; make client CC=clang CXX=clang++ LD=clang++`
- [ ] `mymanualchecks.sh`
- [ ] `mycppcheck.sh` no alarming warning?
- [ ] `mymakeclang.sh` no alarming error/warning ?
- [ ] `mystandalone_makes.sh` compile all standalone modes (linux only)
- [ ] [Travis](https://travis-ci.org/github/RfidResearchGroup/proxmark3/builds) green (linux noqt / osx+qt ; with makefile (w/wo bt) / with cmake)
- [ ] [Appveyor](https://ci.appveyor.com/project/RfidResearchGroup/proxmark3/history) green (PS)
- [ ] WSL
- [ ] RPI Zero




```
#!/usr/bin/env bash

make clean; make -j PLATFORM=PM3OTHER; ./pm3test.sh
make clean; make -j PLATFORM=PM3RDV4; ./pm3test.sh
make clean; make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON; ./pm3test.sh

( cd client; rm -rf build; mkdir build;cd build;cmake ..;make -j PLATFORM=PM3OTHER ); PM3BIN=./client/build/proxmark3 ./pm3test.sh client
( cd client; rm -rf build; mkdir build;cd build;cmake ..;make -j PLATFORM=PM3RDV4 ); PM3BIN=./client/build/proxmark3 ./pm3test.sh client
( cd client; rm -rf build; mkdir build;cd build;cmake ..;make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON ); PM3BIN=./client/build/proxmark3 ./tools/pm3test.sh client
```

Also test on Debian10 / Ubuntu19.10
```make clean; make client CC=clang CXX=clang++ LD=clang++```

```
- [ ] make PLATFORM=PM3OTHER
- [ ] make PLATFORM=PM3RDV4
- [ ] make PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON
```
