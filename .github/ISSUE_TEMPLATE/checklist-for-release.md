---
name: Checklist for release
about: A template when making a release (usage reserved to repo maintainers)
title: "[RELEASE 4.x] Checklist"
labels: Release
assignees: doegox, iceman1001

---

# Checklist

- [ ] CHANGELOG.md
- [ ] `make style`
- [ ] `make clean; make client CC=clang CXX=clang++ LD=clang++` on recent Debian or Ubuntu
- [ ] `mymanualchecks.sh`
- [ ] `mycppcheck.sh` no alarming warning?
- [ ] `mymakeclang.sh` no alarming error/warning ?
- [ ] `mystandalone_makes.sh` compile all standalone modes (linux only)
- [ ] [Travis](https://travis-ci.org/github/RfidResearchGroup/proxmark3/builds) green (linux noqt / osx+qt ; with makefile (w/wo bt) / with cmake)
- [ ] [Appveyor](https://ci.appveyor.com/project/RfidResearchGroup/proxmark3/history) green (PS)

# OS compilation and tests

```bash
make clean && make -j PLATFORM=PM3OTHER && tools/pm3_tests.sh
make clean && make -j PLATFORM=PM3RDV4 && tools/pm3_tests.sh
make clean && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON && tools/pm3_tests.sh
make install; pushd /tmp; proxmark3 -c 'data load -f em4x05.pm3;lf search 1'; popd; make uninstall

( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3OTHER && PM3BIN=./proxmark3 ../../tools/pm3_tests.sh client )
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3RDV4  && PM3BIN=./proxmark3 ../../tools/pm3_tests.sh client )
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON && PM3BIN=./proxmark3 ../../tools/pm3_tests.sh client )
```

- [ ] RPI Zero
- [ ] WSL
- [ ] PSv3.3
- [ ] Kali
- [ ] Debian
- [ ] Ubuntu20
- [ ] ParrotOS
- [ ] Fedora
- [ ] OpenSuse
- [ ] OSX
- [ ] Android
- [ ] Termux

