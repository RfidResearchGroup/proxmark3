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
- [ ] `mystandalone_makes.sh` check that the script contains all standalone modes then compile all standalone modes (linux only)
- [ ] GitHub Actions - green across the board ( MacOS, Ubuntu, Windows)
- [ ] [Appveyor](https://ci.appveyor.com/project/RfidResearchGroup/proxmark3/history) green (PS)

# OS compilation and tests

```bash
#!/usr/bin/env bash

make clean && make -j PLATFORM=PM3GENERIC && tools/pm3_tests.sh --long
make clean && make -j PLATFORM=PM3RDV4 && tools/pm3_tests.sh --long
make clean && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON && tools/pm3_tests.sh --long
sudo make install; pushd /tmp; proxmark3 -c 'data load -f lf_EM4x05.pm3;lf search -1'; popd; sudo make uninstall

( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3GENERIC && PM3BIN=./proxmark3 ../../tools/pm3_tests.sh client )
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3RDV4  && PM3BIN=./proxmark3 ../../tools/pm3_tests.sh client )
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON && PM3BIN=./proxmark3 ../../tools/pm3_tests.sh client )
```

- [ ] RPI Zero
- [ ] WSL
- [ ] PSv3.9
- [ ] Archlinux
- [ ] Kali
- [ ] Debian
- [ ] Ubuntu20
- [ ] ParrotOS
- [ ] Fedora
- [ ] OpenSuse
- [ ] OSX
- [ ] Android
- [ ] Termux

# creating release
`make release RELEASE_NAME="ice awesome"`
last line of output,  gives you next command to run
Sample:  `git push && git push origin v4.15000`


Go to Github releases,  create release based on the new created tag and publish
update homebrew repo, file `proxmark3.rb` with a SHA256 sum of the file `v4.15000.tar.gz`  
