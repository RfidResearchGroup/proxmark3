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
- [ ] `make miscchecks`
- [ ] `make clean; make client CC=clang CXX=clang++ LD=clang++` on recent Debian or Ubuntu
- [ ] `mymanualchecks.sh`
- [ ] `mycppcheck.sh` no alarming warning?
- [ ] `mystandalone_makes.sh` check that the script contains all standalone modes then compile all standalone modes (linux only)
- [ ] GitHub Actions - green across the board ( MacOS, Ubuntu, Windows)
- [ ] [Appveyor](https://ci.appveyor.com/project/RfidResearchGroup/proxmark3/history) green (PS)

# OS compilation and tests

```bash
#!/usr/bin/env bash

make clean && make -j PLATFORM=PM3GENERIC PLATFORM_EXTRAS= && tools/pm3_tests.sh --long || exit 1
make clean && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS= && tools/pm3_tests.sh --long || exit 1
make clean && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON && tools/pm3_tests.sh --long || exit 1
make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON && sudo make install PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON && ( cd /tmp; proxmark3 -c 'data load -f lf_EM4x05.pm3;lf search -1'|grep 'Valid FDX-B ID found' ) && sudo make uninstall || exit 1

( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3GENERIC PLATFORM_EXTRAS= && ../../tools/pm3_tests.sh --clientbin $(pwd)/proxmark3 client ) || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3RDV4  PLATFORM_EXTRAS= && ../../tools/pm3_tests.sh --clientbin $(pwd)/proxmark3 client ) || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON && ../../tools/pm3_tests.sh --clientbin $(pwd)/proxmark3 client ) || exit 1
```

- [ ] RPI Zero
- [ ] Jetson Nano
- [ ] WSL
- [ ] PSv3.10
- [ ] Archlinux
- [ ] Kali
- [ ] Debian Stable
- [ ] Debian Testing
- [ ] Ubuntu21
- [ ] ParrotOS
- [ ] Fedora
- [ ] OpenSuse Leap
- [ ] OpenSuse Tumbleweed
- [ ] OSX
- [ ] Android
- [ ] Termux

# creating release
`make release RELEASE_NAME="ice awesome"`
last line of output,  gives you next command to run
Sample:  `git push && git push origin v4.15000`

## Step Github releases
Go to Github releases,  create release based on the new created tag and publish

## Step Homebrew updates
update homebrew repo, file `proxmark3.rb` with a SHA256 sum of the file `v4.15000.tar.gz`  

## Step package maintains
make a list of new standalone modes,  so when we alert package maintainers they have a sporting chance of adding them
