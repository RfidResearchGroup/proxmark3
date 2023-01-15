---
name: Checklist for release
about: A template when making a release (usage reserved to repo maintainers)
title: "[RELEASE 4.x] Checklist"
labels: Release
assignees: doegox, iceman1001

---

# Checklist

- [ ] CHANGELOG.md: add title: `## [releasename][YYYY-MM-DD]`
- [ ] `make style`
- [ ] `make miscchecks`
- [ ] `make clean; make client CC=clang CXX=clang++ LD=clang++` on recent Debian or Ubuntu
- [ ] `mymanualchecks.sh`
- [ ] `mycppcheck.sh` no alarming warning?
- [ ] `tools/build_all_firmwares.sh` check that the script contains all standalone modes then compile all standalone modes (linux only)
- [ ] `experimental_lib` compilation & tests
- [ ] `experimental_client_with_swig` compilation & tests
- [ ] GitHub Actions - green across the board ( MacOS, Ubuntu, Windows)

# OS compilation and tests

Run `tools/release_tests.sh` on:

- [ ] RPI Zero
- [ ] Jetson Nano
- [ ] WSL
- [ ] PSv3.10
- [ ] Archlinux
- [ ] Kali
- [ ] Debian Stable
- [ ] Debian Testing
- [ ] Ubuntu 22
- [ ] ParrotOS
- [ ] Fedora 37
- [ ] OpenSuse Leap
- [ ] OpenSuse Tumbleweed
- [ ] OSX (MacPorts)
- [ ] OSX (Homebrew)
- [ ] Android
- [ ] Termux

# creating release

- [ ] `make release RELEASE_NAME="ice awesome"`
  - last line of output,  gives you next command to run.
  - Sample:  `git push && git push origin v4.12345`
- [ ] CHANGELOG.md: edit title to add version info: `## [releasename.4.12345][YYYY-MM-DD]`

## Step Github releases

- [ ] Go to Github releases,  create release based on the new created tag and publish

## Step Homebrew updates

- [ ] update homebrew repo, file `proxmark3.rb`
  - with a SHA256 sum of the file `v4.12345.tar.gz`
  - with updated list of standalone modes

## Step package maintains

- [ ] make a list of new standalone modes, so when we alert package maintainers they have a sporting chance of adding them
