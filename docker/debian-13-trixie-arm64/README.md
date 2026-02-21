# Notes to install corss-platform support
```
sudo apt install qemu-user qemu-user-binfmt binfmt-support
```
# Notes to run tests

The script is to be run in proxmark root folder inside the docker env.

```
docker/debian-13-trixie-arm64/run_tests.sh;
```

Or if you want to run single test,

```
sudo apt update && sudo apt upgrade -y
git config --global --add safe.directory /home/rrg/proxmark3
make clean; make -j
tools/pm3_tests.sh --long
```
