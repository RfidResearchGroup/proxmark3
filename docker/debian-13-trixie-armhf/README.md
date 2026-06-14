# Notes to install corss-platform support
```
sudo apt install qemu-user qemu-user-binfmt binfmt-support
```
# Notes to run tests

The script is to be run in proxmark root folder inside the docker env.

```
su - rrg
cd proxmark3
docker/debian-13-trixie-armhf/run_tests.sh;
```

Or if you want to run single test,

```
apt update && sudo apt upgrade -y
su - rrg
cd proxmark3
git config --global --add safe.directory /home/rrg/proxmark3
make clean; make -j
tools/pm3_tests.sh --long
```
