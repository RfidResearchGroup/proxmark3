# Notes to run tests

```
sudo apt update
git config --global --add safe.directory /home/rrg/proxmark3
cd proxmark3
make clean
make -j
tools/pm3_tests.sh --long
```
