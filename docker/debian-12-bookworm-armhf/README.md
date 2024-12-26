# Notes to run tests

```
sudo apt update
sudo apt install -y python3-minimal
sudo apt install -y python3-pip
sudo apt install python3.11-venv
python3 -m venv /tmp/venv
source /tmp/venv/bin/activate
python3 -m pip install --use-pep517 pyaes
python3 -m pip install ansicolors sslcrypto
git config --global --add safe.directory /home/rrg/proxmark3
cd proxmark3
make clean
make -j
tools/pm3_tests.sh --long
```
