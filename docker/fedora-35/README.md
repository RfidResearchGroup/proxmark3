# Notes to run tests

```
sudo yum -y update
sudo yum -y install cmake python-pip
python3 -m pip install ansicolors sslcrypto
tools/pm3_tests.sh --long
```

Warning, `recover_pk selftests` will fail on Fedora because they stripped down the available ECC curves in their OpenSSL.

So just comment the "recover_pk test"
