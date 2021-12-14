# Notes to run tests

```
sudo yum -y update
sudo yum -y install cmake python-pip
python3 -m pip install ansicolors sslcrypto
tools/pm3_tests.sh --long
```

Warning, no idea how to manage to run `recover_pk` on Fedora...
Tried the followings:
```
python3 -m pip install pyopenssl
sudo yum -y install openssl-devel libffi-devel
```
Error is:
```
  File "/home/rrg/.local/lib/python3.9/site-packages/sslcrypto/_ecc.py", line 202, in get_curve
    return EllipticCurve(self._backend, params, self._aes, nid)
  File "/home/rrg/.local/lib/python3.9/site-packages/sslcrypto/_ecc.py", line 211, in __init__
    self._backend = backend_factory(**params)
  File "/home/rrg/.local/lib/python3.9/site-packages/sslcrypto/openssl/ecc.py", line 221, in __init__
    raise ValueError("Could not create group object")
```

So just comment the "recover_pk test" for now, until someone figures out how to solve the issue.
