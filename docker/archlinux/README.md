# Notes to install latest gcc and arm-none-eabi-gcc

```
cat << EOF |sudo tee -a /etc/pacman.conf

[testing]
Include = /etc/pacman.d/mirrorlist

[community-testing]
Include = /etc/pacman.d/mirrorlist

[staging]
Include = /etc/pacman.d/mirrorlist
EOF

sudo pacman -Syu

# search available versions
pacman -Ss '^arm-none-eabi-gcc$'
pacman -Ss '^gcc$'

# depending on where the latest bleeding edge is:
sudo pacman -S community-testing/arm-none-eabi-gcc
sudo pacman -S arm-none-eabi-gcc
sudo pacman -S staging/gcc
sudo pacman -S testing/gcc
sudo pacman -S gcc
```

# Notes on run_tests.sh script
This script does both setup the mirrors and pip install and then run a 
bunch of different builds with make and cmake together with the different combos 
of RDV4, GENERIC, BTADDON combos. 

If all tests OK,  the script will finish with PASS.


# Notes to run tests
Add first the mirrors, see above, if needed.

The release test build script is to be run in proxmark root folder inside the docker env.
```
docker/archlinux/run_tests.sh;
```

Or if you want to run single test,

```
make clean; make -j

python3 -m venv /tmp/venv
source /tmp/venv/bin/activate
python3 -m pip install --use-pep517 pyaes
python3 -m pip install ansicolors sslcrypto
tools/pm3_tests.sh --long
deactivate
```
