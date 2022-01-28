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

# Notes to run tests

Add first the mirrors, see above

```
sudo pacman -S python-pip
python3 -m pip install ansicolors sslcrypto
tools/pm3_tests.sh --long
```
