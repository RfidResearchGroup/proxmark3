#!/bin/bash
set -x
# This is for linux ppl and it works on Ubuntu distros. Don't know about Kali.
function installProxmark_Linux {
  # install dependencies for Proxmark3 source code.
  sudo apt-get install p7zip git build-essential libreadline5 libreadline-dev gcc-arm-none-eabi
  sudo apt-get install libusb-0.1-4 libusb-dev libqt4-dev libncurses5-dev perl pkg-config wget
  #cleaning up
  sudo apt-get install -f -y
  sudo apt-get autoremove -y
  sudo apt-get autoclean -y
  sudo apt-get clean -y
  sudo apt-get update
# install RDV40 - proxmark3
  git clone https://github.com/RfidResearchGroup/proxmark3.git
  (
      cd proxmark3 || exit 1
      git reset --hard
      git clean -dfx
      make clean
      make all
      # Copy blacklist rules into /etc/udev/rules.d
      # check the Makefile for details
      sudo make udev
   )
}
function installProxmark_macOS {
  # Install dependencies for Proxmark3 source code.
  brew tap nitsky/stm32
  brew install readline libusb p7zip libusb-compat wget qt5 pkgconfig arm-none-eabi-gcc
  brew link --force readline
  # add moc_location in Qt5Core.pc file.
local qtDir=$(ls /usr/local/Cellar/qt/ 2>/dev/null | head -1)
local qt5Core=$(find /usr -name Qt5Core.pc 2>/dev/null)
  (
    export PKG_CONFIG_PATH=/usr/local/Cellar/qt/$qtDir/lib/pkgconfig/
    export QT_PKG_CONFIG_QT5CORE=$qt5Core
    chmod 666 $QT_PKG_CONFIG_QT5CORE
    echo "moc_location=\${prefix}/bin/moc" >> $QT_PKG_CONFIG_QT5CORE
    chmod 444 $QT_PKG_CONFIG_QT5CORE
  )
  # install RDV40 - proxmark3
    git clone https://github.com/RfidResearchGroup/proxmark3.git
      (
        cd proxmark3 || exit 1
        git reset --hard
        git clean -dfx
        make clean
        make
      )
  }
# Where is my device?
#dmesg | tail -10
# Detect OS and install libraries and proxmark3 client
if [[ $(uname | awk '{print toupper($0)}') == "LINUX" ]]; then
    echo >&2 "Linux Detected - Updating your system..."
    $(installProxmark_Linux)
elif [[ $(uname | awk '{print toupper($0)}') == "DARWIN" ]]; then
    echo >&2 "MAC OS X Detected - Updating your system..."
    $(installProxmark_macOS) 2>/dev/null
fi
echo >&2 "Done."
