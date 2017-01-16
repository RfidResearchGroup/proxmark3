#for linux ppl
# this should work fine on Ubuntu distros. Don't know about Kali, ...

echo "Updating your system..."

# install dependencies for Proxmark3 source code.
sudo apt-get install p7zip git build-essential libreadline5 libreadline-dev gcc-arm-none-eabi 
sudo apt-get install libusb-0.1-4 libusb-dev libqt4-dev libncurses5-dev perl pkg-config wget

#cleaning up
sudo apt-get install -f -y
sudo apt-get autoremove -y
sudo apt-get autoclean -y
sudo apt-get clean -y
sudo apt-get update

# Copy blacklist rules into /etc/udev/rules.d
# check the Makefile for details
sudo make udev

# Where is my device?
#dmesg | tail -10

