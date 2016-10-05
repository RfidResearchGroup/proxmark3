echo "Updating your system..."

# install dependencies for Proxmark3 source code.
sudo apt-get install p7zip git build-essential libreadline5 libreadline-dev gcc-arm-none-eabi 
sudo apt-get install libusb-0.1-4 libusb-dev libqt4-dev ncurses-dev perl pkg-config wget

#cleaning up
sudo apt-get install -f -y
sudo apt-get autoremove -y
sudo apt-get autoclean -y
sudo apt-get clean -y
sudo apt-get update

# Where is my device?
dmesg | tail -10

