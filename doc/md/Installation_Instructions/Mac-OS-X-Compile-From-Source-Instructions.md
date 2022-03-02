<a id="Top"></a>

# Mac OS X - Compilation from source instructions

# Table of Contents
- [Mac OS X - Compilation from source instructions](x#mac-os-x---compilation-from-source-instructions)
- [Table of Contents](#table-of-contents)
  - [Installing build prerequisites via Homebrew](#installing-build-prerequisites-via-homebrew)
  - [Configure the build](#configure-the-build)
  - [Compilation from source](#compilation-from-source)

## Installing build prerequisites via Homebrew
^[Top](#top)

We need to install the ``openssl`` library with ``brew``:
```bash
brew install openssl
```
To run the local install script below, we also require the GNU versions 
of several core Unix utilities:
```bash
brew install coreutils
```

## Configure the build
^[Top](#top)

Clone the repository by running the following:
```bash
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
```
Configure the build by editing ``Makefile.platform`` 
(this step is optional -- the default will suffice):
```bash
cp Makefile.platform.sample Makefile.platform
vim Makefile.platform
```

## Compilation from source
^[Top](#top)

The following command has been shown to work on MacOS Big Sur with the 
default Compiler Tools that comes installed on this release of the platform:
```bash
make clean && CFLAGS="-I /usr/local/opt/openssl/include" make -j
```
The rest of this section is an *optional* installation procedure. 

If you have ``sudo`` rights, you can install the proxmark3 utilities into the system 
path by running
```bash
sudo make install
```
Otherwise, assuming you are using the ``bash`` shell (using ``chsh -s /bin/bash `whoami```), we can create 
an alias to the relevant commands:
```bash
export BASHRC="~/.bash_profile"
export PM3LOCAL_PATH="$(greadlink -f .)"
touch $BASHRC
echo "alias pm3=\'$PM3LOCAL_PATH/pm3\'" >> $BASHRC
echo "alias pm3-flash=\'$PM3LOCAL_PATH/pm3-flash\'" >> $BASHRC
echo "alias pm3-flash-all=\'$PM3LOCAL_PATH/pm3-flash-all\'" >> $BASHRC
echo "alias pm3-flash-bootrom=\'$PM3LOCAL_PATH/pm3-flash-bootrom\'" >> $BASHRC
echo "alias pm3-flash-fullimage=\'$PM3LOCAL_PATH/pm3-flash-fullimage\'" >> $BASHRC
```
When you are done running the previous script, make sure to update the settings in your 
current shell (Mac Terminal) instance by running
```bash
source ~/.bash_profile
```
When you re-start the Mac terminal, new shell instances will automatically load these 
new settings.
