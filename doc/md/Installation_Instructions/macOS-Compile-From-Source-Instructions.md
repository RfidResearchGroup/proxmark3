<a id="Top"></a>

# macOS - Compilation from source instructions

# Table of Contents
- [macOS - Compilation from source instructions](#macos---compilation-from-source-instructions)
- [Table of Contents](#table-of-contents)
  - [Follow Homebrew developer instructions](#follow-homebrew-developer-instructions)
  - [(optional) Running without sudo](#optional-running-without-sudo)


## Follow Homebrew developer instructions
^[Top](#top)

Follow the instructions here [developer instructions](/doc/md/Installation_Instructions/macOS-Homebrew-Installation-Instructions.md#homebrew-macos-developer-installation) and you are done. 

## (optional) Running without sudo
^[Top](#top)

This section is an *optional* installation procedure. 


Assuming you are using the ``bash`` shell (using ``chsh -s /bin/bash `whoami```), we can create 
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
