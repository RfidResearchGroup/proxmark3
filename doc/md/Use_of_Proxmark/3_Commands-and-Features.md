<a id="Top"></a>

# 3. Commands and Features

# Table of Contents
- [3. Commands and Features](#3-commands-and-features)
- [Table of Contents](#table-of-contents)
  - [To get interactive help](#to-get-interactive-help)
  - [New Features in RDV4](#new-features-in-rdv4)
  - [Useful commands](#useful-commands)



Please make sure you've gone through the following pages firstly:

* [Compilation Instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md)
* [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md)
* [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)

## To get interactive help
^[Top](#top)

As seen before, for basic help type `help`. Or for help on a set of sub commands type the command followed by `help`. For example `hf mf help`.  Many commands uses the `-h` / `--help` parameter to show a help text.

## New Features in RDV4
^[Top](#top)

Further details coming soon

## Useful commands
^[Top](#top)

Here are some commands to start off with.

To get an overview of the available commands for LF RFID and HF RFID:
```
[usb] pm3 --> lf
[usb] pm3 --> hf
```

To search quickly for known LF or HF tags:
```
[usb] pm3 --> lf search
[usb] pm3 --> hf search
```

To get info on a ISO14443-A tag:
```
[usb] pm3 --> hf 14a info
```

A good starting point is the following [Cheat sheet](/doc/cheatsheet.md)

Or 

this compilation of links to [Proxmark3 walk throughs](https://github.com/RfidResearchGroup/proxmark3/wiki/More-cheat-sheets)
