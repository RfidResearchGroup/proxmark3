# StandAlone Modes

This contains functionality for different StandAlone modes. The fullimage will be built given the correct compiler flags used. Build targets for these files are contained in `armsrc/Makefile`.

If you want to implement a new standalone mode, you need to implement the methods provided in `standalone.h`.

## Implementing a standalone mode

Each standalone mod needs to have its own compiler flag to be added in `armsrc\makefile` and inside the function `AppMain` inside  AppMain.c.  Inside Appmain a call to RunMod is needed.  It looks strange because of what kinds of dependencies your mode will have.
The RunMod function is your "main" function when running.  You need to check for Usb commands,  in order to let the pm3 client break the standalone mode. 

As it is now, you can only have one standalone mode installed at the time.  

## Name
Use HF/LF to denote which frequence your mod is targeting.  
Use you own github name/similar for perpetual honour to denote your mod

Samples:
### -DWITH_LF_ICERUN
### -DWITH_LF_SAMYRUN
### -DWITH_LF_PROXBRUTE
### -DWITH_LF_HIDBRUTE
### -DWITH_HF_YOUNG
### -DWITH_HF_MATTYRUN

## Adding identification of your mode
Do please add a identification string in the function `printStandAloneModes` inside `armsrc\appmain.c`
This will enable an easy way to detect on client side which standalone mods has been installed on the device.
