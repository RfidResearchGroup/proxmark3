# StandAlone Mods

This contains functionality for different StandAlone mods. The fullimage will be built given the correct compiler flags used. Build targets for these files are contained in `armsrc/Makefile`.

If you want to implement a new standalone mod, you need to implement the methods provided in `standalone.h`.

## Implementing a standalone mod

Each standalone mod needs to have its own compiler flag to be added in `armsrc\makefile` and inside the function `AppMain` inside  AppMain.c 

Use HF/LF to denote which frequence your mod is targeting.  
Use you own github name/similar for perpetual honour to denote your mod

samples:
# -DWITH_LF_ICERUN
# -DWITH_LF_SAMYRUN
# -DWITH_LF_PROXBRUTE
# -DWITH_LF_HIDCORP
# -DWITH_HF_YOUNG
# -DWITH_HF_MATTYRUN

## Adding identification of your mod
Do please add a identification string in the function `printStandAloneModes` inside `armsrc\appmain.c`
This will enable an easy way to detect on client side which standalone mods has been installed on the device.