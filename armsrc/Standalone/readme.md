# StandAlone Modes

This contains functionality for different StandAlone modes. The fullimage will be built given the correct compiler flags used. Build targets for these files are contained in `armsrc/Makefile`.

If you want to implement a new standalone mode, you need to implement the methods provided in `standalone.h`.

## Implementing a standalone mode

Each standalone mod needs to have its own compiler flag to be added in `armsrc\makefile` and inside the function `AppMain` inside  AppMain.c.  Inside Appmain a call to RunMod is needed.  It looks strange because of what kinds of dependencies your mode will have.  

The RunMod function is your "main" function when running.  You need to check for Usb commands,  in order to let the pm3 client break the standalone mode.  See this basic skeleton of main function RunMod().
````
void RunMod() {
    // led show
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // main loop
    for (;;) {
        WDT_HIT();

        // exit from standalone mode, just send a usbcommand
        if (usb_poll_validate_length()) break;

        // do your standalone stuff..
    }
````

As it is now, you can only have one standalone mode installed at the time.  

## Name
Use HF/LF to denote which frequence your mod is targeting.  
Use you own github name/similar for perpetual honour to denote your mod

Samples of directive flag used in the `armsrc\makefile`:
```
### -DWITH_LF_ICERUN
### -DWITH_LF_SAMYRUN
### -DWITH_LF_PROXBRUTE
### -DWITH_LF_HIDBRUTE
### -DWITH_HF_COLIN
### -DWITH_HF_YOUNG
### -DWITH_HF_MATTYRUN
```
Add your source code file like the following sample in the `armsrc\makefile`

```
# WITH_HF_COLIN
ifneq (,$(findstring WITH_HF_COLIN,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_colin.c vtsend.c
else
    SRC_STANDALONE =
endif
```

## Adding identification of your mode
Do please add a identification string in the function `printStandAloneModes` inside `armsrc\appmain.c`
This will enable an easy way to detect on client side which standalone mods has been installed on the device.
```
#if defined(WITH_HF_COLIN)
    DbpString("   HF Mifare ultra fast sniff/sim/clone - aka VIGIKPWN (Colin Brigato)");
#endif
````

Once all this is done, you and others can now easily compile different standalone modes by just swapping the -D directive in `armsrc\makefile`

````
#remove one of the following defines and comment out the relevant line
#in the next section to remove that particular feature from compilation.
# NO space,TABs after the "\" sign.
APP_CFLAGS = -DWITH_CRC \
             -DON_DEVICE \
             -DWITH_LF \
             -DWITH_HITAG \
             -DWITH_ISO15693 \
             -DWITH_LEGICRF \
             -DWITH_ISO14443b \
             -DWITH_ISO14443a \
             -DWITH_ICLASS \
             -DWITH_FELICA \
             -DWITH_FLASH \
             -DWITH_SMARTCARD \
             -DWITH_HFSNOOP \
             -DWITH_HF_COLIN\
             -DWITH_FPC \
             -fno-strict-aliasing -ffunction-sections -fdata-sections

### IMPORTANT -  move the commented variable below this line
#             -DWITH_LCD \
#             -DWITH_EMV \
#             -DWITH_FPC \
#
# Standalone Mods
#-------------------------------------------------------
#             -DWITH_LF_ICERUN
#             -DWITH_LF_SAMYRUN
#             -DWITH_LF_PROXBRUTE
#             -DWITH_LF_HIDBRUTE
#             -DWITH_HF_YOUNG
#             -DWITH_HF_MATTYRUN
#             -DWITH_HF_COLIN
````
