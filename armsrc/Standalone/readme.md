# StandAlone Modes

This contains functionality for different StandAlone modes. The fullimage will be built given the correct compiler flags used. Build targets for these files are contained in `armsrc/Makefile`.

If you want to implement a new standalone mode, you need to implement the methods provided in `standalone.h`.
Have a look at the skeleton standalone mode called  IceRun, in the files `lf_icerun.c lf_icerun.h`.

## Implementing a standalone mode

Each standalone mod needs to have its own compiler flag to be added in `armsrc\makefile` and inside the function `AppMain` inside  AppMain.c.  Inside Appmain a call to RunMod is needed.  It looks strange because of what kinds of dependencies your mode will have.  

The RunMod function is your "main" function when running.  You need to check for Usb commands,  in order to let the pm3 client break the standalone mode.  See this basic skeleton of main function RunMod().
````
void ModInfo(void) {
    DbpString("   HF good description of your mode - (my name)");
}

void RunMod(void) {
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

Samples of directive flag used in the `common/Makefile.hal`:
```
#PLATFORM_DEFS += -DWITH_STANDALONE_LF_SAMYRUN
#PLATFORM_DEFS += -DWITH_STANDALONE_LF_ICERUN
#PLATFORM_DEFS += -DWITH_STANDALONE_LF_SAMYRUN
#PLATFORM_DEFS += -DWITH_STANDALONE_LF_PROXBRUTE
#PLATFORM_DEFS += -DWITH_STANDALONE_LF_HIDBRUTE
#PLATFORM_DEFS += -DWITH_STANDALONE_HF_YOUNG
#PLATFORM_DEFS += -DWITH_STANDALONE_HF_MATTYRUN
#PLATFORM_DEFS += -DWITH_STANDALONE_HF_COLIN
#PLATFORM_DEFS += -DWITH_STANDALONE_HF_BOG
```
Add your source code file like the following sample in the `armsrc\makefile`

```
# WITH_STANDALONE_HF_COLIN
ifneq (,$(findstring WITH_STANDALONE_HF_COLIN,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_colin.c vtsend.c
else
    SRC_STANDALONE =
endif
```

## Adding identification of your mode
Do please add a identification string in a function called `ModInfo` inside your source code file.
This will enable an easy way to detect on client side which standalone mods has been installed on the device.

## Compiling your standalone mode
Once all this is done, you and others can now easily compile different standalone modes by just selecting one of the standalone modes in `common/Makefile.hal`, e.g.:

```
PLATFORM_DEFS += -DWITH_STANDALONE_HF_COLIN
```
