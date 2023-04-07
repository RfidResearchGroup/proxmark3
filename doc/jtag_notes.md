# Notes on JTAG
<a id="top"></a>

Some notes on how to reflash a bricked Proxmark3 over JTAG.

# Table of Contents
- [Notes on JTAG](#notes-on-jtag)
- [Table of Contents](#table-of-contents)
- [Linux and OpenOCD](#linux-and-openocd)
  - [Using RDV4 scripts](#using-rdv4-scripts)
  - [RDV4 pinout](#rdv4-pinout)
  - [JLink pinout](#jlink-pinout)
  - [Raspberry Pi pinout](#raspberry-pi-pinout)
- [Where to find more information?](#where-to-find-more-information)
  - [Third party notes on using a BusPirate](#third-party-notes-on-using-a-buspirate)
  - [Third party notes on using a J-Link](#third-party-notes-on-using-a-j-link)
  - [Third party notes on using a RaspBerry Pi](#third-party-notes-on-using-a-raspberry-pi)
  - [Third party notes on using a J-Link on Windows](#third-party-notes-on-using-a-j-link-on-windows)
  - [Stack Overflow write up article.](#stack-overflow-write-up-article)
  - [Old original docs](#old-original-docs)



# Linux and OpenOCD
^[Top](#top)

## Using RDV4 scripts
^[Top](#top)

The RDV4 repository contains helper scripts for JTAG flashing.

* Get OpenOCD, e.g.: `apt-get install openocd`
* Create `tools/jtag_openocd/openocd_configuration` by copying [`tools/jtag_openocd/openocd_configuration.sample`](/tools/jtag_openocd/openocd_configuration.sample)
* Tune it to fit your JTAG tool: adapt `CONFIG_IF` to refer to your JTAG tool. `openocd_configuration.sample` contains several examples and is set up by default to work with the J-Link.
* Wire the Proxmark3 to the JTAG tool. How to do it depends on the tool. See below for examples. **Warning:** don't plug the Proxmark3 on USB if the tool delivers already the voltage to the Proxmark3, which is most probably the case.
* Then just run

```
cd tools/jtag_openocd/
./openocd_flash_recovery.sh
```

In some rare situations, flashing the full image over JTAG may fail but the bootloader could be fixed. If it's the case, you can flash the image without JTAG by booting on your fresh bootloader (possibly forced by pressing the Proxmark3 button).

For advanced usages there are also `openocd_flash_dump.sh` for dumping the content of the Proxmark3 and `openocd_interactive.sh` for an OpenOCD console.

## RDV4 pinout
^[Top](#top)

The RDV4 JTAG header is quite smaller compared to other Proxmark3 platforms.  
If you're using a J-Link, there is a [convenient adapter](https://github.com/RfidResearchGroup/proxmark3/wiki/Tools#jtag-adapter) made by Proxgrind.  
You can also make yours with some 1.27mm headers (look for `1.27mm header` on Aliexpress) or Pogo pins or buy an already made clip, e.g. search `dykb clamp` on Aliexpress and take a 1.27mm single-row 6P version.

## JLink pinout
^[Top](#top)

J-Link [pinout](https://www.segger.com/interface-description.html):

```
Pin cut-out on a JLink 20 pin connector

                ^^
  --------------  ---------
 |19 17 15 13 11  9 7 5 3 1|
 |20 18 16 14 12 10 8 6 4 2|
  -------------------------
```

``` 
Map of pins between PM3 / JLink 

PM3 | JLink
--- | -----
TMS |  7
TDI |  5
TDO | 13
TCK |  9
GND |  6
3.3 |  2
```

## Raspberry Pi pinout
^[Top](#top)

RPi [pinout](https://pinout.xyz/):

```
PM3 | RPi
--- | ---
TMS | 22
TDI | 19
TDO | 21
TCK | 23
GND |  6
3.3 |  1
```

# Where to find more information?
^[Top](#top)

There has been lots of articles and blogposts about recovering, debricking, JTAG your Proxmark3 and you find here below an assortiment of resources that will be of help.

## Third party notes on using a BusPirate
^[Top](#top)

* https://github.com/Proxmark/proxmark3/wiki/Debricking-Proxmark3-with-buspirate
* https://b4cktr4ck2.github.io/De-Brickify-Pm3-RDV2/
* https://scund00r.com/all/rfid/2018/05/18/debrick-proxmark.html
* https://joanbono.github.io/PoC/Flashing_Proxmark3.html

## Third party notes on using a J-Link
^[Top](#top)

* http://wiki.yobi.be/wiki/Proxmark

## Third party notes on using a RaspBerry Pi
^[Top](#top)

* http://www.lucasoldi.com/2017/01/17/unbrick-proxmark3-with-a-raspberry-pi-and-openocd/
* https://wiki.elvis.science/index.php?title=Proxmark3:_Debricking
* https://github.com/synthetos/PiOCD/wiki/Using-a-Raspberry-Pi-as-a-JTAG-Dongle

## Third party notes on using a J-Link on Windows
^[Top](#top)

* https://github.com/Proxmark/proxmark3/wiki/De-Bricking-Segger

## Stack Overflow write up article.
^[Top](#top)

https://stackoverflow.com/questions/48794076/error-halt-timed-out-wake-up-gdb/64291913#64291913

## Old original docs
^[Top](#top)

Describes the SEGGER JLINK, JTAG process but be warned,  this document is old.
https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/original_proxmark3/Compiling%20Proxmark%20source%20and%20firmware%20upgrading%20v1.pdf
