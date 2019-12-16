Some notes on how to reflash a bricked Proxmark3 over JTAG.

# Linux and OpenOCD

## Using RDV4 scripts

The RDV4 repository contains helper scripts for JTAG flashing.

* Get OpenOCD, e.g.: `apt-get install openocd`
* Create `tools/jtag_openocd/openocd_configuration` by copying [`tools/jtag_openocd/openocd_configuration.sample`](/tools/jtag_openocd/openocd_configuration.sample)
* Tune it to fit your JTAG tool: adapt `CONFIG_IF` to refer to the `interface-*.cfg` file corresponding to your JTAG tool. By default `openocd_configuration.sample` is set up to work with the J-Link.
* Wire the Proxmark3 to the JTAG tool. How to do it depends on the tool. See below for examples. **Warning:** don't plug the Proxmark3 on USB if the tool delivers already the voltage to the Proxmark3, which is most probably the case.
* Then just run

```
cd tools/jtag_openocd/
./openocd_flash_recovery.sh
```

In some rare situations, flashing the full image over JTAG may fail but the bootloader could be fixed. If it's the case, you can flash the image without JTAG by booting on your fresh bootloader (possibly forced by pressing the Proxmark3 button).

For advanced usages there are also `openocd_flash_dump.sh` for dumping the content of the Proxmark3 and `openocd_interactive.sh` for an OpenOCD console.

## RDV4 pinout

The RDV4 JTAG header is quite smaller compared to other Proxmark3 platforms.  
If you're using a J-Link, there is a [convenient adapter](https://github.com/RfidResearchGroup/proxmark3/wiki/Tools#jtag-adapter) made by Proxgrind.  
You can also make yours with some 1.27mm headers (look for `1.27mm header` on Aliexpress) or Pogo pins.

## JLink pinout

J-Link [pinout](https://www.segger.com/interface-description.html):

```
  ---------  ---------
 |1917151311 9 7 5 3 1|
 |201816141210 8 6 4 2|
  --------------------
```

PM3 | JLink
--- | -----
TMS | 7
TDI | 5
TDO |13
TCK | 9
GND | 6
3.3 | 2

## Raspberry Pi pinout

RPi [pinout](https://pinout.xyz/):

PM3 | RPi
--- | -----
TMS | 22
TDI | 19
TDO | 21
TCK | 23
GND | 6
3.3 | 1

## Third party notes on using a BusPirate

* https://github.com/Proxmark/proxmark3/wiki/Debricking-Proxmark3-with-buspirate
* https://b4cktr4ck2.github.io/De-Brickify-Pm3-RDV2/
* https://scund00r.com/all/rfid/2018/05/18/debrick-proxmark.html
* https://joanbono.github.io/PoC/Flashing_Proxmark3.html

## Third party notes on using a J-Link

* http://wiki.yobi.be/wiki/Proxmark

## Third party notes on using a RaspBerry Pi

* http://www.lucasoldi.com/2017/01/17/unbrick-proxmark3-with-a-raspberry-pi-and-openocd/

## Third party notes on using a J-Link on Windows

* https://github.com/Proxmark/proxmark3/wiki/De-Bricking-Segger
