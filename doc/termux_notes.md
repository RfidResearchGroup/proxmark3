# Proxmark 3 on Android
<a id="top"></a>

## Table of Contents
  * [ Requirements ](#requirements)
  * [ Notes ](#notes)
  * [ Setup ](#setup)
    * [ Setting up Termux ](#setting-up-termux)
    * [ Install Proxmark3 package ](#install-proxmark3-package)
  * [ PC-like method ](#pc-like-method)
    * [ Specific requirements ](#specific-requirements)
    * [ USB_ACM ](#usb_acm)
      * [ Enable the driver ](#enable-the-driver)
      * [ Building the kernel ](#building-the-kernel)
      * [ Flashing the kernel ](#flashing-the-kernel)
      * [ Testing ](#testing)
      * [ Troubleshooting ](#troubleshooting)
  * [ TCP bridge method ](#tcp-bridge-method)
    * [ USB connection ](#usb-connection)
      * [ USB-UART bridge application ](#usb-uart-bridge-application)
    * [ Bluetooth connection ](#bluetooth-connection)
      * [ BT-UART bridge application ](#bt-uart-bridge-application)
    * [ TCP connection ](#tcp-connection)
    * [Troubleshooting](#troubleshooting-1)
      * [BTADDON Missing in Firmware of PM3](#btaddon-missing-in-firmware-of-pm3)
  * [Compiling and Flashing a Proxmark3 Firmware from non-root Android](#compiling-and-flashing-a-proxmark3-firmware-from-non-root-android)
    * [Compiling the Proxmark3 Firmware](#compiling-the-proxmark3-firmware)
    * [Flashing the Proxmark3 Firmware](#flashing-the-proxmark3-firmware)
## Requirements
^[Top](#top)

- Android phone
- [F-Droid](https://f-droid.org/)
- [Termux](https://f-droid.org/en/packages/com.termux/)
- [Proxmark3 RDV4](https://www.proxmark.com/proxmark-3-hardware/proxmark-3-rdv4)
- [Blueshark Standalone Module](https://www.proxmark.com/proxmark-news/proxmark3-blueshark-bluetooth-released) **(ONLY if using Bluetooth)**
- [Proxmark with BTADDON compiled Firmware](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md#platform_extras) **(ONLY if using Bluetooth)**


## Notes
^[Top](#top)
From official Proxmark3 wiki:
 > In any case, you would need a USB-C to A or USB-OTG cable to connect Proxmark3 to your Android device. Some Android devices may not supply enough power (USB-OTG = 100mA), and need a USB Y-cable and external battery, otherwise they will get strange failures.
ref : https://github.com/Proxmark/proxmark3/wiki/android

## Setup
^[Top](#top)

### Setting up Termux
^[Top](#top)

Use [F-Droid](https://f-droid.org/) to install [Termux](https://f-droid.org/en/packages/com.termux/) and start it.

It is recommended to use the F-Droid version of Termux as it will be the latest. The [Play Store version](https://play.google.com/store/apps/details?id=com.termux) is not maintained (as stated in the description: "Updates over Google Play [are] currently halted due to technical reasons").

### Install Proxmark3 package which follows tagged releases
^[Top](#top)

Run the following commands:
```
pkg install proxmark3
```
### Optional: Install Proxmark3 package which offers a more up to date version from git `master` branch
Run the following commands:
```
pkg install proxmark3-git
```
### Optional: Building Proxmark3 client from source
```
pkg install make clang readline libc++ git binutils
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
make clean && make client
```

## PC-like method
^[Top](#top)

### Specific requirements
^[Top](#top)

- Kernel with one of:
    - USB_ACM driver
    - module loading enabled
    - published sources
- Root

termux shell:
```
pkg install tsu
```

### USB_ACM
^[Top](#top)

You need the `USB_ACM` driver enabled and working to communicate with the Proxmark3. To see if it's working, run `tsudo ls /dev/tty*` and it should list `/dev/ttyACM0` (or similar). If you see this, congratulations, skip this step!

#### Enable the driver
^[Top](#top)

If  your kernel has module loading enabled, you should be able to build the module separately and load it on your system without any changes. Otherwise, grab your kernel sources and edit your build config to include `CONFIG_USB_ACM=y`. On the tested kernel, this was under: `android_kernel_oneplus_msm8998/arch/arm64/configs/omni_oneplus5_defconfig`

#### Building the kernel
^[Top](#top)

If using a custom kernel, refer to the build instructions provided by its maintainer. Otherwise, follow the standard Linux kernel build procedure

#### Flashing the kernel
^[Top](#top)

You can flash the kernel however it suits you. On the tested device, this was achieved using [TWRP](https://twrp.me/), the most popular custom recovery

#### Testing
^[Top](#top)

Open Termux and start the Proxmark3 client:
```
tsudo proxmark3/client/proxmark3 /dev/ttyACM0
```
Everything should work just like if it was your PC!

#### Troubleshooting
^[Top](#top)

- `dmesg | grep usb` - useful debug info
- `/proc/config.gz` - contains your kernel's build configuration. Look for `CONFIG_USB_ACM`, which should be enabled

## TCP bridge method
^[Top](#top)

Termux doesn't come with usb serial neither bluetooth serial drivers.
However, it is fully integrated with phone's network, so we need to talk to the proxmark using serial to tcp sockets (carried out by android apps).

### USB connection
^[Top](#top)

#### USB-UART Bridge Application
^[Top](#top)

Install [this free TCPUART app](https://play.google.com/store/apps/details?id=com.hardcodedjoy.tcpuart) on the Play Store

The app lets you choose the baudrate. Default value (115 200 baud) is fine.
Plug the PM3 in and click connect.
Set the toggle in server mode and choose a random port not used by system (e.g. 4321) and start the server.

Alternatively, use the [paid version of the BT/USB/TCP Bridge app](https://play.google.com/store/apps/details?id=masar.bluetoothbridge.pro) which includes USB bridge as well.

In this app, select TCP server as 'Device A' and choose an unused port (e.g. 4321).
Choose your registered PM3 device as 'Device B' -> 'Connect to USB device'.
Ensure 'Retransmission' is set to 'both ways'.
It is possible to record the config as autostart, cf 'Settings' -> 'Autostart setting'.

### Bluetooth connection
^[Top](#top)

#### BT-UART Bridge Application
^[Top](#top)

Install [this free app](https://play.google.com/store/apps/details?id=masar.bb) or [the paid version](https://play.google.com/store/apps/details?id=masar.bluetoothbridge.pro) (which includes usb bridge)

You need to pair the proxmark3 in the Android settings.
In the app, select TCP server as 'Device A' and choose an unused port (e.g. 4321).
Choose your registered PM3 device as 'Device B' -> 'Connect to classic Bluetooth device'.
Ensure 'Retransmission' is set to 'both ways'.
It is possible to record the config as autostart, cf 'Settings' -> 'Autostart setting'.

### TCP connection
^[Top](#top)

Start a new session, then:
```
proxmark3 tcp:localhost:<chosenPort>
```
Alternatively, if you have made the client in the git repo:
```
./client/proxmark3 tcp:localhost:<chosenPort>
```
### Troubleshooting
^[Top](#top)

#### BTADDON Missing in Firmware of PM3
^[Top](#top)

1. Phone and pm3 are connected, blue led is on and *not* blinking
2. BTUART Tool TCP Server at Port 4321 
3. Using proxmark3 in termux shows the following error message:
```
$ proxmark3 tcp:localhost:4321

[=] Session log /data/data/com.termux/files/home/.suroot /.proxmark3/log_20210519.txt

[=] Loading Preferences...

[+] loaded from JSON file /data/data/com.termux/files/ho me/.suroot/.proxmark3/preferences.json

Using UART port tcp:localhost:4321

[!!] ERROR: cannot communicate with the Proxmark
```
Solution:  

Make sure you have installed a firmware with BTADDON compiled. 
See: https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md#platform_extras  

## Compiling and Flashing a Proxmark3 Firmware from non-root Android

READ ME:
* If you can compile and flash your device from a PC, do it! It's probably much confortable than following this method.
* Flashing is possible only via USB-UART, *not* via BT-UART
* Avoid flashing the Bootloader from non-root Android as the connection is probably less stable than with pure USB and you don't want to brick your device...

### Compiling the Proxmark3 Firmware

Assuming we're using the Github repo sources as explained above.

```
pkg install make clang readline libc++ git binutils
cd
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
make clean && make -j client
```

Termux doesn't have the ARM cross-compiler, so we'll install a Debian within Termux.

```
$ pkg install proot-distro
$ proot-distro install debian
$ proot-distro login debian --termux-home
```
At this point we should be on a Debian root prompt in the user directory. We install only the requirements to compile the Proxmark3 firmware.
```
# apt-get update
# apt-get install -y --no-install-recommends make gcc g++ libc6-dev gcc-arm-none-eabi libnewlib-dev
# cd proxmark3
# make -j fullimage
# exit
```
At this point we're back to the Termux prompt.

### Flashing the Proxmark3 Firmware

Plug the Proxmark3 while pressing the button, to enter into bootloader mode manually.

Activate the USB-UART to TCP Bridge with one of the applications as explained above.

```
cd proxmark3
./client/proxmark3 tcp:localhost:<chosenPort> --flash --image armsrc/obj/fullimage.elf
```
Once the Proxmark3 has rebooted, reconnect it to the bridge in the app.
The freshly flashed device is now ready to be used.

```
./client/proxmark3 tcp:localhost:<chosenPort>
```
