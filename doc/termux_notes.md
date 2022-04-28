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
    * [ Termux connection ](#termux-connection)

## Requirements
^[Top](#top)

- Android phone
- [Termux](https://play.google.com/store/apps/details?id=com.termux)
- Proxmark3 RDV4 (https://www.proxmark.com/proxmark-3-hardware/proxmark-3-rdv4)
- Blueshark Standalone Module (Bluetooth ONLY) (https://www.proxmark.com/proxmark-news/proxmark3-blueshark-bluetooth-released)
- Proxmark with BTADDON compiled Firmware (Bluetooth ONLY) (https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md#platform_extras)


## Notes
^[Top](#top)
From official Proxmark3 wiki:
 > In any case, you would need a USB-C to A or USB-OTG cable to connect Proxmark3 to your Android device. Some Android devices may not supply enough power (USB-OTG = 100mA), and need a USB Y-cable and external battery, otherwise they will get strange failures.
ref : https://github.com/Proxmark/proxmark3/wiki/android

## Setup
^[Top](#top)

### Setting up Termux
^[Top](#top)

Install [Termux](https://f-droid.org/en/packages/com.termux/) and start it


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

### Testing
^[Top](#top)

Open Termux and start the Proxmark3 client:
```
tsudo proxmark3/client/proxmark3 /dev/ttyACM0
```
Everything should work just like if it was your PC!

### Troubleshooting
^[Top](#top)

- `dmesg | grep usb` - useful debug info
- `/proc/config.gz` - contains your kernel's build configuration. Look for `CONFIG_USB_ACM`, which should be enabled

## TCP bridge method
^[Top](#top)

Termux doesn't come with usb serial neither bluetooth serial drivers.
However, it is fully integrated with phone's network, so we need to talk to the proxmark using serial to tcp sockets (carried out by android apps).

### USB connection
^[Top](#top)

### USB-UART Bridge Application
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

### BT-UART Bridge Application
^[Top](#top)

Install [this free app](https://play.google.com/store/apps/details?id=masar.bb) or [the paid version](https://play.google.com/store/apps/details?id=masar.bluetoothbridge.pro) (which includes usb bridge)

You need to pair the proxmark3 in the Android settings.
In the app, select TCP server as 'Device A' and choose an unused port (e.g. 4321).
Choose your registered PM3 device as 'Device B' -> 'Connect to classic Bluetooth device'.
Ensure 'Retransmission' is set to 'both ways'.
It is possible to record the config as autostart, cf 'Settings' -> 'Autostart setting'.

### Termux connection
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

