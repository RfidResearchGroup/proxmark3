<a id="top"></a>
# Proxmark 3 on Android
## Table of Contents
  * [ Requirements ](#requirements)
  * [ Notes ](#notes)
  * [ Tested setups ](#tested-setups)
    * OnePlus 5 (arm64, USB-C)
    * Nexus 5X (arm64, USB-C)
    * Xiaomi Mi Mix 2S (arm64, USB-C)
    * OnePlus 5T (arm64, USB-C)
    * Samsung Galaxy Tab S2 (arm64, MicroUSB)
  * [ Setup ](#setup)
    * [ Setting up Termux ](#setting-up-termux)
    * [ Install Proxmark3 package ](#install-proxmark3-package)
    * [ USB_ACM ](#usb_acm)
    * [ Enable the driver ](#enable-the-driver)
    * [ Building the kernel ](#building-the-kernel)
    * [ Flashing the kernel ](#flashing-the-kernel)
  * [ Testing ](#testing)
  * [ Troubleshooting ](#troubleshooting)

## Requirements
^[Top](#top)

- Android phone
- Kernel with one of:
    - USB_ACM driver
    - module loading enabled
    - published sources
- Root
- [Termux](https://play.google.com/store/apps/details?id=com.termux)

## Notes
^[Top](#top)
From official Proxmark3 wiki:
 > In any case, you would need a USB-C to A or USB-OTG cable to connect Proxmark3 to your Android device. Some Android devices may not supply enough power (USB-OTG = 100mA), and need a USB Y-cable and external battery, otherwise they will get strange failures.
ref : https://github.com/Proxmark/proxmark3/wiki/android

## Tested setups
^[Top](#top)

- OnePlus 5 (arm64, USB-C)

  - [OmniROM (Android 9)](https://www.omnirom.org/)
  - [OmniROM kernel](https://www.omnirom.org/)
  - [Magisk 19.3](https://github.com/topjohnwu/Magisk/)

- Nexus 5X (arm64, USB-C)

  - [LineageOS (Android 8.1)](https://download.lineageos.org/)
  - [LineageOS kernel](https://download.lineageos.org/)
  - [Magisk 19.3](https://github.com/topjohnwu/Magisk/)
  
- Xiaomi Mi Mix 2S (arm64, USB-C)
  - [LineageOS (Android 9.0)](https://download.lineageos.org/)
  - [Magisk 20.3](https://github.com/topjohnwu/Magisk/)
  
- OnePlus 5T (arm64, USB-C)
  - [LineageOS (Android 9.0)](https://download.lineageos.org/)
  - [Franko Kernel](https://franco-lnx.net/)
  - [Magisk 20.3](https://github.com/topjohnwu/Magisk/)
  
- Samsung Galaxy Tab S2 (arm64, MicroUSB)
  - [LineageOS (Android 9.0)](https://download.lineageos.org/)
  - [LineageOS kernel](https://download.lineageos.org/)
  - [Magisk 20.3](https://github.com/topjohnwu/Magisk/)



## Setup
^[Top](#top)

### Setting up Termux
^[Top](#top)

Install [Termux](https://play.google.com/store/apps/details?id=com.termux) and start it


### Install Proxmark3 package
^[Top](#top)

Run the following commands:
```
pkg install proxmark3 tsu
```
### Optional: Building Proxmark3 client from source
```
pkg install make clang clang++ readline libc++ git tsu
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark
make clean && make client
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
