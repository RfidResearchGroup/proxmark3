# Proxmark 3 on Android

## Requirements
- Android phone
- Kernel with one of:
    - USB_ACM driver
    - module loading enabled
    - published sources
- Root
- [Termux](https://play.google.com/store/apps/details?id=com.termux)

## Notes
From official Proxmark3 wiki:
 > In any case, you would need a USB-C to A or USB-OTG cable to connect Proxmark3 to your Android device. Some Android devices may not supply enough power (USB-OTG = 100mA), and need a USB Y-cable and external battery, otherwise they will get strange failures.
ref : https://github.com/Proxmark/proxmark3/wiki/android

## Tested setup
- OnePlus 5 (arm64, USB-C)
- [OmniROM (Android 9)](https://www.omnirom.org/)
- [OmniROM kernel](https://www.omnirom.org/)
- [Magisk 19.3](https://github.com/topjohnwu/Magisk/)
- [Nexus 5X] (arm64, USB-C)
- [LineageOS (Android 8.1)](https://download.lineageos.org/)
- [LineageOS kernel](https://download.lineageos.org/)
- [Magisk 19.3](https://github.com/topjohnwu/Magisk/)

## Setup
### Getting ncurses with termcap
You need `termcap` to build the Proxmark3 client. Unfortunately, the prebuilt `ncurses` package does not include it. Since [this PR](https://github.com/termux/termux-packages/pull/2131) hasn't been merged yet, you will have to build `ncurses` yourself

1. Clone the [termux-packages](https://github.com/termux/termux-packages) repo
2. Apply [the PR](https://github.com/termux/termux-packages/pull/2131)
3. Build `ncurses`. Refer to the [build docs](https://github.com/termux/termux-packages/blob/master/docs/BUILD_ENVIRONMENT.md) for more information. The easiest way is to use Docker:
    - `./scripts/run-docker.sh`
    - `./build-package.sh ncurses`
    - the built packages will be under the `debs` directory
4. Copy `ncurses_6.1.x-x_aarch64.deb` to your phone's `/sdcard`
### Setting up Termux
1. Install [Termux](https://play.google.com/store/apps/details?id=com.termux) and start it
2. Run the following commands:
```
pkg install make, clang, clang++, readline-dev, libclang-dev, libc++, git, tsu
termux-setup-storage
dpkg -i /sdcard/ncurses_6.1.x-x_aarch64.deb
git clone https://github.com/RfidResearchGroup/proxmark3.git
```
### Building Proxmark3 client
1. Edit `proxmark3/client/Makefile` and append `-fPIC` to the `CFLAGS` variable (line 30)
2. `make clean && make client`

### USB_ACM
You need the `USB_ACM` driver enabled and working to communicate with the Proxmark3. To see if it's working, run `tsudo ls /dev/tty*` and it should list `/dev/ttyACM0` (or similar). If you see this, congratulations, skip this step!

#### Enable the driver
If  your kernel has module loading enabled, you should be able to build the module separately and load it on your system without any changes. Otherwise, grab your kernel sources and edit your build config to include `CONFIG_USB_ACM=y`. On the tested kernel, this was under: `android_kernel_oneplus_msm8998/arch/arm64/configs/omni_oneplus5_defconfig`

#### Building the kernel
If using a custom kernel, refer to the build instructions provided by its maintainer. Otherwise, follow the standard Linux kernel build procedure

#### Flashing the kernel
You can flash the kernel however it suits you. On the tested device, this was achieved using [TWRP](https://twrp.me/), the most popular custom recovery

### Testing
Open Termux and start the Proxmark3 client:
```
tsudo proxmark3/client/proxmark3 /dev/ttyACM0
```
Everything should work just like if it was your PC!

### Troubleshooting
- `dmesg | grep usb` - useful debug info
- `/proc/config.gz` - contains your kernel's build configuration. Look for `CONFIG_USB_ACM`, which should be enabled
