<a id="Top"></a>

# iOS Installation Instructions

# Table of Contents
- [iOS Installation Instructions](#ios-installation-instructions)
- [Table of Contents](#table-of-contents)
- [Install the required dependencies](#install-the-required-dependencies)
  - [On Bingner bootstrap](#on-bingner-bootstrap)
  - [On Procursus bootstrap](#on-procursus-bootstrap)
  - [Patched SDK and additional patches](#patched-sdk-and-additional-patches)
- [Clone the Iceman repository](#clone-the-iceman-repository)
- [Compile and use the project](#compile-and-use-the-project)
  - [bootrom, fullimage, and recovery](#bootrom-fullimage-and-recovery)
  - [make install](#make-install)
  - [usbselfserial](#usbselfserial)

# Install the required dependencies
^[Top](#top)

If you are using unc0ver or checkra1n, see [On Bingner bootstrap](#on-bingner-bootstrap)
Otherwise, see [On Procursus bootstrap](#on-procursus-bootstrap)
Note: compilation has not yet been attempted on Procursus' bootstrap or on rootless. Attempt at your own peril.

## On Bingner bootstrap
^[Top](#top)

Run this as `root`, as sudo isn't installed by default. The default password is `alpine`.
```sh
apt install git make clang odcctools gawk sudo pkg-config python3.7 libpython3.7-dev
```
Furthermore, if you're trying to build from git instead of a release, you'll need SWIG from [The-SamminAter's repo](https://the-samminater.github.io/repo).

## On Procursus bootstrap
^[Top](#top)

Currently, you're on your own. Most of the packages should be named similarly, but sometimes Procursus packages up components differently than bingner. Furthermore, if you're using a rootless jailbreak and want to build from git, you'll likely have to port over SWIG yourself.

## Patched SDK and additional patches
^[Top](#top)

1. Git clone [theos/sdks](https://github.com/theos/sdks) and symlink or move the target version (tested with 13.7, others should work) to `/usr/share/SDKs/iPhoneOS.sdk`.
2. Delete `__IOS_PROHIBITED` from line 188 of `iPhoneOS.sdk/usr/include/stdlib.h`
3. Git clone [theos/headers](https://github.com/theos/headers) and move `headers/openssl` to `iPhoneOS.sdk/usr/include/`
4. Download the latest macOS SDK from [phracker/MacOSX-SDKs](https://github.com/phracker/MacOSX-SDKs/releases/latest) (tested with 11.3) and move `MacOSX.sdk/System/Library/Frameworks/OpenCL.framework` and `OpenGL.framework` to `iPhoneOS.sdk/System/Library/Frameworks/`

Note: when compiling hitag2crack/crack5opencl, the following warning is to be expected:
```
ld: warning: building for iOS, but linking in .tbd file (/usr/share/SDKs/iPhoneOS.sdk/System/Library/Frameworks//OpenCL.framework/OpenCL.tbd) built for macOS
```

# Clone the Iceman repository
^[Top](#top)

```sh
git clone https://github.com/RfidResearchGroup/proxmark3.git
```

# Compile and use the project
^[Top](#top)

Now you're ready to (mostly) follow the [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md).

## bootrom, fullimage, and recovery
^[Top](#top)

Because there's no arm-none-eabi-gcc (or objcopy) for iOS, you'll have to build these components on a different operating system. The files and directories you'll need to copy over from a desktop build to iOS are `armsrc/fpga_version_info.c`, `armsrc/obj/`, `bootrom/version_pm3.c`, `bootrom/obj/`, and lastly `recovery/`. Everything else will build successfully, but `make all` and `make install` will fail without them.

## make install
^[Top](#top)

Because of the lack of arm-none-eabi-gcc (and objcopy), to successfully run `make all` and/or `make install` you'll have to create the following scripts as a workaround.

`/usr/local/bin/arm-none-eabi-gcc` and `arm-none-eabi-objcopy`

```bash
#!/bin/bash
#This exists just to trick proxmark3 into making the fullimage, bootrom, and recovery
#Don't worry about it
cc --version
echo "Arguments: $@"
```

With those in place, `make all` and `make install` will run flawlessly.

## usbselfserial
^[Top](#top)

As iOS doesn't support USB-CDC ACM, you'll need to use [usbselfserial](https://github.com/lotuspar/usbselfserial). A compiled binary can be found at [The-SamminAter's repo](https://the-samminater.github.io/repo).

Once the proxmark is connected to your iOS device via a USB adapter, run `usbselfserial -v 0x9ac4 -p 0x4b8f --driver cdcacm -o /tmp/tty.usbmodemiceman1` (for devices other than the PM3 Easy, adjust the identifiers accordingly). If proxmark3 can't communicate with the device, try providing the port as an argument, or run `sudo killall usbmuxd`.

Lastly, it may also be helpful to modify `pm3` as follows, to automatically select the right port:

```bash
function get_pm3_list_macOS {
    N=$1
    #PM3LIST=()
    PM3LIST=(/tmp/tty.usbmodemiceman1) #<-- our addition
    for DEV in $(ioreg -r -c "IOUSBHostDevice" -l | awk -F '"' '
        $2=="USB Vendor Name"{b=($4=="proxmark.org")}
        b==1 && $2=="IODialinDevice"{print $4}'); do
        PM3LIST+=("$DEV")
        if [ ${#PM3LIST[*]} -ge "$N" ]; then
            return
        fi
    done
}
```
