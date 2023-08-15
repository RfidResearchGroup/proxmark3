<a id="top"></a>

# WSL2 Installation instructions

## Table of Contents
- [WSL2 Installation instructions](#wsl2-installation-instructions)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Install Kali Linux distribution](#install-kali-linux-distribution)
  - [Driver installation (Windows 11)](#driver-installation-windows-11)
  - [USBIPD hints](#usbipd-hints)
  - [WSL2 / Kali Linux Installation](#wsl2--kali-linux-installation)
  - [X Server Installation](#x-server-installation)
  - [Clone the Iceman repository](#clone-the-iceman-repository)
  - [Compile the project](#compile-the-project)
  - [Install the udev rules](#install-the-udev-rules)
  - [Inform udev that it really, really should work](#inform-udev-that-it-really-really-should-work)
  - [Verify Device Exists](#verify-device-exists)
  - [Using the client...](#using-the-client)
  - [Done!](#done)

This provides instructions on how to install, build, and use Proxmark3
on Windows 11, using WSL2 (and Kali Linux).

## Requirements
^[Top](#top)

This WSL 2 method requires Windows 11 (Build 22000 or later),
WSL installed and [set to WSL2](https://learn.microsoft.com/en-us/windows/wsl/basic-commands#set-wsl-version-to-1-or-2),

While WSL 2 does not itself support passing through USB or
serial devices, it can work by using the USB/IP open-source
project, [`usbipd-win`](https://github.com/dorssel/usbipd-win).


## Install Kali Linux distribution
^[Top](#top)

Open the Windows App Store, and install Kali Linux.

For WSL configuration, see [Manage and configure Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/wsl-config).

Start the Kali Linux distribution at least once, to ensure it's fully installed.

## Driver installation (Windows 11)
^[Top](#top)

On the Windows (host) machine, install the
[latest release](https://github.com/dorssel/usbipd-win/releases)
of `usbpid-win` (typically an `.MSI` file).

## USBIPD hints
^[Top](#top)

This is *NOT* intended to be a full description of how to use USBIPD.
Rather, this is intended only to give a starting point, as ***the values
shown here are extremely likely to differ per machine***.

It's presumed that you've already installed USBIPD.  Plug the Proxmark
device into a USB port.  Then, from a `cmd.exe` or `wt.exe` ***launched
with administrative permissions***:

Get a list of attached devices.  Example (NOTE: VID/PID for non-proxmark devices redacted)

```cmd
C:\qwert> usbipd list

Connected:
BUSID  VID:PID    DEVICE                                                        STATE
1-2    xxxx:xxxx  USB Input Device                                              Not shared
2-3    xxxx:xxxx  USB Mass Storage Device                                       Not shared
5-3    9ac4:4b8f  USB Serial Device (COM31)                                     Not shared

Persisted:
GUID                                  DEVICE
```

Take note of the `BUSID` for the proxmark device, which should show as a USB Serial Device.

Setup that bus ID to always be redirected to the WSL distribution named `kali-linux`:

```cmd
C:\qwert> usbipd wsl attach --busid 5-3 --distribution kali-linux --auto-attach
usbipd: info: Starting endless attach loop; press Ctrl+C to quit.
Attached
```

NOTE: You must leave that running in the background, to allow the device to automatically
re-attach to the WSL2 instance.



## WSL2 / Kali Linux Installation
^[Top](#top)

Start the Kali Linux distribution you installed.  First, make sure
the distribution is up-to-date:

```sh
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get auto-remove -y
```

then, install proxmark dependencies:

```sh
sudo apt-get install --no-install-recommends \
  git ca-certificates build-essential pkg-config \
  libreadline-dev gcc-arm-none-eabi libnewlib-dev \
  libbz2-dev liblz4-dev libpython3-dev qtbase5-dev libssl-dev
```

_note_
If you don't need the graphical components of the Proxmark3 client, you can skip the installation of `qtbase5-dev`.  
If you don't need support for Python3 scripts in the Proxmark3 client, you can skip the installation of `libpython3-dev`.

## X Server Installation
^[Top](#top)

TBD -- Installing [`Win-KeX`](https://www.kali.org/docs/wsl/win-kex/) has worked
to provide a fully integrated experience, with three distinct modes.....
However, WSL2 may have some functionality already built-in?

## Clone the Iceman repository
^[Top](#top)

```sh
cd ~/
git clone https://github.com/RfidResearchGroup/proxmark3.git
```

## Compile the project
^[Top](#top)

```sh
cd ~/proxmark3
make clean && make -j
```

## Install the udev rules

```sh
sudo make accessrights
sudo make udev
```

On Kali, the above does two things:
1. Ensures the user is a member of the `dialout` group
2. Copies the `./driver/77-pm3-usb-device-blacklist.rules` file to the `/etc/udev/rules.d/` directory

This presumes that the file includes `MODE="660" GROUP="dialout"` at the end of the three match lines.
The goal is that Kali Linux will automatically apply the proper permissions when the device is attached.

However, it may be necessary to give the `udev` service a kind reminder:

## Inform udev that it really, really should work

As of August 2023, the following needs to be done anytime the WSL2 subsystem
has been restarted (e.g., host machine reboot, first WSL2 console window, etc.).
Otherwise, it appears that `udev` service will not see the arrival of devices,
and therefore won't modify permissions on `/dev/ttyACM*` devices.

After this is run once, `udev` appears to work correctly (at least until the
host machine reboots or the last WSL console window is closed for a while).
One workaround is to simply ensure you keep at least one WSL2 console open.

```sh
sudo service udev restart
sudo udevadm trigger --action=change
```

## Verify Device Exists

Verify the device exists, and has a symbolic link created:

```sh
ls -lFA /dev/ttyACM*
ls -lFA /dev/pm3*
```


The first should show the `rw` permissions for both owner
and group, and show the group as `dialout`:

```sh
┌──(qwert㉿host)-[~]
└─$ ls -lFA /dev/ttyACM*
crw-rw---- 1 root dialout 166, 0 Jan 22 11:28 /dev/ttyACM0
```

The second command should show that a symbolic link exists
from the friendly name `/dev/pm3-0` to the TTY device:

```sh
┌──(qwert㉿host)-[~]
└─$ ls -lFA /dev/pm3*
lrwxrwxrwx 1 root root 7 Jan 17 19:46 /dev/pm3-0 -> ttyACM0
```

## Using the client...

```sh
┌──(qwert㉿host)-[~]
└─$ pushd ~/proxmark3

┌──(qwert㉿host)-[~]
└─$ ./pm3
```

## Done!
^[Top](#top)

Full [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md) may be helpful.

