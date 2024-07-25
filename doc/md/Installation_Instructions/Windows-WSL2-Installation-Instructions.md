<a id="top"></a>

# WSL2 Installation instructions

This provides instructions on how to install, build, and use Proxmark3
on Windows 11, using WSL2 (and Ubuntu Linux).

## Table of Contents
- [WSL2 Installation instructions](#wsl2-installation-instructions)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Install the Linux distribution](#install-the-linux-distribution)
  - [One-time configuration of Windows 11 host](#one-time-configuration-of-windows-11-host)
    - [Install Git with Credential manager](#install-git-with-credential-manager)
    - [Install USBIPD](#install-usbipd)
      - [USBIPD hints](#usbipd-hints)
      - [Get a list of attached devices.](#get-a-list-of-attached-devices)
      - [Bind the device via USBIPD (configure for sharing)](#bind-the-device-via-usbipd-configure-for-sharing)
      - [Attach the shared device to the WSL2 distribution](#attach-the-shared-device-to-the-wsl2-distribution)
  - [One-time configuration of the WSL2 distribution](#one-time-configuration-of-the-wsl2-distribution)
    - [Update / upgrade the distribution](#update--upgrade-the-distribution)
    - [Install stuff needed to build proxmark3 binaries](#install-stuff-needed-to-build-proxmark3-binaries)
    - [Configure source files and first build](#configure-source-files-and-first-build)
      - [Configure git to use credential helper, etc.](#configure-git-to-use-credential-helper-etc)
      - [Clone the Iceman repository](#clone-the-iceman-repository)
      - [Start with a release tag ("known good" version)](#start-with-a-release-tag-known-good-version)
      - [IMPORTANT! -- Setup configuration for your device](#important----setup-configuration-for-your-device)
      - [Compile the project](#compile-the-project)
    - [One-time configuration to fix permissions](#one-time-configuration-to-fix-permissions)
      - [Install the udev rules](#install-the-udev-rules)
      - [Install the udev rules](#install-the-udev-rules-1)
        - [77-pm3-usb-device-blacklist.rules](#77-pm3-usb-device-blacklistrules)
      - [WORKAROUND - Kick udev into action](#workaround---kick-udev-into-action)
  - [Verify Device Exists](#verify-device-exists)
  - [Using the client...](#using-the-client)
  - [Summary of repeated commands](#summary-of-repeated-commands)
  - [Done!](#done)

## Requirements
^[Top](#top)

This WSL 2 method requires Windows 11 (Build 22000 or later),
with WSL installed and [set to WSL2](https://learn.microsoft.com/en-us/windows/wsl/basic-commands#set-wsl-version-to-1-or-2).

While WSL 2 does not itself support passing through USB or
serial devices, it can work by using the USB/IP open-source
project, [`usbipd-win`](https://github.com/dorssel/usbipd-win).


## Install the Linux distribution
^[Top](#top)

Open the Windows App Store, and install Ubuntu Linux.  I used Ubuntu 20.04 when
verifying these instructions.

For general WSL configuration information, see [Manage and configure Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/wsl-config).

Start the Linux distribution at least once, to ensure it's fully installed.

## One-time configuration of Windows 11 host
^[Top](#top)

### Install Git with Credential manager
^[Top](#top)

This is ***not*** required, but is ***highly*** recommended.
It will allow you to use the credential manager to store
your Git credentials more securely, and allow you to avoid
entering your git passwords into the WSL2 distribution.

Details are outside the scope of this file.
See the [Credential Manager docs](https://microsoft.github.io/Git-Credential-Manager-for-Windows/Docs/CredentialManager.html) for more information,
or checkout its [Github page](https://github.com/Microsoft/Git-Credential-Manager-for-Windows).

### Install USBIPD
^[Top](#top)

On the Windows (host) machine, use the Windows Package Manager:

```cmd
winget install usbipd
```

Or alternatively, install the
[latest release](https://github.com/dorssel/usbipd-win/releases)
of `usbpid-win` (typically an `.MSI` file).


#### USBIPD hints
^[Top](#top)

This is *NOT* intended to be a full description of how to use USBIPD.
Rather, this is intended only to give a starting point, as ***the values
shown here are extremely likely to differ per machine***.

It's presumed that you've already installed USBIPD, plugged the Proxmark
device into a USB port, and that it appears in Windows as a COM port.

> [!NOTE]
> **Breaking changes in USBIPD 4.0.0 (released 2023-12-06)**
> 
> * You have to share the device using `usbipd bind --busid <busid>` first.
> * You no longer have to install any client-side tooling.
> * You no longer have to specify a specific distribution.
> * The syntax for the command to attach has changed slightly.

#### Get a list of attached devices.
^[Top](#top)

Note that this command does ***not*** require administrative privileges.

```cmd
C:\qwert> usbipd list

Connected:
BUSID  VID:PID    DEVICE                      STATE
1-2    xxxx:xxxx  USB Input Device            Not shared
2-3    xxxx:xxxx  USB Mass Storage Device     Not shared
7-4    9ac4:4b8f  USB Serial Device (COM60)   Not shared

Persisted:
GUID                                  DEVICE
```

Take note of the `BUSID` for the proxmark device, which should show
as a USB Serial Device.  In the above example, the `BUSID` is `7-4`.
The VID:PID of the proxmark device is going to be one of `9ac4:4b8f`,
`502d:502d`, or `2d2d:504d`.

#### Bind the device via USBIPD (configure for sharing)
^[Top](#top)

This is the ***only*** command that ***does*** require
administrative privileges with USBIPD v4.0.0.  This
must be done once per boot of the host (Windows) machine,
as it configures the device to be shared via USBIPD.

In this example, it is configuring the device attached at
`BUSID` of `7-4`, as that was the proxmark device.  As can
be seen, at least as of v4.0.0, no output is shown on success.

```cmd
C:\qwert>usbipd bind -b 7-4
```

#### Attach the shared device to the WSL2 distribution
^[Top](#top)

Continuing the example, this will attach (and re-attach) the
device with `BUSID` of `7-4` to the WSL2 distributions.

```cmd
C:\qwert> usbipd attach --auto-attach --busid 7-4 --wsl
usbipd: info: Using WSL distribution 'Ubuntu-20.04' to attach; the device will be available in all WSL 2 distributions.
usbipd: info: Using IP address 172.xxx.xxx.1 to reach the host.
usbipd: info: Starting endless attach loop; press Ctrl+C to quit.
WSL Attached
WSL Detached
WSL usbip: error: Attach Request for 7-4 failed - Device not found
WSL Attached
WSL Detached
WSL usbip: error: Attach Request for 7-4 failed - Device not found
WSL Attached
```

NOTE: This example used the `--auto-attach` option to reconnect
the device automatically when it's reset, uplugged/replugged, etc.
While this requires leaving the terminal that run the command
running in the background, it does make updating firmware from
WSL2 much easier.

## One-time configuration of the WSL2 distribution
^[Top](#top)


### Update / upgrade the distribution
^[Top](#top)

Start the Linux distribution you installed.  First, make sure
the distribution is up-to-date.  For example, on Ubuntu:

```sh
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get auto-remove -y
```

### Install stuff needed to build proxmark3 binaries
^[Top](#top)

For example, on Ubuntu:

```sh
sudo apt-get install --no-install-recommends \
  git ca-certificates build-essential pkg-config \
  libreadline-dev gcc-arm-none-eabi libnewlib-dev \
  libbz2-dev liblz4-dev libpython3-dev qtbase5-dev \
  libssl-dev libgd-dev
```

> [!NOTE]
> * If you don't need the graphical components of the
>   Proxmark3 client, you can skip the installation of `qtbase5-dev`.  
> * If you don't need support for Python3 scripts in the
>   Proxmark3 client, you can skip the installation of `libpython3-dev`.
> * If you don't need support for NFC ePaper devices in the
>   PM3 device, you can skip the installation of `libgd-dev`.

### Configure source files and first build
^[Top](#top)


#### Configure git to use credential helper, etc.
^[Top](#top)

```sh
# While optional, reduces new use of 'master' as default branch name.
git config --global init.defaultbranch main
# For example, my two commands would be:
# ... config --global user.name "Henry Gabryjelski"
# ... config --global user.email "henrygab@users.noreply.github.com"
git config --global user.name "Your Name"
git config --global user.email "yourAlias@users.noreply.github.com"
```

If you've installed and setup the Git Credential Manager
in the host Windows 11 machine, configure git to use it,
so you don't have to enter your password into the WSL2
distribution:

```sh
git config --global credential.helper "/mnt/c/Program\ Files/Git/mingw64/bin/git-credential-manager.exe"
```

#### Clone the Iceman repository
^[Top](#top)

```sh
cd ~/
# For example, my command would be:
# ... clone https://github.com/henrygab/proxmark3.git
# If you are using only (will not contribute changes),
# then you could just clone Iceman's repository directly:
# ... clone https://github.com/RfidResearchGroup/proxmark3.git
git clone https://github.com/YourUsernameHere/proxmark3.git
cd ~/proxmark3
git remote add upstream https://github.com/RfidResearchGroup/proxmark3.git
```

#### Start with a release tag ("known good" version)

The following starts you at the release named "Steamboat Willie".
This reduces variables in case your first build doesn't work.

```sh
cd ~/proxmark3
git checkout v4.17768
```

#### IMPORTANT! -- Setup configuration for your device
^[Top](#top)

This can be skipped for RDV4 devices.
For PM3 Easy, it helps to know if your device has the external
flash memory chip.  Most do, but some do not.

As an example, all my PM3 Easy devices have external flash,
and by default, and if I wanted to use the `HF_UNISNIFF`
standalone mode, my final `Makefile.platform` would be:

```
PLATFORM=PM3GENERIC
PLATFORM_EXTRAS=FLASH
STANDALONE=HF_UNISNIFF
# always ensure final line ends in line feed, or comment line
```

Without flash memory (or if not sure it's there), only the
first line of `PLATFORM=PM3GENERIC` is needed for a PM3Easy.

Here are the commands I would use to edit the file using
the `nano` editor:

```
cd ~/proxmark3
cp Makefile.platform.sample Makefile.platform
nano Makefile.platform
REM In nano editor: Ctrl-S to save; Ctrl-X to exit
```

#### Compile the project
^[Top](#top)

Now that the project is configured for your device, it's time
to build the binaries.

```sh
cd ~/proxmark3
make clean
make -j
```

Once completed, you should have a number of executable
files in the `~/proxmark3/` directory:

```sh
$ ls -lFA ~/proxmark3/pm3*
-rwxr-xr-x 1 q q 17849 Jan 28 11:17 /home/q/proxmark3/pm3*
-rwxr-xr-x 1 q q    62 Jan 28 11:17 /home/q/proxmark3/pm3-flash*
-rwxr-xr-x 1 q q    62 Jan 28 11:17 /home/q/proxmark3/pm3-flash-all*
-rwxr-xr-x 1 q q    62 Jan 28 11:17 /home/q/proxmark3/pm3-flash-bootrom*
-rwxr-xr-x 1 q q    62 Jan 28 11:17 /home/q/proxmark3/pm3-flash-fullimage*
```

However, ***they won't work yet***, as you have to configure
permissions for the device first.



### One-time configuration to fix permissions
^[Top](#top)

#### Install the udev rules
^[Top](#top)

Verify the proxmark device is appearing as a TTY device:

```sh
ls -lFA /dev/ttyACM*
crw------- 1 root root 166,  0 Jan 28 12:07 /dev/ttyACM0
```

Note that the permissions above only allow the `root` 
user to access the device.  These next steps adjust the
configuration so that the current user is added to the
`dialout` group, and that when the device appears, it
is automatically configured to permit RWX access by
the `dialout` group.

#### Install the udev rules
^[Top](#top)

```sh
sudo make accessrights
sudo make udev
```

On Ubuntu, the above does two things:
1. Ensures the user is a member of the `dialout` group
2. Copies the `./driver/77-pm3-usb-device-blacklist.rules` file to the `/etc/udev/rules.d/` directory

The file is used when a new device arrives.  Walking through some lines
of the file...

##### 77-pm3-usb-device-blacklist.rules
^[Top](#top)

* `ACTION!="add|change", GOTO="pm3_usb_device_blacklist_end"`
  Having this line first means that the rest of the file is only processed
  when a new device is added or changed.  Any other events are ignored.
* `SUBSYSTEM!="tty", GOTO="pm3_ignore"`
  Having this line as the second ensures that, unless the subsystem is
  `tty` (e.g., COM port), the lines that grant the additional permissions
  are not processed.
* Multiple VID/PID lines, ending with `SYMLINK+="pm3-%n" MODE="660" GROUP="dialout"`
  * The `SYMLINK` portion instructs to creates a symbolic link named `/dev/pm3-0` (or `/dev/pm3-1`, etc.).
  * The `GROUP="dialout"` portion instructs to change the group ownership to the `dialout` group.
  * The `MODE=660` portion instructs to set the permissions to `rw` for the owner (root) and the group (`dialout` per above).

#### WORKAROUND - Kick udev into action
^[Top](#top)

> [!NOTE]
> As of December 2024, the following still needs to be done
> anytime the WSL2 subsystem has been restarted (e.g., host
> machine reboot, first WSL2 console window, first-time config,
> etc.).  Otherwise, it appears that `udev` service will *not*
> see the arrival of devices, and therefore won't modify
> the permissions or group ownership on the `/dev/ttyACM*`.
> 
> The following commands cause `udev` to work correctly...
> at least until the host machine reboots, or the last WSL
> console window is closed for a while, or the WSL2 subsystem
> is updated, or ....
> 
> If you keep at least one WSL2 console open, that appears
> to prevent the WSL subsystem from being shutdown / restarted,
> and thus prevents needing to rerun this command more than
> once per boot:

```sh
sudo service udev restart
sudo udevadm trigger --action=change
```

## Verify Device Exists
^[Top](#top)

Verify the device exists, and has a symbolic link created:

```sh
$ ls -lFA /dev/ttyACM* /dev/pm3*
lrwxrwxrwx 1 root root         7 Jan 28 15:54 /dev/pm3-0 -> ttyACM0
crw-rw---- 1 root dialout 166, 0 Jan 28 15:54 /dev/ttyACM0
```

Specifically, check that each `/dev/ttyACM*` device has
its group set to `dialout`, and that the permissions
show `rw-` for both the owner and the group.
Also verify that each `/dev/pm3*` device is a symbolic link,
and points to the corresponding `/dev/ttyACM*` device.



## Using the client...
^[Top](#top)

Build and flash the client (does not update bootloader):

```sh
cd ~/proxmark3
make clean
make -j
./pm3-flash-all
./pm3
```

## Summary of repeated commands
^[Top](#top)
Each time Windows restarts:

```cmd
C:\qwert> REM ADMINISTRATOR PRIVILEGES REQUIRED FOR THIS COMMAND
C:\qwert> usbipd bind --busid 7-4
```

Each time WSL2 restarts:

```cmd
C:\qwert> usbipd attach --auto-attach --busid 7-4 --wsl
```

and...

```sh
sudo service udev restart
sudo udevadm trigger --action=change
```

And for building and updating:

```sh
cd ~/proxmark3
make clean
make -j
./pm3-flash-all
```

## Script to automate environment setup

Use this script if you don't want to enter the above commands every single time you reboot. 

You must have Windows Terminal installed to use this script.

1. Save the following script as a batch file (**pm3_quick_startup_wsl2.bat**).
2. Use `usbipd list` to get your Proxmark3 hardware ID and replace in the script, as using BUSID is not very reliable since it might change between reboots.
3. Make sure your Proxmark3 is plugged in, and it is detected in the Device Manager as a COM port.
4. Run **pm3_quick_startup_wsl2.bat** and accept the UAC prompt. The script auto detects and asks for admin privileges, so you don't have to right-click and select Run As Administrator.
5. It will open up 2 windows. The first one is Command Prompt where initializing commands will run, and you need to keep this window open. The second one is Windows Terminal, where your pm3 client will run.

```batch
@echo off

REM -- Minimize the initial command prompt window
if not "%Minimized%"=="" goto :Minimized
set Minimized=True
start /min cmd /C "%~dpnx0"
goto :EOF

:Minimized
REM  -- Check for permissions
IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
    >nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
    >nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

REM -- If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

REM -- Start Ubuntu in a new Terminal window, change working directory to /home/proxmark3 and run Proxmark3 Client. Adjust your path accordingly.
start "" wt wsl.exe -d Ubuntu --cd ~/proxmark3 ./pm3

REM -- A trick to make this script sleep for 2 seconds, waiting for the Ubuntu session to fully initialize.
ping 127.0.0.1 -n 3 > nul

REM -- Replace the following hardware IDs with your actual Proxmark3 ID. You can find it by using "usbipd list"
usbipd bind --hardware-id 9ac4:4b8f
usbipd attach --auto-attach --hardware-id 9ac4:4b8f --wsl

wsl -u root "service udev restart"
wsl -u root "udevadm trigger --action=change"

pause & exit
```

## Done!
^[Top](#top)

Full [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md) may be helpful.

