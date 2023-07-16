<a id="top"></a>

# Windows Installation instructions


## Table of Contents
- [Windows Installation instructions](#windows-installation-instructions)
  - [Table of Contents](#table-of-contents)
  - [Installing dev-environment with ProxSpace](#installing-dev-environment-with-proxspace)
  - [Video Installation guide](#video-installation-guide)
  - [Driver Installation ( Windows 7 )](#driver-installation--windows-7-)
  - [Download ProxSpace repo](#download-proxspace-repo)
  - [Launch ProxSpace](#launch-proxspace)
  - [Clone the Iceman repository](#clone-the-iceman-repository)
  - [Compile and use the project](#compile-and-use-the-project)
  - [Done!](#done)
- [Installing pre-compiled binaries with ProxSpace](#installing-pre-compiled-binaries-with-proxspace)
- [Installing dev-environment with WSL 1](#installing-dev-environment-with-wsl-1)
    - [Stay away from WSL 2](#stay-away-from-wsl-2)
    - [More about WSL](#more-about-wsl)
  - [X Server Installation](#x-server-installation)
  - [Windows Terminal Installation](#windows-terminal-installation)
  - [Dependencies](#dependencies)
  - [Clone the Iceman repository](#clone-the-iceman-repository-1)
  - [Compile and use the project](#compile-and-use-the-project-1)
  - [Done!](#done-1)


There are two ways to install, build and use Proxmark3 on Windows:

* Using Gator96100 **ProxSpace**, a package to assist in your Windows installation of MinGW
* Using native **WSL 1**, if you're running a Windows 10 version recent enough (FCU 1709 or later)

We have listed three ways to use these two setups  (dev environment vs pre-compiled binaries)

---

## Installing dev-environment with ProxSpace
^[Top](#top)

## Video Installation guide
^[Top](#top)

_note:  this video is out-of-date but still informative_
[![Windows Installation tutorial](https://raw.githubusercontent.com/Chrissy-Morgan/Proxmark3-RDV4-ParrotOS/master/screenshot-www.youtube.com-2019.03.17-20-44-33.png)](https://youtu.be/zzF0NCMJnYU "Windows Installation Tutorial")

## Driver Installation ( Windows 7 )
^[Top](#top)

_note: for Windows 7 you will this step.  On a later Windows edition skip this._

Install required drivers for your Windows installation. You may need admin privileges to do this.  
Step by step guides are online such as [RyscCorps](https://store.ryscc.com/blogs/news/how-to-install-a-proxmark3-driver-on-windows-10).

## Download ProxSpace repo
^[Top](#top)

Download the Gator96100 ProxSpace package from https://github.com/Gator96100/ProxSpace/releases

Extract 'ProxSpace' to a location path without spaces.  

Good example 
```
D:\OneDrive\Documents\GitHub
``` 

Bad example
```
C:\My Documents\My Projects\proxspace
                  ^
```

If you're running Windows in a Virtualbox guest, make sure not to install ProxSpace on a vbox shared drive. (It's ok later to move the `/pm3` subfolder to a shared drive and edit the `*.bat`)

## Launch ProxSpace
^[Top](#top)

Run `runme64.bat`.

You'll get a Bash prompt and your home directory should become the ProxSpace `pm3` sub-directory.

Please note you will need to use `/` in paths as you are using Bash.

## Clone the Iceman repository
^[Top](#top)

```sh
cd
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
```

If you're a contributing developer, you probably want to be able to use `make style`. If so, you've got to install astyle:

```sh
pacman -S mingw-w64-x86_64-astyle
```

## Compile and use the project
^[Top](#top)

To use the compiled client, the only differences are that executables end with `.exe` (e.g. `proxmark3.exe`) and that the Proxmark3 port is one of your `comX` ports where "X" is the com port number assigned to proxmark3 under Windows, so commands like `proxmark3 /dev/ttyACMX` become `proxmark3.exe comX`.

## Done!
^[Top](#top)

Now you're ready to follow the [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md).


# Installing pre-compiled binaries with ProxSpace
^[Top](#top)

There are a community effort by @gator96100 to make up-to-date precompiled version of the official repository and this repository.
[www.proxmarkbuilds.org](https://www.proxmarkbuilds.org/)

It has excellent instructions to follow. 



# Installing dev-environment with WSL 1
^[Top](#top)

WSL 1 requires to run on Windows 10 version 1709 or above. Previous windows versions didn't have support for COM ports.

### Stay away from WSL 2
^[Top](#top)

*Microsoft introduced WSL 2 starting on Windows 10 version 2004 with Hyper-V powering its virtualization; As of 2020-08-13, WSL 2 does not support USB and Serial.*

### More about WSL
^[Top](#top)

Install WSL 1 with e.g. the standard Ubuntu. You can follow the guide on [Microsoft Docs](https://docs.microsoft.com/en-us/windows/wsl/install-win10) but be careful to follow WSL 1 specific instructions! When they recommend you to restart, you must restart.

For WSL configuration, see [Manage and configure Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/wsl-config).

Make sure your WSL can launch Windows processes to get the `pm3` scripts working (cf `interop` in the WSL settings).

## X Server Installation
^[Top](#top)

If you want to run the graphical components of the Proxmark3 client, you need to install a X Server such as in the list below, and launch it, e.g. by executing XLaunch.
 * [VcXsrv](https://sourceforge.net/projects/vcxsrv/) 
 * [Xming](https://sourceforge.net/projects/xming/) 


## Windows Terminal Installation
^[Top](#top)

Microsoft has recently released a new terminal for their OS. It is much better experience than old `cmd.exe` so we strongly recommend installing it.
It is also open sourced (see [github.com/microsoft/terminal](https://github.com/microsoft/terminal)). You can download and install from [GitHub](https://github.com/microsoft/terminal/releases/latest) or [Microsoft Store](https://www.microsoft.com/en-us/p/windows-terminal/9n0dx20hk701).


## Dependencies
^[Top](#top)

Enter WSL prompt (`wsl` or Start Windows Terminal with `wt`) and from there, follow the [Linux Installation Instructions](/doc/md/Installation_Instructions/Linux-Installation-Instructions.md) for Ubuntu, summarized here below:

Make sure your WSL guest OS is up-to-date first:

```sh
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get auto-remove -y
```

Install dependencies:

```sh
sudo apt-get install --no-install-recommends git ca-certificates build-essential pkg-config \
libreadline-dev gcc-arm-none-eabi libnewlib-dev libbz2-dev liblz4-dev libpython3-dev qtbase5-dev libssl-dev
```
_note_
If you don't need the graphical components of the Proxmark3 client, you can skip the installation of `qtbase5-dev`.  
If you don't need support for Python3 scripts in the Proxmark3 client, you can skip the installation of `libpython3-dev`.

## Clone the Iceman repository
^[Top](#top)

```sh
git clone https://github.com/RfidResearchGroup/proxmark3.git
```

## Compile and use the project
^[Top](#top)

To use the compiled client, the only difference is that the Proxmark3 port is translated from your `comX` port where **"X"** is the com port number assigned to proxmark3 under Windows, to a `/dev/ttySX`, so commands become:

```sh
proxmark3 /dev/ttyACM0  =>  proxmark3 /dev/ttySX
```

Depending on the Windows version, you might need to give permission to the current user to access `/dev/ttySX`: (change **X** to your port number)

```sh
ls -al /dev/ttySX
groups|grep dialout
```

If group ownership is `dialout` and your user is member of `dialout` group, all is fine. Else you'll have to provide access to `/dev/ttySX`: (Unfortunately the access rights of the port won't survive and will have to be fixed again next time.)

```sh
sudo chmod 666 /dev/ttySX
```

If you installed an X Server and compiled the Proxmark3 with QT5 support, you've to export the `DISPLAY` environment variable:

```sh
export DISPLAY=:0
```

And add it to your Bash (or your preferred shell) profile for the next times:

```sh
echo "export DISPLAY=:0" >> ~/.bashrc
```

Note that it may take a quite long time for a freshly plugged Proxmark3 to be visible on a WSL /dev/ttySX port.

## Done!
^[Top](#top)

Now you're ready to follow the [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md).

