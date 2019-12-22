# Installing on Windows

There are two ways to install, build and use Proxmark3 on Windows:

* Using Gator96100 **ProxSpace**, a package to assist in your Windows installation of MinGW
* Using native **WSL**, if you're running a Windows 10 version recent enough (FCU 1709 or later)

---

# Installing on Windows with ProxSpace

## Video Installation guide
[![Windows Installation tutorial](https://github.com/5w0rdfish/Proxmark3-RDV4-ParrotOS/blob/master/screenshot-www.youtube.com-2019.03.17-20-44-33.png)](https://youtu.be/zzF0NCMJnYU "Windows Installation Tutorial")

## Driver Installation

Install required drivers for your Windows installation. You may need admin privileges to do this.  
Step by step guides are online such as [RiscCorps](https://store.ryscc.com/blogs/news/how-to-install-a-proxmark3-driver-on-windows-10).

## Download / clone ProxSpace repo

Download the Gator96100 ProxSpace package from https://github.com/Gator96100/ProxSpace/releases

If you prefer, you can clone it, provided that you installed Github for Windows https://desktop.github.com/.

Extract 'ProxSpace' to a location path without spaces.  
For example D:\OneDrive\Documents\GitHub is ok whereas C:\My Documents\My Projects\proxspace is not.

If you're running Windows in a Virtualbox guest, make sure not to install ProxSpace on a vbox shared drive. (It's ok later to move the `/pm3` subfolder to a shared drive and edit the `*.bat`)

## Launch ProxSpace

Run `runme.bat` or `runme64.bat` depending on your Windows architecture.

You'll get a Bash prompt and your home directory should become the ProxSpace `pm3` sub-directory.

Please note you will need to use `/` in paths as you are using Bash.

## Clone the RRG/Iceman repository

```sh
cd
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
```

If you're a contributing developer, you probably want to be able to use `make style`. If so, you've to install astyle:

```sh
pacman -S mingw-w64-x86_64-astyle
```

## Compile and use the project

To use the compiled client, the only differences are that executables end with `.exe` (e.g. `proxmark3.exe`) and that the Proxmark3 port is one of your `comX` ports where "X" is the com port number assigned to proxmark3 under Windows, so commands like `proxmark3 /dev/ttyACMX` become `proxmark3.exe comX`.

Now you're ready to follow the [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md).

# Installing on Windows with WSL

It requires to run a Windows 10 version 1709 or above. Previous versions didn't have support for COM ports.

Install WSL with e.g. the standard Ubuntu.

For WSL configuration, see [Manage and configure Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/wsl-config).

Make sure your WSL can launch Windows processes to get the `pm3` scripts working (cf `interop` in the WSL settings).

## X Server Installation

If you want to run the graphical components of the Proxmark3 client, you need to install a X Server such as [VcXsrv](https://sourceforge.net/projects/vcxsrv/) or [Xming](https://sourceforge.net/projects/xming/) and launch it, e.g. by executing XLaunch.

## Dependencies

Enter WSL prompt (`wsl`) and from there, follow the [Linux Installation Instructions](/doc/md/Installation_Instructions/Linux-Installation-Instructions.md) for Ubuntu, summarized here below:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends git ca-certificates build-essential pkg-config \
libreadline-dev gcc-arm-none-eabi libnewlib-dev qtbase5-dev libsndfile1-dev
```

If you don't need the graphical components of the Proxmark3 client, you can skip the installation of `qtbase5-dev`.

## Clone the RRG/Iceman repository

```sh
git clone https://github.com/RfidResearchGroup/proxmark3.git
```

## Compile and use the project

To use the compiled client, the only difference is that the Proxmark3 port is translated from your `comX` port where "X" is the com port number assigned to proxmark3 under Windows, to a `/dev/ttySX`, so commands become:

```sh
proxmark3 /dev/ttyACM0  =>  proxmark3 /dev/ttySX
```

Depending on the Windows version, you might need to give permission to the current user to access `/dev/ttySX`: (change X to your port number)

```sh
ls -al /dev/ttySX
groups|grep dialout
```

If group ownership is `dialout` and your user is member of `dialout` group, all is fine. Else you'll have to provide access to `/dev/ttySX`: (Unfortunately the access rights of the port won't survive and will have to be fixed again next time.)

```sh
sudo chmod 666 /dev/ttySX
```

If you installed a X Server and compiled the Proxmark3 with QT4 support, you've to export the `DISPLAY` environment variable:

```sh
export DISPLAY=:0
```

and add it to your Bash profile for the next times:

```sh
echo "export DISPLAY=:0" >> ~/.bashrc
```

Note that it may take a quite long time for a freshly plugged Proxmark3 to be visible on a WSL /dev/ttySX port.

Now you're ready to follow the [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md).

## Color text on windows 10
In later versions of windows 10 you may be able to get color to work by setting this registery key
```
[HKEY_CURRENT_USER\Console]
    "VirtualTerminalLevel"=dword:00000001
```
You also need to disable "use legacy console" in the cmd.exe properties, or set the following registry key
```
[HKEY_CURRENT_USER\Console]
    "ForceV2"=dword:00000001
```
After making these changes, you will need to start a new command prompt (cmd.exe) to ensure its using the new settings.

If after making these changes (and restarting proxmark3.exe) you get extra characters and no color text, set either key to 0 or enable legacy mode again (and restart the command prompt).

