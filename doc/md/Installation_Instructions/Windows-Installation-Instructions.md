# Building on Windows
You will need to use the Gator96100 Proxspace package to assist in your windows installation.
This can be downloaded from https://github.com/Gator96100/ProxSpace/

## Notes
If you receive gcc errors using v3.1 during build, download and use v2.2. This may help resolve the issue.

- https://github.com/Gator96100/ProxSpace/releases/tag/v3.1   (release v3.1 with gcc v7.3.0 )
- https://github.com/Gator96100/ProxSpace/releases/tag/v2.2   (release v2.2 with gcc v5.3.0 arm-none-eabi-gcc v7.1.0)

---
# Video Installation guide
[![Windows Installation tutorial](https://github.com/5w0rdfish/Proxmark3-RDV4-ParrotOS/blob/master/screenshot-www.youtube.com-2019.03.17-20-44-33.png)](https://youtu.be/zzF0NCMJnYU "Windows Installation Tutorial")

## Manual Installation

### Driver Installation

Install required drivers for your windows installation. You will may need admin privileges to do this. 
(This is covered in the video) Step by step guides are online such as [RiscCorps](https://store.ryscc.com/blogs/news/how-to-install-a-proxmark3-driver-on-windows-10)

### Install Github

Install Github for Windows https://desktop.github.com/

### Download / clone Proxspace repo

Download the required proxspace repo. https://github.com/Gator96100/ProxSpace/

Extract 'ProxSpace' to a location on drive without spaces. 
For example D:\OneDrive\Documents\GitHub is ok whereas C:\My Documents\My Projects\proxspace is not.

### Clone the RRG/Iceman repository

```sh
git clone https://github.com/RfidResearchGroup/proxmark3.git
```

### Copy files to Proxspace

Copy all the contents from the `proxmark3` folder into the proxspace `pm3` folder

### Run the .bat

Run `runme.bat` or `runme64.bat` depending on your Windows architecture.

Please note you will need to use `/` as you are using BASH.

### Compile and use the project

Now you're ready to follow the [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md).

The only differences are that executables end with `.exe` (e.g. `client/flasher.exe`) and that the Proxmark3 port is one of your `comX` ports where "X" is the com port number assigned to proxmark3 under Windows.

So flashing will resemble

```sh
client/flasher.exe comX -b bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf
```

And running the client will resemble

```sh
cd client
./proxmark3.exe comX
```
