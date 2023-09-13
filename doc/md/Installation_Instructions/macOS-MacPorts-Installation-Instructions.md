
<a id="Top"></a>

# macOS - MacPorts automatic installation

# Table of Contents
- [macOS - MacPorts automatic installation](#macOS---macports-automatic-installation)
- [Table of Contents](#table-of-contents)
  - [Main prerequisite](#main-prerequisite)
  - [Installing latest releases](#installing-latest-releases)
  - [Build from source](#build-from-source)
- [Clone the Iceman repository](#clone-the-iceman-repository)
  - [Compile the project](#compile-the-project)
    - [the button trick](#the-button-trick)
  - [Run it](#run-it)




## Main prerequisite
^[Top](#top)

1. Have MacPorts installed. Visit https://www.macports.org/ for more information.

## Installing stable releases directly
^[Top](#top)

Packaging for latest releases are available on MacPorts with the port name [`proxmark3-iceman`](https://ports.macports.org/port/proxmark3-iceman/details/), with a variant for PM3GENERIC firmwares available as `+pm3generic`.

Installing is as simple as `sudo port install proxmark3-iceman` and if you want to install for PM3GENERIC, you can run `sudo port install proxmark3-iceman +pm3generic` instead.


## Build from source
^[Top](#top)

These instructions will show how to setup the environment on OSX to the point where you'll be able to clone and compile the repo by yourself, as on Linux, Windows, etc.

1. Have MacPorts installed. Visit https://www.macports.org/ for more information.

    * Since you're going to compile directly; this will require a bit more setup, you first need to set up your PATH variable (we assume your MacPorts prefix is located at its default, which is `/opt/local`) in your shell rc file:

      ```bash
      export MACPORTS_PREFIX="/opt/local"
      # we assume you'll use GNU coreutils; which is also a required dependency for proxmark3
      # install it with `sudo port install coreutils`
      export "$MACPORTS_PREFIX/libexec/gnubin:$MACPORTS_PREFIX/bin:$MACPORTS_PREFIX/sbin:$PATH"
      ```

      For a somewhat seamless development environment, you can use these in your shell rc file:

      ```bash
      export C_INCLUDE_PATH="$MACPORTS_PREFIX/include:$C_INCLUDE_PATH"
      export CPLUS_INCLUDE_PATH="$MACPORTS_PREFIX/include:$CPLUS_INCLUDE_PATH"
      export LIBRARY_PATH="$MACPORTS_PREFIX/lib:$LIBRARY_PATH"
      export LDFLAGS="-L$MACPORTS_PREFIX/lib $LDFLAGS"
      export CFLAGS="-I$MACPORTS_PREFIX/include $CFLAGS"
      export CPPFLAGS="-isystem$MACPORTS_PREFIX/include -I$MACPORTS_PREFIX/include $CPPFLAGS"
      export PKG_CONFIG_PATH="$MACPORTS_PREFIX/lib/pkgconfig:$MACPORTS_PREFIX/share/pkgconfig:$PKG_CONFIG_PATH"
      ```

2. Install dependencies:

    ```bash
    sudo port install readline jansson lua52 python311 bzip2 lz4 openssl11 arm-none-eabi-gcc arm-none-eabi-binutils coreutils qt5 qt5-qtbase pkgconfig
    ```

3. Clamp Python version for pkg-config

    MacPorts doesn't handle Python version defaults when it comes to pkg-config. So even if you have done:

    ```bash
    sudo port install python311 cython311

    sudo port select --set python python311  # this also makes calls to "python" operate on python3.11
    sudo port select --set python3 python311
    sudo port select --set cython cython311
    ```

    This won't set a default python3.pc (and python3-embed.pc) under the MacPorts pkgconfig includes folder.

    To fix that, follow these steps:

    ```bash
    cd /opt/local/lib/pkgconfig
    sudo ln -svf python3.pc python-3.11.pc
    sudo ln -svf python3-embed.pc python-3.11-embed.pc
    ```

    _Or_ you can use a framework definition in your shell rc file:

    ```bash
    export MACPORTS_FRAMEWORKS_DIR="$MACPORTS_PREFIX/Library/Frameworks"
    export PYTHON_FRAMEWORK_DIR="$MACPORTS_FRAMEWORKS_DIR:/Python.framework/Versions/3.11"
    export PKG_CONFIG_PATH="$PYTHON_FRAMEWORK_DIR:$PKG_CONFIG_PATH"
    ```

4. (optional) Install makefile dependencies:

    ```bash
    sudo port install recode astyle
    ```


# Clone the Iceman repository
^[Top](#top)

```sh
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
```

## Compile the project
^[Top](#top)

Now you're ready to follow the [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md).
From there, you can follow the original instructions. 
_Take extra note to instructions if you **don't** have a Proxmark3 RDV4 device._

To flash on OS X, better to enter the bootloader mode manually, else you may experience errors.

### the button trick
^[Top](#top)

With your Proxmark3 unplugged from your machine, press and hold the button on your Proxmark3 as you plug it into a USB port. You can release the button, two of the four LEDs should stay on. You're in bootloader mode, ready for the next step. In case the two LEDs don't stay on when you're releasing the button, you've an old bootloader, start over and keep the button pressed during the whole flashing procedure.


## Run it
^[Top](#top)

To use the compiled client, you can use `pm3` script, it is a wrapper of the proxmark3 client that handles automatic detection of your proxmark.
```sh
pm3
```

If you want to manually select serial port, remember that the Proxmark3 port is `/dev/tty.usbmodemiceman1`, so commands become:
```sh
proxmark3 /dev/ttyACM0  =>  proxmark3 /dev/tty.usbmodemiceman1
```
