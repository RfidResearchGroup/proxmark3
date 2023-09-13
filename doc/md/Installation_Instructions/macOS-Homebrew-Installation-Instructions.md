
<a id="Top"></a>

# macOS - Homebrew automatic installation


# Table of Contents
- [macOS - Homebrew automatic installation](#macos---homebrew-automatic-installation)
- [Table of Contents](#table-of-contents)
  - [macOS Ventura Beta users](#macos-ventura-beta-users)
  - [Apple Silicon (M1) Notes](#apple-silicon-m1-notes)
  - [Install Proxmark3 tools](#install-proxmark3-tools)
  - [Upgrade HomeBrew tap formula](#upgrade-homebrew-tap-formula)
  - [Flash the BOOTROM & FULLIMAGE](#flash-the-bootrom--fullimage)
  - [Run the client](#run-the-client)
  - [Next steps](#next-steps)
- [Homebrew (macOS), developer installation](#homebrew-macos-developer-installation)
- [Clone the Iceman repository](#clone-the-iceman-repository)
  - [Compile the project](#compile-the-project)
    - [the button trick](#the-button-trick)
  - [Run it](#run-it)



## macOS Ventura Beta users
^[Top](#top)

Early users of macOS Ventura and Xcode 14.0 might run into an error saying that Xcode 14.0 is out-of-date (even though you have the latest Xcode Beta installed).

If (and only if) you run into that error, here is the fix:
- RE-download the *latest* Command Line Tools of Xcode Beta 14 and install them (again). (https://developer.apple.com/download/all/)
- Run `sudo xcode-select -s /Applications/Xcode-beta.app` in Terminal.
- Proceed with Brew installation
That should normally fix the issue.

Alternatively, and only if the issue still persists after following the steps above, you can use this *temporary and ugly* fix:
- Try renaming `Xcode-beta.app` to `Xcode.app` (Note: If you still need Xcode 13.0 for signing and uploading apps to App Store rename `Xcode.app` to `Xcode-2.app`)
- Proceed with Brew installation
- IMPORTANT: Reverse renaming done in first step.

## Apple Silicon (M1) Notes
^[Top](#top)

Ensure Rosetta 2 is installed as it's currently needed to run `arm-none-eabi-gcc` as it's delivered as a precombiled x86_64 binary.

If you see an error like:

```sh
bad CPU type in executable
```

Then you are missing Rosetta 2 and need to install it: `/usr/sbin/softwareupdate --install-rosetta`

Homebrew has changed their prefix to differentiate between native Apple Silicon and Intel compiled binaries.  The Makefile attempts to account for this but please note that 
whichever terminal or application you're using must be running under Architecture "Apple" as seen by Activity Monitor as all child processes inherit the Rosetta 2 environment of their parent.  You can check which architecture you're currently running under with a `uname -m` in your terminal.

The fastest option is to run the brew command with the `arch -arm64` prefix i.e. `arch -arm64 brew install --HEAD --with-blueshark proxmark3`. This doesn't require running the whole terminal in Rosetta 2.

Visual Studio Code still runs under Rosetta 2 and if you're developing for proxmark3 on an Apple Silicon Mac you might want to consider running the Insiders build which has support for running natively on Apple Silicon.

## Install Proxmark3 tools
^[Top](#top)

These instructions comes from \@Chrisfu, where we got the proxmark3.rb scriptfile from.
For further questions about Mac & Homebrew, contact [\@Chrisfu on Twitter](https://github.com/chrisfu/)

0. Install XCode Command Line Tools if you haven't yet already done so:
  - `xcode-select --install`

1. Install homebrew if you haven't yet already done so:
  - http://brew.sh/

2. Install xquartz:
  - `brew install xquartz`
 
3. Tap this repo:
  - `brew tap RfidResearchGroup/proxmark3`

4. Install Proxmark3:
  - `brew install proxmark3` for stable release 
  - `brew install --HEAD proxmark3` for latest non-stable from GitHub (use this if previous command fails)
  - `brew install --with-blueshark proxmark3` for blueshark support, stable release
  - `brew install --HEAD --with-blueshark proxmark3` for blueshark support, latest non-stable from GitHub (use this if previous command fails)
  - `brew install --with-generic proxmark3`: for generic (non-RDV4) devices ([platform](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md#platform)), stable release
  - `brew install --HEAD --with-generic proxmark3`: for generic (non-RDV4) devices ([platform](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md#platform)), latest non-stable from GitHub (use this if previous command fails)

For more info, go to https://github.com/RfidResearchGroup/homebrew-proxmark3

## Upgrade HomeBrew tap formula
^[Top](#top)

*This method is useful for those looking to run bleeding-edge versions of iceman's fork. Keep this in mind when attempting to update your HomeBrew tap formula as this procedure could easily cause a build to break if an update is unstable on macOS.* 

Tested on macOS Mojave 10.14.4

*Note: This assumes you have already installed iceman's fork from HomeBrew as mentioned above*

Force HomeBrew to pull the latest source from github

```sh
brew upgrade --fetch-HEAD proxmark3
```

## Flash the BOOTROM & FULLIMAGE
^[Top](#top)

With your Proxmark3 unplugged from your machine, press and hold the button on your Proxmark3 as you plug it into a USB port. You can release the button, two of the four LEDs should stay on. You're in bootloader mode, ready for the next step. In case the two LEDs don't stay on when you're releasing the button, you've an old bootloader, start over and keep the button pressed during the whole flashing procedure.

In principle, the helper script `pm3-flash-all` should auto-detect your port, so you can just try:

```sh
pm3-flash-all
```

If port detection failed, you'll have to call the flasher manually and specify the correct port:

```sh
proxmark3 /dev/tty.usbmodemiceman1 --flash --unlock-bootloader --image /usr/local/share/proxmark3/firmware/bootrom.elf --image /usr/local/share/proxmark3/firmware/fullimage.elf
```

> Depending on the firmware version your Proxmark3 can also appear as:
> `/dev/tty.usbmodem881`


When compiling and you didn't flash the device,  the client will now warn that you have a full image that doesn't match the source code of your client.  If you know what you are doing, you can ignore it.



## Run the client
^[Top](#top)

```sh
pm3
```

or, if the port doesn't get properly detected:

```sh
proxmark3 /dev/tty.usbmodemiceman1
```

## Next steps
^[Top](#top)

For the next steps, please read the following pages:

* [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md)
* [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)
* [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)|
 



# Homebrew (macOS), developer installation
^[Top](#top)

These instructions will show how to setup the environment on OSX to the point where you'll be able to clone and compile the repo by yourself, as on Linux, Windows, etc.

1. Install homebrew if you haven't yet already done so: http://brew.sh/

2. Install dependencies:

```
brew install readline qt5 pkgconfig coreutils
brew install RfidResearchGroup/proxmark3/arm-none-eabi-gcc
```
3. (optional) Install makefile dependencies:
```
brew install recode
brew install astyle
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
From there, you can follow the original compilation instructions. 
_Take extra note to instructions if you don't have a Proxmark3 RDV4 device._

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
