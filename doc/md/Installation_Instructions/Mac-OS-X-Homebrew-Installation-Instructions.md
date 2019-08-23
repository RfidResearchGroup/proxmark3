# Homebrew (Mac OS X), automatic installation

## Install Proxmark3 tools

These instructions comes from @Chrisfu, where we got the proxmark3.rb scriptfile from.
For further questions about Mac & Homebrew,  contact @Chrisfu  (https://github.com/chrisfu/)

1. Install homebrew if you haven't yet already done so: http://brew.sh/

2. Tap this repo: `brew tap RfidResearchGroup/proxmark3`

3. Install Proxmark3: `brew install proxmark3` for stable release or `brew install --HEAD proxmark3` for latest non-stable from GitHub.

## Upgrade HomeBrew tap formula

*This method is useful for those looking to run bleeding-edge versions of RRG/iceman's client. Keep this in mind when attempting to update your HomeBrew tap formula as this procedure could easily cause a build to break if an update is unstable on macOS.* 

Tested on macOS Mojave 10.14.4

*Note: This assumes you have already installed RRG/iceman's fork from HomeBrew as mentioned above*

Force HomeBrew to pull the latest source from github

```sh
brew upgrade --fetch-HEAD proxmark3
```

## Flash the BOOTROM & FULLIMAGE

With your Proxmark3 unplugged from your machine, press and hold the button on your Proxmark3 as you plug it into a USB port. You can release the button, two of the four LEDs should stay on. You're un bootloader mode, ready for the next step. In case the two LEDs don't stay on when you're releasing the button, you've an old bootloader, start over and keep the button pressed during the whole flashing procedure.

```sh
sudo proxmark3-flasher /dev/tty.usbmodemiceman1 -b /usr/local/Cellar/proxmark3/HEAD-<Commit-ID>/share/firmware/bootrom.elf /usr/local/Cellar/proxmark3/HEAD-<Commit-ID>/share/firmware/fullimage.elf
```

> Replace \<Commit-ID\> with the HEAD-XXXX ID displayed by brew.  
> Depending on the firmware version your Proxmark3 can also appear as `/dev/tty.usbmodem881`



## Run the client

```sh
sudo proxmark3 /dev/tty.usbmodemiceman1
```

## Next steps

For the next steps, please read the following pages:

* [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md)
* [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)
* [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)|
 



# Homebrew (Mac OS X), developer installation

These instructions will show how to setup the environment on OSX to the point where you'll be able to clone and compile the repo by yourself, as on Linux, Windows, etc.

1. Install homebrew if you haven't yet already done so: http://brew.sh/

2. Install dependencies:

```
brew install readline p7zip libusb-compat perl qt5 wget
brew install RfidResearchGroup/proxmark3/arm-none-eabi-gcc
```

## Compile and use the project

Now you're ready to follow the [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md).

To use the compiled client and flasher, the only difference is that the Proxmark3 port is `/dev/tty.usbmodemiceman1`.

To flash: With your Proxmark3 unplugged from your machine, press and hold the button on your Proxmark3 as you plug it into a USB port. You can release the button, two of the four LEDs should stay on. You're un bootloader mode, ready for the next step. In case the two LEDs don't stay on when you're releasing the button, you've an old bootloader, start over and keep the button pressed during the whole flashing procedure.

In principle, the helper script `flash-all.sh` should auto-detect your port, so you can just try:

```sh
./flash-all.sh
```

If port detection failed, you'll have to call the flasher manually and specify the correct port:

```sh
client/flasher /dev/tty.usbmodemiceman1 -b bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf
```

Similarly, to run the client, you may try:

```sh
./proxmark3.sh
```

Or, by specifying the port manually:

```sh
client/proxmark3 /dev/tty.usbmodemiceman1
```

