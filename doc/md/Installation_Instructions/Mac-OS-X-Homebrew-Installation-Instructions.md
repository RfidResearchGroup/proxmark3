## Homebrew (Mac OS X)
These instructions comes from @Chrisfu, where I got the proxmark3.rb scriptfile from.
Further questions about Mac & Homebrew,  contact @Chrisfu  (https://github.com/chrisfu/)

1. Install homebrew if you haven't yet already done so: http://brew.sh/

2. Tap this repo: `brew tap RfidResearchGroup/proxmark3`

3. Install Proxmark3: `brew install proxmark3` for stable release or `brew install --HEAD proxmark3` for latest non-stable from GitHub.

Upgrading HomeBrew tap formula
-----------------------------
*This method is useful for those looking to run bleeding-edge versions of iceman's client. Keep this in mind when attempting to update your HomeBrew tap formula as this procedure could easily cause a build to break if an update is unstable on macOS.* 

Tested on macOS High Sierra 10.13.2

*Note: This assumes you have already installed iceman's fork from HomeBrew as mentioned above*

1. Force HomeBrew to pull the latest source from github
`brew upgrade --fetch-HEAD RfidResearchGroup/proxmark3`
 
2. Flash the bootloader & fullimage.elf
  * With your Proxmark3 unplugged from your machine, press and hold the button on your Proxmark 3 as you plug it into a USB port. Continue to hold the button until after this step is complete and the `proxmark3-flasher` command outputs "Have a nice day!"*
   `$ sudo proxmark3-flasher /dev/tty.usbmodem881 -b /usr/local/Cellar/proxmark3/HEAD-6a710ef/share/firmware/bootrom.elf /usr/local/Cellar/proxmark3/HEAD-6a710ef/share/firmware/fullimage.elf`


`$ sudo proxmark3-flasher /dev/tty.usbmodem881 `

4. Enjoy the update
