
<a id="Top"></a>

# Modem Manager must be discarded


# Table of Contents
- [Modem Manager must be discarded](#modem-manager-must-be-discarded)
- [Table of Contents](#table-of-contents)
- [If you're a Linux user](#if-youre-a-linux-user)
- [Solution 1: remove ModemManager](#solution-1-remove-modemmanager)
- [Solution 2: disable ModemManager](#solution-2-disable-modemmanager)
- [Solution 3: use filtering udev rules](#solution-3-use-filtering-udev-rules)
- [Solution 4: use global ttyACM filtering rule](#solution-4-use-global-ttyacm-filtering-rule)
- [Testing ModemManager filtering effectiveness](#testing-modemmanager-filtering-effectiveness)
- [I didn't read carefully this page and now my Proxmark3 is not responding](#i-didnt-read-carefully-this-page-and-now-my-proxmark3-is-not-responding)
  - [Only the fullimage is damaged](#only-the-fullimage-is-damaged)
  - [The bootloader is damaged](#the-bootloader-is-damaged)

# If you're a Linux user
^[Top](#top)

ModemManager is a real threat that can lead to a bricked Proxmark3, read this very attentively.

**The problem:**

ModemManager is pre-installed on many different Linux distributions, very probably yours as well.
It's intended to prepare and configure the mobile broadband (2G/3G/4G) devices, whether they are built-in or dongles.
Some are serial, so when the Proxmark3 is plugged and a `/dev/ttyACM0` appears, ModemManager attempts to talk to it to see if it's a modem replying to AT commands.

Now imagine what happens when you're flashing your Proxmark3 and ModemManager suddenly starts sending bytes to it at the same time...
Yes it makes the flashing failing. And if it happens while you're flashing the bootloader, it will require a JTAG device to unbrick the Proxmark3.

ModemManager is a threat for the Proxmark3, but also for many other embedded devices, such as some Arduino platforms.

# Solution 1: remove ModemManager
^[Top](#top)

If you don't need ModemManager, the safest is to remove it entirely.

On Debian-alike (Ubuntu, Kali,...):
```sh
sudo apt remove modemmanager
```
On Archlinux:
```sh
sudo pacman -R modemmanager
```

# Solution 2: disable ModemManager
^[Top](#top)

```sh
sudo systemctl stop ModemManager
sudo systemctl disable ModemManager
```

# Solution 3: use filtering udev rules
^[Top](#top)

If you *really* need ModemManager, e.g. for your 4G device, you'll have to use some filtering rules to make sure it doesn't interfere with the Proxmark3. 

Once you have cloned the Proxmark3 repository, you can run `make udev` to install udev rules that will tell ModemManager to not look at your Proxmark3.

**BEWARE** it will not work if your ModemManager installation is using a `strict` policy, which is the case on some distributions.
So you'll need first to check what `filter-policy` is used on your distribution:

```sh
systemctl status ModemManager
```
```
● ModemManager.service - Modem Manager
   Loaded: loaded (/lib/systemd/system/ModemManager.service...
   Active: active (running) since ...
   ...
   CGroup: /system.slice/ModemManager.service
           └─XXXX /usr/sbin/ModemManager --filter-policy=strict
```

If it's using `filter-policy=strict`, either look at [solution 4](#solution-4-use-global-ttyACM-filtering-rule) or change the filter policy of your system.

In any case, it's very important that you test if the filtering is effective before attempting to flash your Proxmark3, see section [Testing ModemManager filtering effectiveness](#Testing-ModemManager-filtering-effectiveness).

# Solution 4: use global ttyACM filtering rule
^[Top](#top)

Edit the system ModemManager configuration:
```sh
sudo systemctl edit ModemManager.service
```
And add the following content to add a global ttyACM filtering rule:
```
[Service]
Environment="MM_FILTER_RULE_TTY_ACM_INTERFACE=0"
```
This will create the following file: `/etc/systemd/system/ModemManager.service.d/override.conf`. Then restart the service:
```sh
sudo service ModemManager restart
```

It's very important that you test if the filtering is effective before attempting to flash your Proxmark3, see section [Testing ModemManager filtering effectiveness](#Testing-ModemManager-filtering-effectiveness).

# Testing ModemManager filtering effectiveness
^[Top](#top)

If you chose to keep ModemManager, test the filtering effectiveness before attempting to flash Proxmark3.

**Reboot**

Turn systemd debug on and watch logs:
```sh
sudo mmcli -G DEBUG
sudo journalctl -f|grep "ModemManager.*\[filter\]"
```
Now plug in the Proxmark 3.

If ModemManager interferes, you'll get logs like this:
```
ModemManager[xxxxx]: <debug> [filter] (tty/ttyACM0): port allowed: cdc-acm interface reported AT-capable
```
It it's the case, you *need to fix your ModemManager issues* before using the Proxmark3.

When ModemManager is properly filtering `/dev/ttyACM0`:
```
ModemManager[xxxxx]: <debug> [filter] (tty/ttyACM0) port filtered: forbidden
```
If this is the case, you're fine and you can safely use and flash the PRoxmark3 on your system.

To turn systemd debug off again:
```sh
sudo mmcli -G ERR
```

# I didn't read carefully this page and now my Proxmark3 is not responding
^[Top](#top)

First of all, follow the instructions above to make sure ModemManager will not interfere with the Proxmark3 anymore.

Now there are two possibilities:

## Only the fullimage is damaged
^[Top](#top)

If the flashing of the fullimage failed, you can still force the Proxmark to start in bootloader mode by keeping the button pressed while you're plugging it in and while you're attempting to flash it again.

In short:

* unplug device
* press button and keep it pressed (IMPORTANT)
* plug in device
* run flash command `pm3-flash-fullimage`
* wait until flash is finished
* release button
* un/plug device


## The bootloader is damaged
^[Top](#top)

If attempting to flash via the button fails, this means your bootloader is corrupted.
You'll have no other choice than flashing it via an external JTAG instrument.
