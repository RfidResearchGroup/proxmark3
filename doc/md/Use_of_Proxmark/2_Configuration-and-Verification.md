<a id="Top"></a>

# 2. Configuration and Verification

# Table of Contents
- [2. Configuration and Verification](#2-configuration-and-verification)
- [Table of Contents](#table-of-contents)
    - [First things on your Proxmark3 RDV4](#first-things-on-your-proxmark3-rdv4)
    - [Verify sim module firmware version](#verify-sim-module-firmware-version)
  - [Next steps](#next-steps)



### First things on your Proxmark3 RDV4
^[Top](#top)

You will need to run these commands to make sure your RDV4 is prepared
```
[usb] pm3 --> script run init_rdv4
```


The lua script actually executes the following commands below.  These are here because of documentation, you can jump down to *Verify sim module firmware version* part.
```
[usb] pm3 --> mem load -f mfc_default_keys -m
[usb] pm3 --> mem load -f t55xx_default_pwds -t
[usb] pm3 --> mem load -f iclass_default_keys -i
[usb] pm3 --> lf t55xx deviceconfig --r0 -a 29 -b 17 -c 15 -d 47 -e 15 -p
[usb] pm3 --> lf t55xx deviceconfig --r1 -a 31 -b 20 -c 18 -d 50 -e 15 -p
[usb] pm3 --> lf t55xx deviceconfig --r2 -a 31 -b 20 -c 18 -d 40 -e 15 -p
[usb] pm3 --> lf t55xx deviceconfig --r3 -a 29 -b 17 -c 15 -d 31 -e 15 -f 47 -g 63 -p

Set all t55xx settings to defaults (will set all 4 at once)
[usb] pm3 --> lf t55xx deviceconfig -z -p
```


### Verify sim module firmware version
^[Top](#top)

To make sure you got the latest sim module firmware.

_Latest version is v4.12_

```
[usb] pm3 --> hw status
```

Find version in the long output,  look for these two lines

```
#db# Smart card module (ISO 7816)
#db#   version.................v2.06

or

#db# Smart card module (ISO 7816)
#db#   version.................v3.11

```

These versions is obsolete.

If you didn't download sim013.bin from the RRG Repo be aware that it might be corrupted or faulty.
You find a hash text file in this folder.   It was generated with the following linux command.

```
sha512sum -b sim013.bin > sim013.sha512.txt
```

You should validate the sim013.bin file against this hash file in order to be sure the file is not corrupted or faulty.

The following command upgrades your device sim module firmware.
Don't not turn off your device during the execution of this command!!
Even its a quite fast command you should be warned.  You may brick it if you interrupt it.

```
[usb] pm3 --> smart upgrade -f /usr/local/share/proxmark3/firmware/sim013.bin
# or if from local repo
[usb] pm3 --> smart upgrade -f sim013.bin
```

You get the following output if the execution was successful:

```
[=] -------------------------------------------------------------------
[!] ⚠️  WARNING - sim module firmware upgrade
[!] ⚠️  A dangerous command, do wrong and you could brick the sim module
[=] -------------------------------------------------------------------

[=] firmware file       sim013.bin
[=] Checking integrity  sim013.sha512.txt
[+] loaded 866 bytes from binary file sim013.bin
[+] loaded 141 bytes from binary file sim013.sha512.txt
[=] Don't turn off your PM3!
[+] Sim module firmware uploading to PM3...
 🕑 864 bytes sent
[+] Sim module firmware updating...
[#] FW 0000
[#] FW 0080
[#] FW 0100
[#] FW 0180
[#] FW 0200
[#] FW 0280
[#] FW 0300
[+] Sim module firmware upgrade successful    
```

Run hw status command to verify that the upgrade went well.

```
[usb] pm3 --> hw status
```

## Next steps
^[Top](#top)

For the next steps, please read the following page:

* [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)
 
