### First things on your RDV40
You will need to run these commands to make sure your rdv4 is prepared
```
pm3 --> mem load f mfc_default_keys m
pm3 --> mem load f t55xx_default_pwds t
pm3 --> mem load f iclass_default_keys i
pm3 --> lf t55xx deviceconfig a 29 b 17 c 15 d 47 e 15 p
pm3 --> lf t55xx deviceconfig r 1 a 31 b 20 c 18 d 50 e 15 p
pm3 --> lf t55xx deviceconfig r 2 a 31 b 20 c 18 d 40 e 15 p
pm3 --> lf t55xx deviceconfig r 3 a 29 b 17 c 15 d 31 e 15 f 47 g 63 p

Set all t55xx settings to defaults (will set all 4 at once)
pm3 --> lf t55xx deviceconfig z p
```

### Verify sim module firmware version

To make sure you got the latest sim module firmware.

_Lastest version is v3.11_

```
pm3 --> hw status
```

Find version in the long output,  look for these two lines

```
#db# Smart card module (ISO 7816)
#db#   version.................v2.06
```

This version is obsolete.

If you didn't download sim011.bin from the RRG Repo be aware that it might be corrupted or faulty.
You find a hash text file in this folder.   It was generated with the following linux command.

```
sha512sum -b sim011.bin > sim011.sha512.txt
```

You should validate the sim011.bin file against this hash file in order to be sure the file is not corrupted or faulty.

The following command upgrades your device sim module firmware.
Don't not turn off your device during the execution of this command!!
Even its a quite fast command you should be warned.  You may brick it if you interrupt it.

```
pm3 --> sc upgrade f /usr/local/share/proxmark3/firmware/sim011.bin
# or if from local repo
pm3 --> sc upgrade f tools/simmodule/sim011.bin
```

You get the following output if the execution was successful:

```
[!] WARNING - Smartcard socket firmware upgrade.
[!] A dangerous command, do wrong and you will brick the smart card socket
[+] Smartcard socket firmware uploading to PM3
..
[+] Smartcard socket firmware updating,  don't turn off your PM3!
#db# FW 0000
#db# FW 0080
#db# FW 0100
#db# FW 0180
#db# FW 0200
#db# FW 0280
[+] Smartcard socket firmware upgraded successful        
```

Run hw status command to verify that the upgrade went well.

```
pm3 --> hw status
```

## Next steps

For the next steps, please read the following page:

* [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)
 
