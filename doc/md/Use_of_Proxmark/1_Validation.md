## 1. Validating proxmark client functionality

If all went well you should get some information about the firmware and memory usage as well as the prompt,  something like this.

```
[=] Session log /home/iceman/.proxmark3/log_20200521.txt
[=] Loading Preferences...
[+] loaded from JSON file /home/iceman/.proxmark3/preferences.json
[=] Using UART port /dev/ttyS7
[=] Communicating with PM3 over USB-CDC


██████╗ ███╗   ███╗ ████╗  
██╔══██╗████╗ ████║   ══█║ 
██████╔╝██╔████╔██║ ████╔╝ 
██╔═══╝ ██║╚██╔╝██║   ══█║    :snowflake: iceman@icesql.net
██║     ██║ ╚═╝ ██║ ████╔╝    https://github.com/rfidresearchgroup/proxmark3/
╚═╝     ╚═╝     ╚═╝ ╚═══╝  Release v4.9237 - Ice Coffee :coffee:


 [ Proxmark3 RFID instrument ] 

 [ CLIENT ]
  client: RRG/Iceman/master/v4.9237-2-g2cb19874 2020-05-21 22:00:00
  compiled with GCC 9.3.0 OS:Linux ARCH:x86_64
 
 [ PROXMARK RDV4 ]
  external flash:                  present 
  smartcard reader:                present 

 [ PROXMARK RDV4 Extras ]
  FPC USART for BT add-on support: absent 

 [ ARM ]
 bootrom: RRG/Iceman/master/v4.9237-2-g2cb19874 2020-05-21 22:00:10
      os: RRG/Iceman/master/v4.9237-2-g2cb19874 2019-05-21 22:00:26
 compiled with GCC 8.3.1 20190703 (release) [gcc-8-branch revision 273027]

 [ FPGA ]
 LF image built for 2s30vq100 on 2020/02/22 at 12:51:14
 HF image built for 2s30vq100 on 2020/01/12 at 15:31:16

 [ Hardware ] 
  --= uC: AT91SAM7S512 Rev B
  --= Embedded Processor: ARM7TDMI
  --= Nonvolatile Program Memory Size: 512K bytes, Used: 291382 bytes (56%) Free: 232906 bytes (44%)
  --= Second Nonvolatile Program Memory Size: None
  --= Internal SRAM Size: 64K bytes
  --= Architecture Identifier: AT91SAM7Sxx Series
  --= Nonvolatile Program Memory Type: Embedded Flash Memory


pm3 --> 
```

This `pm3 --> ` is the Proxmark3 interactive prompt.


### To get interactive help

For basic help type `help`. Or for help on a set of sub commands type the command followed by `help`. For example `hf mf help`.

### First tests

These commands will return some info about your Proxmark software and hardware status.
```
pm3 --> hw status
pm3 --> hw version
pm3 --> hw tune
```

You are now ready to use your newly flashed proxmark3 device.  Many commands uses the `h` parameter to show a help text.

### To quit the client
```
pm3 --> quit
```
or simple press `CTRL-D`.

## Next steps

Some configuration steps are still needed.

For the next steps, please read the following pages:

* [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)
* [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)
 
