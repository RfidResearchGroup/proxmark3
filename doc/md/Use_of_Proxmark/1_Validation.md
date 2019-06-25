## 1. Validating proxmark client functionality

If all went well you should get some information about the firmware and memory usage as well as the prompt,  something like this.

```

██████╗ ███╗   ███╗ ████╗      ...iceman fork
██╔══██╗████╗ ████║   ══█║       ...dedicated to RDV40 
██████╔╝██╔████╔██║ ████╔╝ 
██╔═══╝ ██║╚██╔╝██║   ══█║     iceman@icesql.net
██║     ██║ ╚═╝ ██║ ████╔╝    https://github.com/rfidresearchgroup/proxmark3/
╚═╝     ╚═╝     ╚═╝ ╚═══╝  pre-release v4.0

Support iceman on patreon,   https://www.patreon.com/iceman1001/


[=] Using UART port /dev/pm3-0 
[=] Communicating with PM3 over USB-CDC 

 [ Proxmark3 RFID instrument ] 


 [ CLIENT ]
  client: RRG/Iceman

 [ PROXMARK RDV4 ]
  external flash:                  present 
  smartcard reader:                present 

 [ PROXMARK RDV4 Extras ]
  FPC USART for BT add-on support: absent 

 [ ARM ]
 bootrom: RRG/Iceman/master/5ab9716e 2019-05-01 11:02:08
      os: RRG/Iceman/master/6b5a0f83 2019-05-04 23:57:47

 [ FPGA ]
 LF image built for 2s30vq100 on 2019/ 4/18 at  9:35:32
 HF image built for 2s30vq100 on 2018/ 9/ 3 at 21:40:23

 [ Hardware ] 
  --= uC: AT91SAM7S512 Rev B
  --= Embedded Processor: ARM7TDMI
  --= Nonvolatile Program Memory Size: 512K bytes, Used: 250913 bytes (48%) Free: 273375 bytes (52%)
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
 
