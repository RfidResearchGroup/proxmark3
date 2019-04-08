## 1. Validating proxmark client functionality

If all went well you should get some information about the firmware and memory usage as well as the prompt,  something like this.
We should be able to answer ..can I connect to my proxmark device?   does it respond?

>[=] UART Setting serial baudrate 460800
>
>Proxmark3 RFID instrument
>
> [ CLIENT ]
>
> client: iceman build for RDV40 with flashmem; smartcard;
>
> [ ARM ]
>
> bootrom: iceman/master/4517531c-dirty-unclean 2018-12-13 15:42:24
>
>   os: iceman/master/5a34550a-dirty-unclean 2019-01-07 23:04:07
>
> [ FPGA ]
>
> LF image built for 2s30vq100 on 2018/ 9/ 8 at 13:57:51
>
> HF image built for 2s30vq100 on 2018/ 9/ 3 at 21:40:23
>
> [ Hardware ]
>
>--= uC: AT91SAM7S512 Rev B
>
>--= Embedded Processor: ARM7TDMI
>
>--= Nonvolatile Program Memory Size: 512K bytes, Used: 247065 bytes (47%) Free: 277223 bytes (53%)
>
>--= Second Nonvolatile Program Memory Size: None
>
>--= Internal SRAM Size: 64K bytes
>
>--= Architecture Identifier: AT91SAM7Sxx Series
>
>--= Nonvolatile Program Memory Type: Embedded Flash Memory
>
> pm3 -->

### Run the following commands
    pm3 --> hw status
    pm3 --> hw version
    pm3 --> hw tune

You are now ready to use your newly upgraded proxmark3 device.  Many commands uses the **h** parameter to show a help text. The client uses a arcaic command structure which will be hard to grasp at first.  Here are some commands to start off with.

    pm3 --> hf
    pm3 --> hf 14a info
    pm3 --> lf
    pm3 --> lf search

### Quit client
    pm3 --> quit
