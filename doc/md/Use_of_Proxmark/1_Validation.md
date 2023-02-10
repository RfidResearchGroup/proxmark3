<a id="Top"></a>

# 1. Validating Proxmark3 client functionality

# Table of Contents
- [1. Validating Proxmark3 client functionality](#1-validating-proxmark3-client-functionality)
- [Table of Contents](#table-of-contents)
    - [To get interactive help](#to-get-interactive-help)
    - [First tests](#first-tests)
    - [To quit the client](#to-quit-the-client)
  - [Next steps](#next-steps)



If all went well you should get some information about the firmware and memory usage as well as the prompt,  something like this.

```
[=] Session log /home/iceman/.proxmark3/logs/log_20230208.txt
[+] loaded from JSON file /home/iceman/.proxmark3/preferences.json
[=] Using UART port /dev/ttyS3
[=] Communicating with PM3 over USB-CDC


  8888888b.  888b     d888  .d8888b.
  888   Y88b 8888b   d8888 d88P  Y88b
  888    888 88888b.d88888      .d88P
  888   d88P 888Y88888P888     8888"
  8888888P"  888 Y888P 888      "Y8b.
  888        888  Y8P  888 888    888
  888        888   "   888 Y88b  d88P
  888        888       888  "Y8888P"    [ ☕ ]


 [ Proxmark3 RFID instrument ]

    MCU....... AT91SAM7S512 Rev A
    Memory.... 512 Kb ( 66% used )

    Client.... Iceman/master/v4.16191 2023-02-08 22:54:30
    Bootrom... Iceman/master/v4.16191 2023-02-08 22:54:26
    OS........ Iceman/master/v4.16191 2023-02-08 22:54:27
    Target.... RDV4
 
[usb] pm3 -->
```

This `[usb] pm3 --> ` is the Proxmark3 interactive prompt.


### To get interactive help
^[Top](#top)

For basic help type `help`. Or for help on a set of sub commands type the command followed by `help`. For example `hf mf help`.
All commands now implement `-h` or `--help` parameter to give basic instructions on how to use the command.

### First tests
^[Top](#top)

These commands will return some info about your Proxmark software and hardware status.
```
[usb] pm3 --> hw status
[usb] pm3 --> hw version
[usb] pm3 --> hw tune
```

You are now ready to use your newly flashed proxmark3 device.  Many commands uses the `h` parameter to show a help text.

### To quit the client
^[Top](#top)

```
[usb] pm3 --> quit
```
or simple press `CTRL-D`  on an empty line.

## Next steps
^[Top](#top)

Some configuration steps are still needed.

For the next steps, please read the following pages:

* [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)
* [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)
 
