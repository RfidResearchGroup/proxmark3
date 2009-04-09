Modifications to 20081211 release by d18c7db on proxmark.org

This compiles fine under the pre-built windows compile environment ProxSpace

I make no apologies for the utterly cr@p coding. It's rubbish, you've been warned.

Changes made to armsrc and winsrc, no changed to fpga code. Works fine with the bootloader and fpga images that you will build using the 20081211 release.


Extra functionality includes:

ISO1443a support
================

i) Support for cascade 2 select (used for UID's longer than 4 bytes)
ii) Hard-coded (some) responses in for DESfire 


ISO15563 support
================

i) demodulation all moved onto the arm
ii) Addition of a command, hi15reader (a reader simulator)
iii) Addition of a command, hi15sim (a tag simulator) - not working too well



greg.jones@digitalassurance.com