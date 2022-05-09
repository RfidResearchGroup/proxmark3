# Notes on Setting up NDEF (NDEF type4a)
<a id="Top"></a>

# Table of Contents

- [Notes on Setting up NDEF type4a](#Notes-on-Setting-up-NDEF)
- [Table of Contents](#table-of-contents)
  - [NDEF on Desfire EV1](#NDEF-on-Desfire-EV1)
    - [Step 1. Create Application](#Step-1-Create-Application)
    - [Step 2. Create the Capability Container file (CC File)](#Step-2-Create-the-Capability-Container-file-CC-File)
    - [Step 3. Create the NDEF Record File](#Step-3-Create-the-NDEF-Record-File)
  - [Check the NDEF Record works](#Check-the-NDEF-Record-works)

## NDEF type4a on Desfire EV1
^[Top](#top)

The follow is a guide to assist in setting up a single NDEF record on an Desfire EV1 (or later).
Please refere to the NDEF documention and standards for assistance on the actual NDEF record setup and structure.

It is assumed you are fimular with using a desfire cards and commands.

The follow notes are based on:
    NXP - AN11004 - MIFARE DESFire as Type 4 Tag
    Rev. 2.4 - 22 May 2013

In order to setup NDEF on a Mifare Desfire card you need to create an Application and two files inside that application.
The application and files have some special needs in order for the standands to work and the NDEF recrod to be found.

### Step 1 Create Application

While I beleive the App ID and File IDs dont matter (for EV1 and later)
I did find a reference to using the values in this example.

The Application MUST have the DFName of D2760000850101  
Note: That is the hex/binary data that needs to be stored!

    DF Name         : D2760000850101            <- **Important MUST be D2760000850101**  
    AID             : 000001                    <- In EV1 and later can be any AID  
    FID             : E110                      <- In EV1 and later can be any App - FID  
    Keys            : 1                         <- Any number of keys (based on your needs)  
    Encryption      : AES                       <- Any encryption.  
    ISO 2 Byte FID  : Yes                       <- **Important MUST support 2 Byte ISO File IDs**  

***Proxmark Command***  
```    hf mfdes createapp --aid 000001 --fid E110 --ks1 0B --ks2 A1 --dfhex D2760000850101 -t des -n 0 -k 0000000000000000```

Result  
```    [+] Desfire application 000001 successfully created```

### Step 2 Create the Compatibility Container file (CC File)

The CC File is a standard file to store the needed NDEF information to find your NDEF records.  This example will contrain the setup for a single NDEF record.
Note: You can define more then one NDEF data file if needed (not covered in this example)

    Type            : Standard data file
    FID             : 01                        <- File ID can be any uniqure File ID for this AID
    ISO FID         : E103                      <- **Important MUST be the 2 byte ISO File of E103**
    Size            : 0F (15 bytes)             <- May need to be longer in more advanced setups.
    Comms           : Plain                     <- **Important the file MUST support plain communication mode**
    Permissions     : E000                      <- **Read Free** write change etc key 0)  
                                                    Note: To allow public update, set Write to E as well.
                                                          All keys should be set as per normal desfire rules.

CC File (E103) example

    000F20003B00340406E10400FF00FF

Usefull items in the CC File

    000F20003B00340406 E104 00FF 00 FF
                         |    |      |
                         |    |       --- 00 = Write allowed, FF = Read Only 
                         |     ---------- The maxium size of the NDEF record (set to the NDEF record file size)
                          --------------- The ISO 2 byte File ID for the NDEF Record file
                          

    Note: the NDEF Record File Size should be <= the actual data file size and >= the amount of data you have. Its not how long the actual NDEF record is.

***Proxmark Commands***  

Create the CC file  

    hf mfdes createfile --aid 000001 --fid 01 --isofid E103 --amode plain --size 00000F --rrights free --wrights key0 --rwrights key0 --chrights key0 -n 0 -t aes -k 00000000000000000000000000000000 -m plain  

Result:  

    [=] ---- Create file settings ----
    [+] File type        : Standard data
    [+] File number      : 0x01 (1)
    [+] File ISO number  : 0xe103
    [+] File comm mode   : Plain
    [+] Additional access: No
    [+] Access rights    : e000
    [+] read     : free
    [+] write    : key 0x00
    [+] readwrite: key 0x00
    [+] change   : key 0x00
    [=] File size        : 15 (0xF) bytes
    [+] Standard data file 01 in the app 000001 created successfully

Write the CC record to the file  

    hf mfdes write --aid 000001 --fid 01 -d 000F20003B00340406E10400FF00FF -n 0 -t aes -k 00000000000000000000000000000000 -m plain

Result  

    [=] Write data file 01 success

Check the contents of the CC file (note: no-auth was selected to ensure we can read without authentication, as needed for normal ndef discovery)  

    hf mfdes read --no-auth --aid 000001 --fid 01

Result  

    [=] ------------------------------- File 01 data -------------------------------
    [+] Read 15 bytes from file 0x01 offset 0
    [=]  Offset  | Data                                            | Ascii
    [=] ----------------------------------------------------------------------------
    [=]   0/0x00 | 00 0F 20 00 3B 00 34 04 06 E1 04 00 FF 00 FF    | .. .;.4........


### Step 3 Create the NDEF Record File


    Type            : Standard data file
    FID             : 02                        <- File ID can be any uniqure File ID for this AID
    ISO FID         : E104                      <- **Important MUST be the 2 byte ISO File set in the CC File**
    Size            : 00FF (255 bytes)          <- Can be as big as needed, but should not be smaller then the value in the CC File
    Comms           : Plain                     <- **Important the file MUST support plain communication mode**
    Permissions     : E000                      <- **Read Free** write change etc key 0)  
                                                    Note: To allow public update set Write to E as well.
                                                          All keys should be set as per normal desfire rules.


NDEF data file example

    000CD1010855016E78702E636F6DFE

Usefull Items in this NDEF example record

    000C D10108 55 01 6E78702E636F6D FE
      |          |  |        |
      |          |  |         ----------- nxp.com  
      |          |   -------------------- Well known record sub-type : 01 HTTP://, 02 HTTPS://
      |           ----------------------- ASCII U - URI
       ---------------------------------- Lenght of the NDEF record (not inluding the trailing FE

***Proxmark Commands***

Create the NDEF record file  

    hf mfdes createfile --aid 000001 --fid 02 --isofid E104 --amode plain --size 0000FF --rrights free --wrights key0 --rwrights key0 --chrights key0 -n 0 -t aes -k 00000000000000000000000000000000 -m plain

Result:  

    [=] ---- Create file settings ----
    [+] File type        : Standard data
    [+] File number      : 0x02 (2)
    [+] File ISO number  : 0xe104
    [+] File comm mode   : Plain
    [+] Additional access: No
    [+] Access rights    : e000
    [+] read     : free
    [+] write    : key 0x00
    [+] readwrite: key 0x00
    [+] change   : key 0x00
    [=] File size        : 255 (0xFF) bytes
    [+] Standard data file 02 in the app 000001 created successfully

Write an NDEF record to the file  

    hf mfdes write --aid 000001 --fid 02 -d 000CD1010855016E78702E636F6DFE -n 0 -t aes -k 00000000000000000000000000000000 -m plain

Result:  

    [=] Write data file 02 success


## Check the NDEF Record works

You can use any NDEF reading tool or device to check.  If this card is presented to a mobile phone, it should visit the nxp.com web page.

***Proxmark Command***  

Check the contents of the NDEF record file  

    hf mfdes read --no-auth --aid 000001 --fid 02

Result:  

    [=] ------------------------------- File 02 data -------------------------------
    [+] Read 255 bytes from file 0x02 offset 0
    [=]  Offset  | Data                                            | Ascii
    [=] ----------------------------------------------------------------------------
    [=]   0/0x00 | 00 0C D1 01 08 55 01 6E 78 70 2E 63 6F 6D FE 00 | .....U.nxp.com..
    [=]  16/0x10 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=]  32/0x20 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=]  48/0x30 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=]  64/0x40 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=]  80/0x50 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=]  96/0x60 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=] 112/0x70 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=] 128/0x80 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=] 144/0x90 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=] 160/0xA0 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=] 176/0xB0 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=] 192/0xC0 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=] 208/0xD0 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=] 224/0xE0 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    [=] 240/0xF0 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    | ...............

Check if the NDEF record can be read correctly

    nfc type4a read

Result:  

    [+] ------------ Capability Container file ------------
    [+]  Version... v2.0 ( 0x20 )
    [+]  Len....... 15 bytes ( 0x0F )
    [+]  Max bytes read  59 bytes ( 0x003B )
    [+]  Max bytes write 52 bytes ( 0x0034 )
    
    [+]  NDEF file control TLV
    [+]     (t) type of file.... 04
    [+]     (v) ................ 06
    [+]     file id............. E104
    [+]     Max NDEF filesize... 255 bytes ( 0x00FF )
    [+]     Access rights
    [+]     read   ( 00 ) protection: disabled
    [+]     write  ( FF ) protection: enabled
    [+]
    [+] ----------------- raw -----------------
    [+] 000F20003B00340406E10400FF00FF
    
    
    [+] Record 1
    [=] -----------------------------------------------------
    [=] Header info
    [+]   1 ....... Message begin
    [+]    1 ...... Message end
    [+]     0 ..... Chunk flag
    [+]      1 .... Short record bit
    [+]       0 ... ID Len present
    [+]
    [+]  Header length...... 3
    [+]  Type length........ 1
    [+]  Payload length..... 8
    [+]  ID length.......... 0
    [+]  Record length...... 12
    [+]  Type name format... [ 0x01 ] Well Known Record
    [=]
    [=] Payload info
    [=] Type data
    [=]     00: 55                                              | U
    [=] Payload data
    [=]     00: 01 6E 78 70 2E 63 6F 6D                         | .nxp.com
    [=]
    [=] URL
    [=]     uri... http://www.nxp.com
    [=]
