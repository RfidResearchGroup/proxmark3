# Notes on CIPURSE card
<a id="Top"></a>

# Table of Contents

- [Notes on CIPURSE card](#notes-on-cipurse-card)
- [Table of Contents](#table-of-contents)
  - [Documentation](#documentation)
  - [Source code](#source-code)
  - [Communication channel with a card](#communication-channel-with-a-card)
  - [Card architecture](#card-architecture)
  - [How to](#how-to)
    - [How to personalize card](#how-to-personalize-card)


## Documentation
^[Top](#top)

Useful links to documentation about CIPURSE.
[full documentation accessible from osptalliance](https://www.osptalliance.org/)
[Infineon cipurse](https://www.infineon.com/cms/en/product/security-smart-card-solutions/cipurse-products/)
[Infineon cipurse card SLS 32TLC100(M)](https://www.infineon.com/cms/en/product/security-smart-card-solutions/cipurse-products/sls-32tlc100m/)


## Source code
^[Top](#top)

Useful links to Implementations / Source code on Github.
[cipurse card emulation](https://github.com/duychuongvn/demo-nfc/tree/master/smart-ticket-demo/app/src/main/java/ch/smartlink/smartticketdemo/cipurse)
[cipurse card core](https://github.com/duychuongvn/cipurse-card-core)
[card side some code](https://github.com/duychuongvn/cipurse-card-side)


## Communication channel with a card
^[Top](#top)

The card has two secure channels - the reader to the card and the card to the reader.

And each channel has 3 modes: `open, MACed, Encrypted`

After authentication reader can specify the mode for each channel for each command.

Card answers if the mode that sets by the reader matches the mode of the file and the command matches the key via an access list.

## Card architecture
^[Top](#top)

The card has one master file with FID 0x3F00 that works as the root node.

The card has several applications inside the master file and the applications may have files. There are PxSE (special type) applications that work as an applications directory.

Each application has keys and an access control list that sets what commands can be issued in the session that authenticates with a specific key.

Master file have keys and an access control list that works at the card level.

Each file can only have an access control list that specifies what operation the key can do with this file.

## How to

### How to personalize card
^[Top](#top)

1. Format card (if it needs) 
```hf cipurse formatall```

2. Create create PxSE file

The following command creates PTSE file with FID 0x2000, AID A0000005070100, and space for 8 AIDs

```hf cipurse create -d 9200123F00200008000062098407A0000005070100```

```
9200123F00200008000062098407A0000005070100
          ----                               FID
              --                             Num of AIDs in list
                            --------------   AID
```


3. Create application file

```hf cipurse create -d 92002438613F010A05020000FFFFFF021009021009621084054144204631D407A0000005070100A00F2873737373737373737373737373737373015FD67B000102030405060708090A0B0C0D0E0F01C6A13B```

This command creates a application with following details:
  - FID.................... 0x3F01
  - AID.................... 4144204631
  - App type............... 61
  - Max files count........ 10
  - Max SFID count......... 5
  - Minimum command's group security levels plain/plain/plain/plain (0000)
  - Access rights.......... all two keys can do anything (FFFFFF)
  - Key attributes......... 021009
  - 2 keys.........
    - `73..73`     (add. info 01 / kvv 5FD67B)
    - `0001..0e0f` (01/C6A13B)
  - Register in the PxSE... A0000005070100

