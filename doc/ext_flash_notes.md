# External flash

External 256kbytes flash is a unique feature of the RDV4 edition.

## Addresses

Flash memory is

* 256kb (0x40000= 262144)
* divided into 4 pages of 64kb (0x10000 = 65536)
* 4 pages divided into 16 sectors of 4kb (0x1000 = 4096), so last sector is at 0x3F000

Therefore a flash address can be interpreted as such:
```
0xPSxxx       e.g. 0x3FF7F
  ^ page             ^ page 3
   ^ sector           ^ sector 0xF
    ^^^ offset         ^^^ offset 0xF7F
```

## Layout

Page 0:
* available for user data
* to dump it: `mem dump f page0_dump o 0 l 65536`
* to erase it: `mem wipe p 0`

Page 1:
* available for user data
* to dump it: `mem dump f page1_dump o 65536 l 65536`
* to erase it: `mem wipe p 1`

Page 2:
* available for user data
* to dump it: `mem dump f page2_dump o 131072 l 65536`
* to erase it: `mem wipe p 2`

Page 3:
* used by Proxmark3 RDV4 specific functions: flash signature and keys dictionaries, see below for details
* to dump it: `mem dump f page3_dump o 196608 l 65536`
* to erase it:
  * **Beware** it will erase your flash signature (see below) so better to back it up first as you won't be able to regenerate it by yourself!
  * It's possible to erase completely page 3 by erase the entire flash memory with the voluntarily undocumented command `mem wipe i`.
  * Updating keys dictionaries doesn't require to erase page 3.

## Page3 Layout

Page3 is used as follows by the Proxmark3 RDV4 firmware:

* **MF_KEYS**
  * offset: page 3 sector  9 (0x9) @ 3*0x10000+9*0x1000=0x39000
  * length: 2 sectors

* **ICLASS_KEYS**
  * offset: page 3 sector 11 (0xB) @ 3*0x10000+11*0x1000=0x3B000
  * length: 1 sector

* **T55XX_KEYS**
  * offset: page 3 sector 12 (0xC) @ 3*0x10000+12*0x1000=0x3C000
  * length: 1 sector

* **T55XX_CONFIG**
  * offset: page 3 sector 13 (0xD) @ 3*0x10000+13*0x1000=0x3D000
  * length: 1 sector (actually only a few bytes are used to store `t55xx_config` structure)

* **RSA SIGNATURE**, see below for details
  * offset: page 3 sector 15 (0xF) offset 0xF7F @ 3*0x10000+15*0x1000+0xF7F=0x3FF7F
  * length: 128 bytes
  * offset should have been 0x3FF80 but historically it's one byte off and therefore the last byte of the flash is unused

## RSA signature

To ensure your Proxmark3 RDV4 is not a counterfeit product, its external flash contains a RSA signature of the flash unique ID.
You can verify it with: `mem info`

```
[usb] pm3 --> mem info
          
[=] --- Flash memory Information ---------
          
[=] -------------------------------------------------------------          
[=] ID            | xx xx xx xx xx xx xx xx           
[=] SHA1          | xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx           
[=] RSA SIGNATURE |          
[00] | xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx 
[01] | xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx 
[02] | xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx 
[03] | xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx 
[=] KEY length   | 128          
[+] RSA key validation ok          
[+] RSA Verification ok          
```

For a backup of the signature: `mem dump p f flash_signature_dump o 262015 l 128`

