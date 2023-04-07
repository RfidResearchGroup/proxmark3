# Introduction

* `.pm3` are analog signal files to be loaded with `data load` and displayed with `data plot`
* `.trace` are protocol binary data to be loaded with `trace load` and displayed with `trace list <protocol> 1`

# Analog acquisitions

## LF traces

|filename                                 |description|
|-----------------------------------------|-----------|
|lf_AWID-15-259.pm3                       |AWID FSK RF/50 FC: 15 Card: 259 |
|lf_Casi-12ed825c29.pm3                   |casi rusco 40 bit (EM410x ID: 12ed825c29)|
|lf_EM4102-1.pm3                          |credit card style card EM4102 tag (ID: 010872e77c)|
|lf_EM4102-2.pm3                          |credit card style card EM4102 tag (ID: 010872beec)|
|lf_EM4102-3.pm3                          |credit card style card EM4102 tag (ID: 010872e14f)|
|lf_EM4102-clamshell.pm3                  |Samy's clamshell EM4102 tag (ID: 1f00d9b3a5)|
|lf_EM4102-fob.pm3                        |(ID: 0400193cbe)|
|lf_EM4102-thin.pm3                       |Samy's thin credit-card style EM4102 tag (ID: 1a0041375d)|
|lf_EM4x05.pm3                            |ear tag FDX-B ISO-11784/5 (ID: 6DB0840800F80001 - Application Identifier:  8000, Country Code:  124 (Canada), National ID:  270601654)|
|lf_EM4x50.pm3                            |credit card style card EM4x50 tag (ID: DE2A3F00)|
|lf_FDX_Bio-Thermo.pm3                    |FDX Animal tag with Biosensor|
|lf_GALLAGHER.pm3                         |GALLAGHER tag|
|lf_GProx_36_30_14489.pm3                 |G-Prox-II FC: 30 Card: 3949,  Format 36b  ASK/BIPHASE|
|lf_HID-proxCardII-05512-11432784-1.pm3   |clamshell-style HID ProxCard II card|
|lf_HID-weak-fob-11647.pm3                |HID 32bit Prox Card#: 11647.  very weak tag/read but just readable.|
|lf_HomeAgain.pm3                         |HomeAgain animal (cat) tag - ID 985121004515220|
|lf_HomeAgain1600.pm3                     |HomeAgain animal (cat) tag - ID 985121004515220|
|lf_IDTECK_4944544BAC40E069.pm3           |IDTECK raw 4944544BAC40E069 , PSK,  printed  "806 082 43084"|
|lf_IDTECK_4944544B351FBE4B.pm3           |IDTECK raw 4944544B351FBE4B , PSK,  printed  "708 082 14087"|
|lf_IDTECK_idk50_PSK.pm3                  |IDTECK (?)|
|lf_Indala-00002-12345678-1A.pm3          |Indala credit-card style card|
|lf_indala_4041x_234_21801.pm3            |Indala 4041X 26-bit|
|lf_Indala-504278295.pm3                  |PSK 26 bit indala|
|lf_IOProx-XSF-01-3B-44725.pm3            |IO Prox FSK RF/64 ID in name|
|lf_IOProx-XSF-01-BE-03011.pm3            |IO Prox FSK RF/64 ID in name|
|lf_Keri.pm3                              |Keri PSK-3 Key Ring tag (back of tag: 1460 3411)|
|lf_Motorola_0437_00072.pm3               |Motorola Grey clamshell card, old.  (RAW: A0000000E308C0C1)|
|lf_NEXWATCH_Nexkey_74755342.pm3          |NEXWATCH, Nexkey ID: 74755342|
|lf_NEXWATCH_Quadrakey-521512301.pm3      |NEXWATCH, Quadrakey ID: 521512301|
|lf_NEXWATCH_Securakey-64169.pm3          |Securakey Tag BitLen: 26, Card ID: 64169, FC: 0x35|
|lf_PAC-8E4C058E.pm3                      |PAC/Stanley 20204/21020 PAC8 tag (ID: 8E4C058E)|
|lf_Paradox-96_40426-APJN08.pm3           |PARADOX FC 96 CN 40426|
|lf_TI.pm3                                |TI HDX FSK 134.2 / 123.2kHz, zerocross line acquisition at 2 MHz|
|lf_Transit999-best.pm3                   |Transit 999 format (UID 99531670)|
|lf_VeriChip_1022000000084146.pm3         |VeriChip,  epoxy encased glasschip (ID: 1022-00000000084146) |
|lf_VISA2000.pm3                          |VISA2000 ASK/MAN RF/64, Card: 480518|

## LF test traces

|filename|description|
|--------|-----------|
|lf_Q5_mod-*                              |Q5 configured to emit `00 01 02 03 04 05 06 07 08 09 0A 0B` under various modulation schemes|
|lf_ATA5577_*                             |ATA5577 configured to emulate various techs as suggested in the Proxmark3 clone commands|
|lf_ATA5577.txt                           |Description on how lf_ATA5577_* were generated|

## LF sniffed traces

|filename|description|
|--------|-----------|
|lf_sniff_blue_cloner_em4100.pm3          |Sniffing of blue cloner writing an EM4100 on T5577 and EM4305|
|lf_sniff_ht2-BC3B8810-acg-reader.pm3     |Sniffing of Hitag2 being read by an HID ACG LF Multitag reader|
|lf_sniff_ht2-BC3B8810-frosch-reader.pm3  |Sniffing of Hitag2 being read by a Frosch Hitag reader|
|lf_sniff_ht2-BC3B8810-rfidler-reader.pm3 |Sniffing of Hitag2 being read by a RFIDler|

## HF traces

|filename|description|
|--------|-----------|
|hf_14b_raw_050008_resp.pm3               |Response of 14b card to `hf 14b raw -c 050008`|
|hf_14b_raw_0600_st_sri512.pm3            |Response of ST SRI512 to `hf 14b raw -c 0600`|
|hf_14b_raw_0600_st_sri512_collision.pm3  |Same but with two cards, showing the collisions in answers|
|hf_14b_raw_10_ask_ctx.pm3                |Response of ASK CTx to `hf 14b raw -c 10`|
|hf_14b_raw_010fxxxxxxxx_innovatron.pm3   |Response of 14b' card to `hf 14b raw -c -k 010fxxxxxxxx`|

## HF sniffed traces

|filename|description|
|--------|-----------|
|hf_sniff_14b_scl3711.pm3                 |`hf sniff 15000 2` <> `nfc-list -t 8`: PUPI: c12c8b1b AppData: 00000000 ProtInfo: 917171|


# Demodulated acquisitions

## HF demodulated traces

|filename|description|
|--------|-----------|
|hf_14a_reader_4b.trace                   |Execution of `hf 14a reader` against a 4b UID card|
|hf_14a_reader_4b_rats.trace              |Execution of `hf 14a reader` against a 4b UID card with RATS|
|hf_14a_reader_7b_rats.trace              |Execution of `hf 14a reader` against a 7b UID card with RATS|
|hf_14a_mfu.trace                         |Reading of a password-protected MFU|
|hf_14a_mfuc.trace                        |Reading of a UL-C with 3DES authentication|
|hf_14a_mfu-sim.trace                     |Trace seen from a Proxmark3 simulating a MFU|
|hf_14b_reader.trace                      |Execution of `hf 14b reader` against a card|
|hf_14b_cryptorf_select.trace             |Sniff of libnfc select / anticollision ofa cryptoRF tag|
|hf_15_reader.trace                       |Execution of `hf 15 reader` against a card|
|hf_mfp_mad_sl3.trace                     |`hf mfp mad`|
|hf_mfp_read_sc0_sl3.trace                |`hf mfp rdsc --sn 0 -k ...`|
|hf_visa_apple_ecp.trace                  |Sniff of VISA Apple ECP transaction|
|hf_visa_apple_normal.trace               |Sniff of VISA Apple normal transaction|
|hf_visa_apple_transit_bypass.trace       |Sniff of VISA Apple transaction bypass|
|hf_mfdes_sniff.trace                     |Sniff of HID reader reading a MIFARE DESFire SIO card|
|hf_iclass_sniff.trace                    |Sniff of HID reader reading a Picopass 2k card|
|hf_mf_hid_sio_sim.trace                  |Simulation of a HID SIO MFC 1K card|
