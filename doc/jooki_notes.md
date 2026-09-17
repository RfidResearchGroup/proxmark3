# Jooki Figurine Notes
<a id="top"></a>

# Table of Contents
- [Jooki Figurine Notes](#jooki-figurine-notes)
- [Table of Contents](#table-of-contents)
  - [Jooki proxmark commands](#jooki-proxmark-commands)
    - [Decoding NDEF URL parameter](#decoding-ndef-url-parameter)
    - [Encoding NDEF record](#encoding-ndef-record)
    - [Simulation](#simulation)
    - [Cloning to a NTAG213 tag](#cloning-to-a-ntag213-tag)
    - [List of known figurine types](#list-of-known-figurine-types)



- NTAG213 (Should be tested if other NTAG2xx work)
- A single NDEF record of type URL
- Physical figurines are Fox, Dragon, Knight, Ghost, Whale, Generic Flat. Than there are variations of those figures with different colors.

## Jooki proxmark commands
^[Top](#top)

You can `encode`, `decode` a NDEF record, write with `clone` a record to a card or simulate with`sim`.

### Decoding NDEF URL parameter
^[Top](#top)

`hf jooki decode -d g+t07s57aX1bB6tk`

### Encoding NDEF record
^[Top](#top)

You can either use figurine abbreviation arguments:
```
    --dragon 
    --fox   
    --ghost
    --knight 
    --whale   
    --blackdragon   
    --blackfox     
    --blackknight 
    --blackwhale 
    --whitedragon 
    --whitefox    
    --whiteknight 
    --whitewhale 
```
Or pass directly the figurine type id `--tid` and figurine id `--fid`

Example encoding NDEF record for UID `04010203040506`

`hf jooki encode --uid 04010203040506 --tid 1 --fid 1`

or use `--dragon` parameter to achieve the same:


`hf jooki encode --uid 04010203040506 --dragon`

Output:
```
[=] Encoded URL.. 67 2B 74 30 37 73 35 37 61 58 31 62  ( g+t07s57aX1bB6tk )
[=] Figurine..... 01 00 - Figurine, Dragon
[=] iv........... 80 77 51 
[=] uid.......... 04 01 02 03 04 05 06 
[=] NDEF raw..... 0103A00C340329D101255504732E6A6F6F6B692E726F636B732F732F3F733D672B743037733537615831624236746B0AFE000000
```

Use `-r` parameter to read UID directly from tag.

### Simulation
^[Top](#top)

To simulate the above figurine use the encoded URL parameter given in `encode` output and type following command into your proxmark:
 
`hf jooki sim -b g+t07s57aX1bB6tk`

If no parameter is given to the simulation command, last loaded dump is used.

### Cloning to a NTAG213 tag
^[Top](#top)

```
    hf jooki clone [-h] [-b <base64>] [-d <hex>] [-p <hex>]

options:
    -h, --help                     This help
    -b, --b64 <base64>             base64 url parameter
    -d, --data <hex>               raw NDEF bytes
    -p, --pwd <hex>                password for authentication (EV1/NTAG 4 bytes)

examples/notes:
    hf jooki clone -d <hex bytes>  -> where hex is raw NDEFhf jooki clone --b64 7WzlgEzqLgwTnWNy --> using base64 url parameter
```

Use either the above NDEF raw output from `encode` to write a new record to a tag:

`hf jooki clone -d 0103A00C340329D101255504732E6A6F6F6B692E726F636B732F732F3F733D672B743037733537615831624236746B0AFE000000`

or use the base64 encoded parameter to clone:

`hf jooki clone -b A5wlbrkq6QoKh9w1


Note: Jooki doesn't like more than one NDEF record, so make sure you just have one. Check with `hf mfu ndefread`

### List of known figurine types
^[Top](#top)

`Value`|`Figurine Type`|
|------|---------------|
**01** | Stones |
**02** | Generic Flat |         
**03** | System Commands |          
**04** | Tests |

| `Figurine Type` | `Figurine ID` | `Figurine`           |
|---------------|-------------|--------------------------|
| 01            | 00          | 狐狸 Fox                 |
| 01            | 01          | 龙 Dragon                |
| 01            | 02          | 骑士 Knight              |
| 01            | 03          | 鬼 Ghost                 |
| 01            | 04          | 鲸 Whale                 |
| 01            | 05          | ThankYou                 |
| 01            | 06          | Black.Fox                |
| 01            | 07          | Black.Dragon             |
| 01            | 08          | Black.Whale              |
| 01            | 09          | Black.Knight             |
| 01            | 0a          | White.Fox                |
| 01            | 0b          | White.Dragon             |
| 01            | 0c          | White.Whale              |
| 01            | 0d          | White.Knight             |
|               |             |                          |
|     `02`      |             |      `Generic Flat`      |
| 02            | 00          | 圆盘 Generic Flat        |
| 02            | 01          | unknown_0201             |
|               |             |                          |
|     `03`      |             |    `System Commands`     |
| 03            | 00          | sys.record               |
| 03            | 01          | sys.factory_mode_on      |
| 03            | 02          | sys.factory_mode_off     |
| 03            | 03          | sys.airplane_mode_on     |
| 03            | 04          | sys.airplane_mode_off    |
| 03            | 05          | sys.toy_safe_on          |
| 03            | 06          | sys.toy_safe_off         |
| 03            | 07          | sys.wifi_on              |
| 03            | 08          | sys.wifi_off             |
| 03            | 09          | sys.bt_on                |
| 03            | 0a          | sys.bt_off               |
| 03            | 0b          | sys.production_finished  |
|               |             |                          |
|     `04`      |             |         `Tests`          |
| 04            | 00          | Hello test.0             |
| 04            | 01          | Hello test.1             |
| 04            | 02          | Hello test.2             |
| 04            | 03          | Hello test.3             |
| 04            | 04          | Hello test.4             |
| 04            | 05          | Hello test.5             |
| 04            | 06          | Hello test.6             |
| 04            | 07          | Hello test.7             |
| 04            | 08          | Hello test.8             |
| 04            | 09          | Hello test.9             |
| 04            | 0a          | Hello unknown_040A       |
| 04            | 10          | Hello test.10            |
| 04            | 11          | Hello test.11            |
| 04            | 12          | Hello test.12            |
| 04            | 13          | Hello test.13            |
| 04            | 14          | Hello test.14            |
| 04            | 15          | Hello test.15            |
| 04            | 16          | Hello test.16            |
| 04            | 17          | Hello test.17            |
| 04            | 18          | Hello test.18            |
| 04            | 19          | Hello test.19            |

