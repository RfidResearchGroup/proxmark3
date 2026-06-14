# arbitrary lf em commands

Goals:
1. Improved logging of `lf em` commands and responses
2. Greater certainty in command sequences
3. Easier testing of new commands

## Methodology

This is documenting the actual commands used by existing code.  Phases include:
* Document the existing command sequences
* Document the existing logging APIs
* Define small set of timing-sensitive functions as abstractions
* Implement the abstractions
* Add logging

The goal is to improve logging and debugging, and allow easily testing new LF commands.

## EM4x70 (aka ID48, aka Megamos)

Only six command sequences currently used:

#define EM4X70_COMMAND_ID                   0x01
#define EM4X70_COMMAND_UM1                  0x02
#define EM4X70_COMMAND_AUTH                 0x03
#define EM4X70_COMMAND_PIN                  0x04
#define EM4X70_COMMAND_WRITE                0x05
#define EM4X70_COMMAND_UM2                  0x07



### ID Command

Wait for `LIW` (listen window), and start transmission at next `LIW`:

source    | bits    | comment
----------|---------|---------
tag       | LIW     | listen window sync
reader    | `0b00`  | RM
reader    | `0b001` | CMD
reader    | `0b1`   | command parity bit
tag       | HEADER  | HEADER (0b1111'1111'1111'0000)
tag       | 32-bits | ID (D31..D0)
tag       | LIW     | tag reverts to be ready for next command

### UM1 Command

source    | bits    | comment
----------|---------|---------
tag       | LIW     | listen window
reader    | `0b00`  | RM
reader    | `0b010` | CMD
reader    | `0b1`   | command parity bit
tag       | 16-bits | HEADER
tag       | 32-bits | UM1 data
tag       | LIW     | tag reverts to be ready for next command

### UM2 Command

source    | bits    | comment
----------|---------|---------
tag       | LIW     | listen window
reader    | `0b00`  | RM
reader    | `0b111` | CMD
reader    | `0b1`   | command parity bit
tag       | 16-bits | HEADER
tag       | 64-bits | UM2 data
tag       | LIW     | tag reverts to be ready for next command


### Auth Command

source    | bits    | comment
----------|---------|---------
tag       | LIW     | listen window
reader    | `0b00`  | RM
reader    | `0b011` | CMD
reader    | `0b0`   | command parity bit
reader    | 56-bits | RN
reader    | 7-bits  | Tdiv == 0b0000000 (always zero)
reader    | 28-bits | f(RN)
tag       | 16-bits | HEADER
tag       | 20-bits | g(RN)
tag       | LIW     | tag reverts to be ready for next command

### Write Word

source    | bits    | comment
----------|---------|---------
tag       | LIW     | listen window
reader    | `0b00`  | RM
reader    | `0b101` | CMD
reader    | `0b0`   | command parity bit
reader    | 4-bits  | address/block to write
reader    | 1-bit   | address/block parity bit
reader    | 25-bits | 5x5 data w/ row and column parity
tag       | ACK     | Wait (TWA) for ACK ... time to wait before searching for ACK
tag       | ACK     | Wait (WEE) for ACK ... time to wait before searching for ACK
tag       | LIW     | tag reverts to be ready for next command




### PIN Command

source    | bits    | comment
----------|---------|---------
tag       | LIW     | listen window
reader    | `0b00`  | RM
reader    | `0b100` | CMD
reader    | `0b1`   | command parity bit
reader    | 32-bits | ID of the tag
reader    | 32-bits | PIN
tag       | ACK     | Wait (TWALB) for ACK  ... time to wait before searching for ACK
tag       | HEADER  | DELAYED (TWEE) header ... time to wait before searching for header
tag       | 32-bits | ID of the tag
tag       | LIW     | tag reverts to be ready for next command


### Abstraction required

Possible items to abstract:
* bits to send: quantity of bits to be sent + storage containing those bits
* bits to receive: expected bits to receive + storage to receive those bits
* LIW: special-case handling to synchronize next command
* ACK: special-case handling to wait for ACK
* HEADER: special-case handling to wait for HEADER
* DELAY:  ticks to delay before processing next item

Special handling required for:
* `HEADER` --> 12-bits of zero, 4-bits of one.  Consider a timeout: if tag disappears, no pulse found, while sometimes expect long time before HEADER appears (as in SEND_PIN).  Read of header may miss the first few bits during transition, so need to special-case handling of this detection.
* `LIW` --> Timing-sensitive, syncs reader with tag ... reader must send during 32 period where chip's modulator is ON.
* `ACK` --> This is currently a time-to-delay.
            Should this be a maximum time to wait for ACK?
            Currently, could sit waiting for long time
            if no tag present, as `check_ack()` has no timeout.

```C
WaitTicks(EM4X70_T_TAG_TWA);
if (check_ack())
    WaitTicks(EM4X70_T_TAG_WEE);
    if (check_ack())
        return PM3_SUCCESS;
```



