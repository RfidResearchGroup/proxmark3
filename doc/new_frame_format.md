# New frame format documentation
<a id="Top"></a>

This document is primarily intended for developers only.

A major change is the support of variable length frames between host and Proxmark3.  
This is a step especially important for usage over FPC/USART/BT.


# Table of Contents
- [New frame format documentation](#new-frame-format-documentation)
- [Table of Contents](#table-of-contents)
  - [Old format](#old-format)
  - [New format](#new-format)
  - [Transition](#transition)
  - [New format API](#new-format-api)
    - [On the client, for sending frames](#on-the-client-for-sending-frames)
    - [On the Proxmark3, for receiving frames](#on-the-proxmark3-for-receiving-frames)
    - [On the Proxmark3, for sending frames](#on-the-proxmark3-for-sending-frames)
    - [On the client, for receiving frames](#on-the-client-for-receiving-frames)
  - [API transition](#api-transition)
  - [Bootrom](#bootrom)
    - [On the Proxmark3, for receiving frames](#on-the-proxmark3-for-receiving-frames-1)
    - [On the Proxmark3, for sending frames](#on-the-proxmark3-for-sending-frames-1)
    - [On the client, for sending frames](#on-the-client-for-sending-frames-1)
    - [On the client, for receiving frames](#on-the-client-for-receiving-frames-1)
  - [New usart RX FIFO](#new-usart-rx-fifo)
  - [Timings](#timings)
  - [Reference frames](#reference-frames)

## Old format
^[Top](#top)

Previously, frames were, in both directions like this:

    uint64_t cmd;
    uint64_t arg[3];
    union {
        uint8_t  asBytes[PM3_CMD_DATA_SIZE];
        uint32_t asDwords[PM3_CMD_DATA_SIZE / 4];
    } d;

with PM3_CMD_DATA_SIZE = 512 and there was no API abstraction, everybody was forging/parsing these frames.  
So the frame size was fixed, 544 bytes, even for simple ACKs.  
When snooping the USB transfers, we can observe the host is sending 544b Bulk USB frames while the Proxmark3 is limited by its internal buffers and is sending 128b, 128b, 128b, 128b, 32b, so in total 5 packets.

## New format
^[Top](#top)

Even if we make the payload part variable in the old format, we've still a minimum of 32 bytes per frame with fields arbitrarily large.
So we designed a new format from scratch:

For commands being sent to the Proxmark3:

    uint32_t magic;
    uint16_t length : 15;
    bool ng : 1;
    uint16_t cmd;
    uint8_t  data[length];
    uint16_t crc;

* `magic`:  arbitrary magic (`PM3a`) to help re-sync if needed
* `length`: length of the variable payload, 0 if none, max 512 (PM3_CMD_DATA_SIZE) for now.
* `ng`:     flag to tell if the data is following the new format (ng) or the old one, see transition notes below
* `cmd`:    as previously, on 16b as it's enough
* `data`:   variable length payload
* `crc`:    either an actual CRC (crc14a) or a Magic placeholder (`a3`)

For responses from the Proxmark:

    uint32_t magic;
    uint16_t length : 15;
    bool ng : 1;
    int16_t  status;
    uint16_t cmd;
    uint8_t  data[length];
    uint16_t crc;

* `magic`:  arbitrary magic (`PM3b`) to help re-sync if needed
* `length`: length of the variable payload, 0 if none, max 512 (PM3_CMD_DATA_SIZE) for now.
* `ng`:     flag to tell if the data is following the new format (ng) or the old one, see transition notes below
* `status`: a field to send back the status of the command execution
* `cmd`:    as previously, on 16b as it's enough
* `data`:   variable length payload
* `crc`:    either an actual CRC (crc14a) or a Magic placeholder (`a3`)

We used to send an anonymous ACK, now we're replying with the corresponding command name and a status.
CRC is optional and on reception, the magic `a3` is accepted as placeholder. If it's different then it's checked as a CRC.
By default CRC is user over USART and is disabled over USB, on both directions.

Internal structures used to handle these packets are:
* PacketCommandNGPreamble
* PacketCommandNGPostamble
* PacketCommandNGRaw
* PacketResponseNGPreamble
* PacketResponseNGPostamble
* PacketResponseNGRaw

But they are abstracted from the developer view with a new API. See below.

## Transition
^[Top](#top)

Because it's a long transition to clean all the code from the old format and because we don't want to break stuffs when flashing the bootloader, the old frames are still supported together with the new frames. The old structure is now called `PacketCommandOLD` and `PacketResponseOLD` and it's also abstracted from the developer view with the new API.

## New format API
^[Top](#top)

So the new API is a merge of the old and the new frame formats, to ensure a smooth transition.

The boolean `ng` indicates if the structure is storing data from the old or the new format.
Old format can come from either old 544b frames or mixed frames (variable length but still with oldargs).
After the full transition, we might remove the fields `oldarg` and `ng`.
`PacketCommandNG` and `PacketResponseNG` are the structs used by the API, as seen in a previous section, there are other variable-sized packed structs specifically for the data transmission.

    typedef struct {
        uint16_t cmd;
        uint16_t length;
        uint32_t magic;      //  NG
        uint16_t crc;        //  NG
        uint64_t oldarg[3];  //  OLD
        union {
            uint8_t  asBytes[PM3_CMD_DATA_SIZE];
            uint32_t asDwords[PM3_CMD_DATA_SIZE / 4];
        } data;
        bool ng;             // does it store NG data or OLD data?
    } PacketCommandNG;

    typedef struct {
        uint16_t cmd;
        uint16_t length;
        uint32_t magic;      //  NG
        int16_t  status;     //  NG
        uint16_t crc;        //  NG
        uint64_t oldarg[3];  //  OLD
        union {
            uint8_t  asBytes[PM3_CMD_DATA_SIZE];
            uint32_t asDwords[PM3_CMD_DATA_SIZE / 4];
        } data;
        bool ng;             // does it store NG data or OLD data?
    } PacketResponseNG;


### On the client, for sending frames
^[Top](#top)

(`client/comms.c`)

    void SendCommandNG(uint16_t cmd, uint8_t *data, size_t len);
    void SendCommandBL(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len);
    void SendCommandOLD(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len);
    void SendCommandMIX(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len);

So cmds should make the transition from `SendCommandOLD` to `SendCommandNG` to benefit from smaller frames (and armsrc handlers adjusted accordingly of course).  
`SendCommandBL` is for Bootloader-related activities, see Bootrom section.  
`SendCommandMIX` is a transition fct: it uses the same API as `SendCommandOLD` but benefits somehow from variable length frames. It occupies at least 24b of data for the oldargs and real data is therefore limited to PM3_CMD_DATA_SIZE - 24 (defined as PM3_CMD_DATA_SIZE_MIX). Besides the size limitation, the receiver handler doesn't know if this was an OLD frame or a MIX frame, it gets its oldargs and data as usual.  
Warning : it makes sense to move from `SendCommandOLD` to `SendCommandMIX` only for *commands with small payloads*.
* otherwise both have about the same size
* `SendCommandMIX` has a smaller payload (PM3_CMD_DATA_SIZE_MIX < PM3_CMD_DATA_SIZE) so it's risky to blindly move from OLD to MIX if there is a large payload.

Internally these functions prepare the new or old frames and call `uart_communication` which calls `uart_send`.

### On the Proxmark3, for receiving frames
^[Top](#top)

(`armsrc/appmain.c`)

    PacketCommandNG

`AppMain` calls `receive_ng`(`common/cmd.c`) which calls `usb_read_ng`/`usart_read_ng` to get a `PacketCommandNG`, then passes it to `PacketReceived`.
(no matter if it's an old frame or a new frame, check `PacketCommandNG.ng` field to know if there are `oldargs`)  
`PacketReceive` is the commands broker.  
Old handlers will still find their stuff in `PacketCommandNG.oldarg` field.

### On the Proxmark3, for sending frames
^[Top](#top)

(`common/cmd.c`)

    int16_t reply_ng(uint16_t cmd, int16_t status, uint8_t *data, size_t len)
    int16_t reply_old(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len)
    int16_t reply_mix(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len)

So replies should make the transition from `reply_old` to `reply_ng` to benefit from smaller frames (and client reception adjusted accordingly of course).  
`reply_mix` is a transition fct: it uses the same API as reply_old but benefits somehow from variable length frames. It occupies at least 24b of data for the oldargs and real data is therefore limited to PM3_CMD_DATA_SIZE - 24. Besides the size limitation, the client command doesn't know if this was an OLD frame or a MIX frame, it gets its oldargs and data as usual.

Example of a handler that supports both OLD/MIX and NG command styles and replies with the new frame format when it receives new command format:

    if (packet->ng) {
        reply_ng(CMD_FOOBAR, PM3_SUCCESS, packet->data.asBytes, packet->length);
    } else {
        // reply_old(CMD_ACK, 0, 0, 0, packet->data.asBytes, packet->length);
        reply_mix(CMD_ACK, 0, 0, 0, packet->data.asBytes, packet->length);
    }

### On the client, for receiving frames
^[Top](#top)

(`client/comms.c`)

    WaitForResponseTimeout ⇒ PacketResponseNG

`uart_communication` calls `uart_receive` and create a `PacketResponseNG`, then passes it to `PacketResponseReceived`.
`PacketResponseReceived` treats it immediately (prints) or stores it with `storeReply`.
Commands do `WaitForResponseTimeoutW` (or `dl_it`) which uses `getReply` to fetch responses.

## API transition
^[Top](#top)

In short, to move from one format to the other, we need for each command:

* (client TX) `SendCommandOLD` ⇒ `SendCommandNG` (with all stuff in ad-hoc PACKED structs in `data` field)
* (pm3 RX) `PacketCommandNG` parsing, from `oldarg` to only the `data` field
* (pm3 TX) `reply_old` ⇒ `reply_ng` (with all stuff in ad-hoc PACKED structs in `data` field)
* (client RX) `PacketResponseNG` parsing, from `oldarg` to only the `data` field

Meanwhile, a fast transition to MIX frames can be done with:

* (client TX) `SendCommandOLD` ⇒ `SendCommandMIX` (but check the limited data size PM3_CMD_DATA_SIZE ⇒ PM3_CMD_DATA_SIZE_MIX)
* (pm3 TX) `reply_old` ⇒ `reply_mix` (but check the limited data size PM3_CMD_DATA_SIZE ⇒ PM3_CMD_DATA_SIZE_MIX)

## Bootrom
^[Top](#top)

Bootrom code will still use the old frame format to remain compatible with other repos supporting the old format and because it would hardly gain anything from the new format:
* almost all frames convey 512b of payload, so difference in overhead is negligible
* bringing flash over usart sounds risky and would be terribly slow anyway (115200 bauds vs. 7M bauds).

`SendCommandBL` is the same as `SendCommandOLD` with a different name to be sure not to migrate it.

### On the Proxmark3, for receiving frames
^[Top](#top)

(`bootrom/bootrom.c`)

    usb_read (common/usb_cdc.c) ⇒ UsbPacketReceived (bootrom.c)
      ⇒ CMD_DEVICE_INFO / CMD_START_FLASH / CMD_FINISH_WRITE / CMD_HARDWARE_RESET

also `usb_enable`, `usb_disable` (`common/usb_cdc.c`)

### On the Proxmark3, for sending frames
^[Top](#top)

(`bootrom/bootrom.c`)

    reply_old (bootrom.c) ⇒ usb_write (common/usb_cdc.c)

also `usb_enable`, `usb_disable` (`common/usb_cdc.c`)

### On the client, for sending frames
^[Top](#top)

Therefore, the flasher client (`client/flasher.c` + `client/flash.c`) must still use these old frames.  
It uses a few commands in common with current client code:

    OpenProxmark
    CloseProxmark
    SendCommandOLD
      ⇒ CMD_DEVICE_INFO / CMD_START_FLASH / CMD_FINISH_WRITE / CMD_HARDWARE_RESET

### On the client, for receiving frames
^[Top](#top)

As usual, old frames are still supported

    WaitForResponseTimeout ⇒ PacketResponseNG

## New usart RX FIFO
^[Top](#top)

USART code has been rewritten to cope with unknown size packets.
* using USART full duplex with double DMA buffer on RX & TX
* using internal FIFO for RX

`usart_init`:
* USART is activated all way long from usart_init(), no need to touch it in RX/TX routines: `pUS1->US_PTCR = AT91C_PDC_RXTEN | AT91C_PDC_TXTEN`

`usart_writebuffer_sync`:
* still using DMA but accepts arbitrary packet sizes
* removed unneeded memcpy
* wait for DMA buffer to be treated before returning, therefore "sync"
* we could make an async version but caller must be sure the DMA buffer remains available!
* as it's sync, no need for next DMA buffer

`usart_read_ng`:
* user tells expected packet length
* relies on usart_rxdata_available to know if there is data in our FIFO buffer
* fetches data from our FIFO
* dynamic number of tries (depending on FPC speed) to wait for asked data

`usart_rxdata_available`:
* polls usart_fill_rxfifo
* returns number of bytes available in our FIFO

`usart_fill_rxfifo`:
* if next DMA buffer got moved to current buffer (`US_RNCR == 0`), it means one DMA buffer is full
  * transfer current DMA buffer data to our FIFO
  * swap to the other DMA buffer
  * provide the emptied DMA buffer as next DMA buffer
* if current DMA buffer is partially filled
  * transfer available data to our FIFO
  * remember how many bytes we already copied to our FIFO

## Timings
^[Top](#top)

Reference (before new format):

    linux usb: #db#   USB Transfer Speed PM3 ⇒ Client = 545109 Bytes/s
On a Windows VM:

    proxspace usb: #db#   USB Transfer Speed PM3 ⇒ Client = 233998 Bytes/s

Over USART:

(`common/usart.h`)  
USART_BAUD_RATE defined there

         9600: #db#   USB Transfer Speed PM3 ⇒ Client =    934 Bytes/s
       115200: #db#   USB Transfer Speed PM3 ⇒ Client =  11137 Bytes/s
       460800: #db#   USB Transfer Speed PM3 ⇒ Client =  43119 Bytes/s
    linux usb: #db#   USB Transfer Speed PM3 ⇒ Client = 666624 Bytes/s (equiv. to ~7Mbaud)


(`pm3_cmd.h`)

Receiving from USART need more than 30ms as we used on USB
else we get errors about partial packet reception

    FTDI   9600 hw status                   ⇒ we need 20ms
    FTDI 115200 hw status                   ⇒ we need 50ms
    FTDI 460800 hw status                   ⇒ we need 30ms
    BT   115200 hf mf fchk --1k -f file.dic ⇒ we need 140ms

    # define UART_FPC_CLIENT_RX_TIMEOUT_MS  170
    # define UART_USB_CLIENT_RX_TIMEOUT_MS  20
    # define UART_TCP_CLIENT_RX_TIMEOUT_MS  300

This goes to `uart_posix.c` `timeval` struct
and `uart_win32.c` `serial_port_windows` struct

It starts at UART_FPC_CLIENT_RX_TIMEOUT_MS and once we detect we're working over USB
it's reduced to UART_USB_CLIENT_RX_TIMEOUT_MS.



Add automatically some communication delay in the `WaitForResponseTimeout` & `dl_it` timeouts.  
Only when using FPC, timeout = 2* empirically measured delay (FTDI cable).  
Empirically measured delay (FTDI cable) with "hw ping -l 512" :

       usb ⇒    6..  32ms
    460800 ⇒   40..  70ms
      9600 ⇒ 1100..1150ms

(`client/comms.c`)

    static size_t communication_delay(void) {
        if (conn.send_via_fpc_usart)  // needed also for Windows USB USART??
            return 2 * (12000000 / uart_speed);
        return 100;
    }

Because some commands send a lot of frames before finishing (hw status, lf read,...),
`WaitForResponseTimeout` & `dl_it` timeouts are reset at each packet reception,
so timeout is actually counted after latest received packet,
it doesn't depend anymore on the number of received packets.

It was needed to tune pm3 RX usart `maxtry` :

(`common/usart.c`)

    uint32_t usart_read_ng(uint8_t *data, size_t len) {
    // Empirical max try observed: 3000000 / USART_BAUD_RATE
    // Let's take 10x
    uint32_t tryconstant = 0;
    #ifdef USART_SLOW_LINK
        // Experienced up to 13200 tries on BT link even at 460800
        tryconstant = 50000;
    #endif
        uint32_t maxtry = 10 * (3000000 / USART_BAUD_RATE) + tryconstant;


`DbpStringEx` using `reply_old`:

    time client/proxmark3 -p /dev/ttyACM0 -c "hw status"
    2.52s
    time client/proxmark3 -p /dev/ttyUSB0 -b 460800 -c "hw status"
    3.03s
    time client/proxmark3 -p /dev/ttyUSB0 -b 115200 -c "hw status"
    4.88s
    time client/proxmark3 -p /dev/ttyUSB0 -b 9600 -c "hw status"
    26.5s

`DbpStringEx` using `reply_mix`:

    time client/proxmark3 -p /dev/ttyUSB0 -b 9600 -c "hw status"
    7.08s

`DbpStringEx` using `reply_ng`:

    time client/proxmark3 -p /dev/ttyACM0 -c "hw status"
    2.10s
    time client/proxmark3 -p /dev/ttyUSB0 -b 460800 -c "hw status"
    2.22s
    time client/proxmark3 -p /dev/ttyUSB0 -b 115200 -c "hw status"
    2.43s
    time client/proxmark3 -p /dev/ttyUSB0 -b 9600 -c "hw status"
    5.75s

    time client/proxmark3 -p /dev/ttyUSB0 -b 9600 -c "lf read"
    50.38s
    time client/proxmark3 -p /dev/ttyUSB0 -b 115200 -c "lf read"
    6.28s

    time client/proxmark3 -p /dev/ttyACM0 -c "mem dump -f foo_usb"
    1.48s
    time client/proxmark3 -p /dev/ttyUSB0 -b 115200 -c "mem dump -f foo_fpc"
    25.34s


Sending multiple commands can still be slow because it waits regularly for incoming RX frames and the timings are quite conservative because of BT (see struct timeval timeout in uart_posix.c, now at 200ms). When one knows there is no response to wait before the next command, he can use the same trick as in the flasher:

    // fast push mode
    conn.block_after_ACK = true;
    some loop {
        if (sending_last_command)
            // Disable fast mode
            conn.block_after_ACK = false;
        SendCommandOLD / SendCommandMix
        if (!WaitForResponseTimeout(CMD_ACK, &resp, some_timeout)) {
            ....
            conn.block_after_ACK = false;
            return PM3_ETIMEOUT;
        }
    }
    return PM3_SUCCESS;

Or if it's too complex to determine when we're sending the last command:

    // fast push mode
    conn.block_after_ACK = true;
    some loop {
        SendCommandOLD / SendCommandMIX
        if (!WaitForResponseTimeout(CMD_ACK, &resp, some_timeout)) {
            ....
            conn.block_after_ACK = false;
            return PM3_ETIMEOUT;
        }
    }
    // Disable fast mode and send a dummy command to make it effective
    conn.block_after_ACK = false;
    SendCommandNG(CMD_PING, NULL, 0);
    WaitForResponseTimeout(CMD_ACK, NULL, 1000);
    return PM3_SUCCESS;


## Reference frames
^[Top](#top)

For helping debug...

* OLD command and reply packets are 544 bytes.
* NG & MIX command packets are between 10 and 522 bytes.
* NG & MIX reply packets are between 12 and 524 bytes.

On linux USB
* sent packets can be 544
* received packets are max 128, so 544 = 128+128+128+128+32

On linux UART (FTDI)
* sent packets are max 256, so 544 = 256+256+32
* received packets are max 512, so 544 = 512+32

`hw ping` (old version, mix reply)

    TestProxmark: SendCommandOLD(CMD_PING, 0, 0, 0, NULL, 0);
    ->544=0901000000000000000000000000000000000000000000000000000000000000  -> OLD
    CMD_PING: reply_mix(CMD_ACK, reply_via_fpc, 0, 0, 0, 0);
    <-36=504d336218000000ff0000000000000000000000000000000000000000000000   <- MIX

`hw ping` (intermediate version using MIX)

    CmdPing  SendCommandMIX(CMD_PING, 0, 0, 0, NULL, 0);
    ->34=504d336118000901000000000000000000000000000000000000000000000000   -> MIX
    CMD_PING reply_mix(CMD_ACK, reply_via_fpc, 0, 0, 0, 0);
    <-36=504d336218000000ff0000000000000000000000000000000000000000000000   <- MIX

`hw ping` (current NG version)

    CmdPing  SendCommandNG(CMD_PING, data, len);
    ->10=504d3361008009016133                                               -> NG
    CMD_PING reply_ng(CMD_PING, PM3_SUCCESS, packet->data.asBytes, packet->length);
    <-12=504d33620080000009016233                                           <- NG

`hw ping -l 512` (NG)

    CmdPing  SendCommandNG(CMD_PING, data, len);
    ->522=504d336100820901000102030405060708090a0b0c0d0e0f1011121314151617  -> NG
    CMD_PING reply_ng(CMD_PING, PM3_SUCCESS, packet->data.asBytes, packet->length);
    <-128=504d3362008200000901000102030405060708090a0b0c0d0e0f101112131415  <- NG
    <-128=767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495
    <-128=f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415
    <-128=767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495
    <-12=f6f7f8f9fafbfcfdfeff6233

