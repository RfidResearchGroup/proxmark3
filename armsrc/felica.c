#include "proxmark3.h"
#include "apps.h"
#include "BigBuf.h"
#include "util.h"
#include "usb_cdc.h" // for usb_poll_validate_length
#include "protocols.h"
#include "crc16.h"   // crc16 ccitt

// FeliCa timings
// minimum time between the start bits of consecutive transfers from reader to tag: 6800 carrier (13.56Mhz) cycles
#ifndef FELICA_REQUEST_GUARD_TIME
# define FELICA_REQUEST_GUARD_TIME (6800/16 + 1)
#endif
// FRAME DELAY TIME 2672 carrier cycles
#ifndef FELICA_FRAME_DELAY_TIME
# define FELICA_FRAME_DELAY_TIME  (2672/16 + 1)
#endif
#ifndef DELAY_AIR2ARM_AS_READER
#define DELAY_AIR2ARM_AS_READER (3 + 16 + 8 + 8*16 + 4*16 - 8*16)
#endif
#ifndef DELAY_ARM2AIR_AS_READER
#define DELAY_ARM2AIR_AS_READER (4*16 + 8*16 + 8 + 8 + 1)
#endif

// CRC skips two first sync bits in data buffer
#define AddCrc(data, len) compute_crc(CRC_FELICA, (data)+2, (len),(data)+(len)+2, (data)+(len)+3)

static uint32_t felica_timeout;
static uint32_t felica_nexttransfertime;
static uint32_t felica_lasttime_prox2air_start;

static void iso18092_setup(uint8_t fpga_minor_mode);
static uint8_t felica_select_card(felica_card_select_t *card);
static void TransmitFor18092_AsReader(uint8_t *frame, int len, uint32_t *timing, uint8_t power, uint8_t highspeed);
bool WaitForFelicaReply(uint16_t maxbytes);

void iso18092_set_timeout(uint32_t timeout) {
    felica_timeout = timeout + (DELAY_AIR2ARM_AS_READER + DELAY_ARM2AIR_AS_READER) / (16 * 8) + 2;
}

uint32_t iso18092_get_timeout(void) {
    return felica_timeout - (DELAY_AIR2ARM_AS_READER + DELAY_ARM2AIR_AS_READER) / (16 * 8) - 2;
}

#ifndef FELICA_MAX_FRAME_SIZE
#define FELICA_MAX_FRAME_SIZE 260
#endif

//structure to hold outgoing NFC frame
static uint8_t frameSpace[FELICA_MAX_FRAME_SIZE + 4];

//structure to hold incoming NFC frame, used for ISO/IEC 18092-compatible frames
static struct {
    enum {
        STATE_UNSYNCD,
        STATE_TRYING_SYNC,
        STATE_GET_LENGTH,
        STATE_GET_DATA,
        STATE_GET_CRC,
        STATE_FULL
    } state;

    uint16_t  shiftReg; //for synchronization and offset calculation
    int       posCnt;
    bool      crc_ok;
    int       rem_len;
    uint16_t  len;
    uint8_t   byte_offset;
    uint8_t   *framebytes;
//should be enough. maxlen is 255, 254 for data, 2 for sync, 2 for crc
// 0,1 -> SYNC, 2 - len,  3-(len+1)->data, then crc
} FelicaFrame;

//b2 4d is SYNC, 45645 in 16-bit notation, 10110010 01001101 binary. Frame will not start filling until this is shifted in
//bit order in byte -reverse, I guess?  [((bt>>0)&1),((bt>>1)&1),((bt>>2)&1),((bt>>3)&1),((bt>>4)&1),((bt>>5)&1),((bt>>6)&1),((bt>>7)&1)] -at least in the mode that I read those in
#ifndef SYNC_16BIT
# define SYNC_16BIT 0xB24D
#endif

static void FelicaFrameReset() {
    FelicaFrame.state = STATE_UNSYNCD;
    FelicaFrame.posCnt = 0;
    FelicaFrame.crc_ok = false;
    FelicaFrame.byte_offset = 0;
}
static void FelicaFrameinit(uint8_t *data) {
    FelicaFrame.framebytes = data;
    FelicaFrameReset();
}

//shift byte into frame, reversing it at the same time
static void shiftInByte(uint8_t bt) {
    uint8_t j;
    for (j = 0; j < FelicaFrame.byte_offset; j++) {
        FelicaFrame.framebytes[FelicaFrame.posCnt] = (FelicaFrame.framebytes[FelicaFrame.posCnt] << 1) + (bt & 1);
        bt >>= 1;
    }
    FelicaFrame.posCnt++;
    FelicaFrame.rem_len--;
    for (j = FelicaFrame.byte_offset; j < 8; j++) {
        FelicaFrame.framebytes[FelicaFrame.posCnt] = (FelicaFrame.framebytes[FelicaFrame.posCnt] << 1) + (bt & 1);
        bt >>= 1;
    }
}

static void Process18092Byte(uint8_t bt) {
    switch (FelicaFrame.state) {
        case STATE_UNSYNCD: {
            //almost any nonzero byte can be start of SYNC. SYNC should be preceded by zeros, but that is not alsways the case
            if (bt > 0) {
                FelicaFrame.shiftReg = reflect8(bt);
                FelicaFrame.state = STATE_TRYING_SYNC;
            }
            break;
        }
        case STATE_TRYING_SYNC: {
            if (bt == 0) {
                //desync
                FelicaFrame.shiftReg = bt;
                FelicaFrame.state = STATE_UNSYNCD;
            } else {
                for (uint8_t i = 0; i < 8; i++) {

                    if (FelicaFrame.shiftReg == SYNC_16BIT) {
                        //SYNC done!
                        FelicaFrame.state = STATE_GET_LENGTH;
                        FelicaFrame.framebytes[0] = 0xb2;
                        FelicaFrame.framebytes[1] = 0x4d;
                        FelicaFrame.byte_offset = i;
                        //shift in remaining byte, slowly...
                        for (uint8_t j = i; j < 8; j++) {
                            FelicaFrame.framebytes[2] = (FelicaFrame.framebytes[2] << 1) + (bt & 1);
                            bt >>= 1;
                        }

                        FelicaFrame.posCnt = 2;
                        if (i == 0)
                            break;
                    }
                    FelicaFrame.shiftReg = (FelicaFrame.shiftReg << 1) + (bt & 1);
                    bt >>= 1;
                }

                //that byte was last byte of sync
                if (FelicaFrame.shiftReg == SYNC_16BIT) {
                    //Force SYNC on next byte
                    FelicaFrame.state = STATE_GET_LENGTH;
                    FelicaFrame.framebytes[0] = 0xb2;
                    FelicaFrame.framebytes[1] = 0x4d;
                    FelicaFrame.byte_offset = 0;
                    FelicaFrame.posCnt = 1;
                }
            }
            break;
        }
        case STATE_GET_LENGTH: {
            shiftInByte(bt);
            FelicaFrame.rem_len = FelicaFrame.framebytes[2] - 1;
            FelicaFrame.len = FelicaFrame.framebytes[2] + 4; //with crc and sync
            FelicaFrame.state = STATE_GET_DATA;
            break;
        }
        case STATE_GET_DATA: {
            shiftInByte(bt);
            if (FelicaFrame.rem_len <= 0) {
                FelicaFrame.state = STATE_GET_CRC;
                FelicaFrame.rem_len = 2;
            }
            break;
        }
        case STATE_GET_CRC: {
            shiftInByte(bt);

            if (FelicaFrame.rem_len <= 0) {
                // skip sync 2bytes. IF ok, residue should be 0x0000
                FelicaFrame.crc_ok = check_crc(CRC_FELICA, FelicaFrame.framebytes + 2, FelicaFrame.len - 2);
                FelicaFrame.state = STATE_FULL;
                FelicaFrame.rem_len = 0;
                if (DBGLEVEL > 3) Dbprintf("[+] got 2 crc bytes [%s]", (FelicaFrame.crc_ok) ? "OK" : "No");
            }
            break;
        }
        case STATE_FULL:  //ignore byte. Don't forget to clear frame to receive next one...
        default:
            break;
    }
}

/* Perform FeliCa polling card
 * Currently does NOT do any collision handling.
 * It expects 0-1 cards in the device's range.
 */
static uint8_t felica_select_card(felica_card_select_t *card) {

    // POLL command
    // 0xB2 0x4B = sync code
    // 0x06 = len
    // 0x00 = rfu
    // 0xff = system service
    // 0xff = system service
    // 0x00  =
    // b7    = automatic switching of data rate
    // b6-b2 = reserved
    // b1    = fc/32 (414kbps)
    // b0    = fc/64 (212kbps)
    // 0x00 = timeslot
    // 0x09 0x21 = crc
    static uint8_t poll[10] = {0xb2, 0x4d, 0x06, FELICA_POLL_REQ, 0xFF, 0xFF, 0x00, 0x00, 0x09, 0x21};

    int len = 20;

    // We try 20 times, or if answer was received.
    do {
        // end-of-reception response packet data, wait approx. 501μs
        // end-of-transmission command packet data, wait approx. 197μs
        // polling card
        TransmitFor18092_AsReader(poll, sizeof(poll), NULL, 1, 0);

        // polling card, break if success
        if (WaitForFelicaReply(512) && FelicaFrame.framebytes[3] == FELICA_POLL_ACK)
            break;

        WDT_HIT();

    } while (--len);

    // timed-out
    if (len == 0)
        return 1;

    // wrong answer
    if (FelicaFrame.framebytes[3] != FELICA_POLL_ACK)
        return 2;

    // VALIDATE CRC   residue is 0, hence if crc is a value it failed.
    if (!check_crc(CRC_FELICA, FelicaFrame.framebytes + 2, FelicaFrame.len - 2))
        return 3;

    // copy UID
    // idm 8
    if (card) {
        memcpy(card->IDm, FelicaFrame.framebytes + 4, 8);
        memcpy(card->PMm, FelicaFrame.framebytes + 4 + 8, 8);
        //memcpy(card->servicecode, FelicaFrame.framebytes + 4 + 8 + 8, 2);
        memcpy(card->code, card->IDm, 2);
        memcpy(card->uid, card->IDm + 2, 6);
        memcpy(card->iccode, card->PMm, 2);
        memcpy(card->mrt, card->PMm + 2, 6);

    }
    // more status bytes?
    return 0;
}

// poll-0: 0xb2,0x4d,0x06,0x00,0xff,0xff,0x00,0x00,0x09,0x21,
// resp:  0xb2,0x4d,0x12,0x01,0x01,0x2e,0x3d,0x17,0x26,0x47,0x80,0x95,0x00,0xf1,0x00,0x00,0x00,0x01,0x43,0x00,0xb3,0x7f,
// poll-1 (reply with available system codes - NFC Tag3 specs, IIRC): 0xb2,0x4d,0x06,0x00,0xff,0xff,0x01,0x00,0x3a,0x10
// resp: 0xb2,0x4d,0x14,0x01,  0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,  0x00,0xf1,0x00,0x00,0x00,0x01,0x43,0x00,  0x88,0xb4,0x0c,0xe2,
// page-req:  0xb2,0x4d,0x10,0x06,  0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,  0x01,  0x0b,0x00,  0x01,  0x80,0x00,  0x2e,0xb3,
// page-req: 0x06, IDm(8), ServiceNum(1),Slist(2*num) BLocknum (1) BLockids(2-3*num)
// page-resp: 0xb2,0x4d,0x1d,0x07,  0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,  0x00,  0x00,  0x01,  0x10,0x04,0x01,0x00,0x0d,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x23,   0xcb,0x6e,

// builds a readblock frame for felica lite(s).  Using SERVICE:  SERVICE_FELICA_LITE_READONLY
// Felica standard has a different file system, AFAIK,
// 8-byte IDm, number of blocks, blocks numbers
// number of blocks limited to 4 for FelicaLite(S)
static void BuildFliteRdblk(uint8_t *idm, int blocknum, uint16_t *blocks) {

    if (blocknum > 4 || blocknum <= 0)
        Dbprintf("Invalid number of blocks, %d != 4", blocknum);

    uint8_t c = 0, i = 0;

    frameSpace[c++] = 0xb2;
    frameSpace[c++] = 0x4d;

    c++; //set length later

    frameSpace[c++] = FELICA_RDBLK_REQ; //command number

    //card IDm, from poll
    frameSpace[c++] = idm[0];
    frameSpace[c++] = idm[1];
    frameSpace[c++] = idm[2];
    frameSpace[c++] = idm[3];
    frameSpace[c++] = idm[4];
    frameSpace[c++] = idm[5];
    frameSpace[c++] = idm[6];
    frameSpace[c++] = idm[7];

    //number of services
    frameSpace[c++] = 0x01;

    //service code
    frameSpace[c++] = (SERVICE_FELICA_LITE_READONLY >> 8);
    frameSpace[c++] = SERVICE_FELICA_LITE_READONLY & 0xFF;

    //number of blocks
    frameSpace[c++] = blocknum;

    for (i = 0; i < blocknum; i++) {

        //3-byte block
        if (blocks[i] >= 256) {
            frameSpace[c++] = 0x00;
            frameSpace[c++] = (blocks[i] >> 8); //block number, little endian....
            frameSpace[c++] = (blocks[i] & 0xff);
        } else {
            frameSpace[c++] = 0x80;
            frameSpace[c++] = blocks[i];
        }
    }

    //set length
    frameSpace[2] = c - 2;
    AddCrc(frameSpace, c - 2);
}

static void TransmitFor18092_AsReader(uint8_t *frame, int len, uint32_t *timing, uint8_t power, uint8_t highspeed) {

    uint8_t flags = FPGA_MAJOR_MODE_ISO18092;

    if (power)
        flags |= FPGA_HF_ISO18092_FLAG_READER;
    if (highspeed)
        flags |= FPGA_HF_ISO18092_FLAG_424K;

    FpgaWriteConfWord(flags);

    uint32_t curr_transfer_time = ((MAX(felica_nexttransfertime, GetCountSspClk()) & 0xfffffff8) + 8);

    while (GetCountSspClk() < curr_transfer_time) {};

    felica_lasttime_prox2air_start = curr_transfer_time;

    // preamble
    // sending 0x00 0x00 0x00 0x00 0x00 0x00
    uint16_t c = 0;
    while (c < 6) {

        // keep tx buffer in a defined state anyway.
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = 0x00;
            c++;
        }
    }
    // sending sync code

    // sending data
    c = 0;
    while (c < len) {

        // Put byte into tx holding register as soon as it is ready
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = frame[c++];
        }
    }

    /**/
    while (!(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))) {};
    AT91C_BASE_SSC->SSC_THR = 0x00; //minimum delay

    while (!(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))) {};
    AT91C_BASE_SSC->SSC_THR = 0x00; //spin
    /**/

    // log
    LogTrace(
        frame,
        len,
        (felica_lasttime_prox2air_start << 4) + DELAY_ARM2AIR_AS_READER,
        ((felica_lasttime_prox2air_start + felica_lasttime_prox2air_start) << 4) + DELAY_ARM2AIR_AS_READER,
        NULL,
        true
    );

    felica_nexttransfertime = MAX(felica_nexttransfertime, felica_lasttime_prox2air_start + FELICA_REQUEST_GUARD_TIME);
}

// Wait for tag reply
// stop when button is pressed
// or return TRUE when command is captured
bool WaitForFelicaReply(uint16_t maxbytes) {

    uint32_t c = 0;

    // power, no modulation
    FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 | FPGA_HF_ISO18092_FLAG_READER | FPGA_HF_ISO18092_FLAG_NOMOD);

    FelicaFrameReset();

    // clear RXRDY:
    uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
    (void)b;

    uint32_t timeout = iso18092_get_timeout();
    for (;;) {
        WDT_HIT();

        if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
            b = (uint8_t)(AT91C_BASE_SSC->SSC_RHR);
            Process18092Byte(b);
            if (FelicaFrame.state == STATE_FULL) {
                felica_nexttransfertime =
                    MAX(
                        felica_nexttransfertime,
                        (GetCountSspClk() & 0xfffffff8) - (DELAY_AIR2ARM_AS_READER + DELAY_ARM2AIR_AS_READER) / 16 + FELICA_FRAME_DELAY_TIME
                    )
                    ;

                LogTrace(
                    FelicaFrame.framebytes,
                    FelicaFrame.len,
                    ((GetCountSspClk() & 0xfffffff8) << 4) - DELAY_AIR2ARM_AS_READER - timeout,
                    ((GetCountSspClk() & 0xfffffff8) << 4) - DELAY_AIR2ARM_AS_READER,
                    NULL,
                    false
                );
                return true;
            } else if (c++ > timeout && FelicaFrame.state == STATE_UNSYNCD) {
                return false;
            } else if (FelicaFrame.state == STATE_GET_CRC) {
                Dbprintf(" Frame: ");
                Dbhexdump(16, FelicaFrame.framebytes, 0);
                //return false;
            }
        }
    }
    return false;
}

// Set up FeliCa communication (similar to iso14443a_setup)
// field is setup for "Sending as Reader"
static void iso18092_setup(uint8_t fpga_minor_mode) {

    LEDsoff();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // allocate command receive buffer
    BigBuf_free();
    BigBuf_Clear_ext(false);

    // Initialize Demod and Uart structs
    //DemodInit(BigBuf_malloc(MAX_FRAME_SIZE));
    FelicaFrameinit(BigBuf_malloc(FELICA_MAX_FRAME_SIZE));

    felica_nexttransfertime = 2 * DELAY_ARM2AIR_AS_READER;
    iso18092_set_timeout(2120); // 106 * 20ms  maximum start-up time of card

    init_table(CRC_FELICA);

    // connect Demodulated Signal to ADC:
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

    // Set up the synchronous serial port
    FpgaSetupSsc();

    // LSB transfer.  Remember to set it back to MSB with
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);

    // Signal field is on with the appropriate LED
    FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 | fpga_minor_mode);

    //20.4 ms generate field,  start sending polling command afterwars.
    SpinDelay(100);

    // Start the timer
    StartCountSspClk();

    LED_D_ON();
}
//-----------------------------------------------------------------------------
// RAW FeliCa commands. Send out commands and store answers.
//-----------------------------------------------------------------------------
// arg0 FeliCa flags
// arg1 len of commandbytes
// d.asBytes command bytes to send
void felica_sendraw(PacketCommandNG *c) {

    if (DBGLEVEL > 3) Dbprintf("FeliCa_sendraw Enter");

    felica_command_t param = c->oldarg[0];
    size_t len = c->oldarg[1] & 0xffff;
    uint8_t *cmd = c->data.asBytes;
    uint32_t arg0;

    felica_card_select_t card;

    if ((param & FELICA_CONNECT))
        clear_trace();

    set_tracing(true);

    if ((param & FELICA_CONNECT)) {
        iso18092_setup(FPGA_HF_ISO18092_FLAG_READER | FPGA_HF_ISO18092_FLAG_NOMOD);

        // notify client selecting status.
        // if failed selecting, turn off antenna and quite.
        if (!(param & FELICA_NO_SELECT)) {
            arg0 = felica_select_card(&card);
            reply_old(CMD_ACK, arg0, sizeof(card.uid), 0, &card, sizeof(felica_card_select_t));
            if (arg0 > 0)
                goto OUT;
        }
    }

    if ((param & FELICA_RAW)) {

        // 2 sync, 1 len, 2crc == 5
        uint8_t *buf = BigBuf_malloc(len + 5);
        // add sync bits
        buf[0] = 0xb2;
        buf[1] = 0x4d;
        buf[2] = len;

        // copy command
        memcpy(buf + 2, cmd, len);

        if ((param & FELICA_APPEND_CRC)) {
            // Don't append crc on empty bytearray...
            if (len > 0) {
                AddCrc(buf, len);
            }
        }

        TransmitFor18092_AsReader(buf, buf[2] + 4, NULL, 1, 0);
        arg0 = !WaitForFelicaReply(1024);
        reply_old(CMD_ACK, arg0, 0, 0, FelicaFrame.framebytes + 2, FelicaFrame.len - 2);
    }

    if ((param & FELICA_NO_DISCONNECT))
        return;

OUT:
    switch_off();

    //Resetting Frame mode (First set in fpgaloader.c)
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) | AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);

    if (DBGLEVEL > 3) Dbprintf("FeliCa_sendraw Exit");
}

void felica_sniff(uint32_t samplesToSkip, uint32_t triggersToSkip) {

    int remFrames = (samplesToSkip) ? samplesToSkip : 0;

    Dbprintf("Sniff FelicaLiteS: Getting first %d frames, Skipping %d triggers.\n", samplesToSkip, triggersToSkip);

    iso18092_setup(FPGA_HF_ISO18092_FLAG_NOMOD);

    //the frame bits are slow enough.
    int n = BigBuf_max_traceLen() / sizeof(uint8_t); // take all memory
    int numbts = 0;
    uint8_t *dest = (uint8_t *)BigBuf_get_addr();
    uint8_t *destend = dest + n - 2;

    uint32_t endframe = GetCountSspClk();

    while (dest <= destend) {
        WDT_HIT();
        if (BUTTON_PRESS()) break;

        if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
            uint8_t dist = (uint8_t)(AT91C_BASE_SSC->SSC_RHR);
            Process18092Byte(dist);

            //to be sure we are in frame
            if (FelicaFrame.state == STATE_GET_LENGTH) {
                //length is after 48 (PRE)+16 (SYNC) - 64 ticks +maybe offset? not 100%
                uint16_t distance = GetCountSspClk() - endframe - 64 + (FelicaFrame.byte_offset > 0 ? (8 - FelicaFrame.byte_offset) : 0);
                *dest = distance >> 8;
                dest++;
                *dest = (distance & 0xff);
                dest++;
            }
            //crc NOT checked
            if (FelicaFrame.state == STATE_FULL) {
                endframe = GetCountSspClk();
                //*dest = FelicaFrame.crc_ok; //kind of wasteful
                dest++;
                for (int i = 0; i < FelicaFrame.len; i++) {
                    *dest = FelicaFrame.framebytes[i];
                    dest++;
                    if (dest >= destend) break;

                }

                remFrames--;
                if (remFrames <= 0) break;
                if (dest >= destend) break;

                numbts += FelicaFrame.len;

                FelicaFrameReset();
            }
        }
    }

    switch_off();

    //reset framing
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) | AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    set_tracelen(numbts);

    Dbprintf("Felica sniffing done, tracelen: %i, use hf list felica for annotations", BigBuf_get_traceLen());
    reply_old(CMD_ACK, 1, numbts, 0, 0, 0);
}

#define R_POLL0_LEN    0x16
#define R_POLL1_LEN    0x18
#define R_READBLK_LEN  0x21
//simulate NFC Tag3 card - for now only poll response works
// second half (4 bytes)  of NDEF2 goes into nfcid2_0, first into nfcid2_1
void felica_sim_lite(uint64_t uid) {

    int i, curlen = 0;
    uint8_t *curresp = 0;

    uint8_t ndef[8];
    num_to_bytes(uid, 8, ndef);

    //prepare our 3 responses...
    uint8_t resp_poll0[R_POLL0_LEN] = { 0xb2, 0x4d, 0x12, FELICA_POLL_ACK, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0xb3, 0x7f};
    uint8_t resp_poll1[R_POLL1_LEN] = { 0xb2, 0x4d, 0x14, FELICA_POLL_ACK, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0x88, 0xb4, 0xb3, 0x7f};
    uint8_t resp_readblk[R_READBLK_LEN] = { 0xb2, 0x4d, 0x1d, FELICA_RDBLK_ACK, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x04, 0x01, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x23, 0xcb, 0x6e};

    //NFC tag 3/ ISo technically. Many overlapping standards
    DbpString("Felica Lite-S sim start");
    Dbprintf("NDEF2 UID: %02x %02x %02x %02x %02x %02x %02x %02x",
             ndef[0], ndef[1], ndef[2], ndef[3], ndef[4], ndef[5], ndef[6], ndef[7]
            );

    //fill in blanks
    for (i = 0; i < 8; i++) {
        resp_poll0[i + 4] = ndef[i];
        resp_poll1[i + 4] = ndef[i];
        resp_readblk[i + 4] = ndef[i];
    }

    //calculate and set CRC
    AddCrc(resp_poll0, resp_poll0[2]);
    AddCrc(resp_poll1, resp_poll1[2]);
    AddCrc(resp_readblk, resp_readblk[2]);

    iso18092_setup(FPGA_HF_ISO18092_FLAG_NOMOD);

    bool listenmode = true;
    //uint32_t frtm = GetCountSspClk();
    for (;;) {
        if (BUTTON_PRESS()) break;
        WDT_HIT();

        if (listenmode) {
            //waiting for request...
            if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {

                uint8_t dist = (uint8_t)(AT91C_BASE_SSC->SSC_RHR);
                //frtm = GetCountSspClk();
                Process18092Byte(dist);

                if (FelicaFrame.state == STATE_FULL) {

                    if (FelicaFrame.crc_ok) {

                        if (FelicaFrame.framebytes[2] == 6 && FelicaFrame.framebytes[3] == 0) {

                            //polling... there are two types of polling we answer to
                            if (FelicaFrame.framebytes[6] == 0) {
                                curresp = resp_poll0;
                                curlen = R_POLL0_LEN;
                                listenmode = false;
                            }
                            if (FelicaFrame.framebytes[6] == 1) {
                                curresp = resp_poll1;
                                curlen = R_POLL1_LEN;
                                listenmode = true;
                            }
                        }

                        if (FelicaFrame.framebytes[2] > 5 && FelicaFrame.framebytes[3] == 0x06) {
                            //we should rebuild it depending on page size, but...
                            //Let's see first
                            curresp = resp_readblk;
                            curlen = R_READBLK_LEN;
                            listenmode = false;
                        }
                        //clear frame
                        FelicaFrameReset();
                    } else {
                        //frame invalid, clear it out to allow for the next one
                        FelicaFrameReset();
                    }
                }
            }
        }
        if (!listenmode) {
            //trying to answer... here to  start answering immediately.
            //this one is a bit finicky. Seems that being a bit late is better than earlier
            //TransmitFor18092_AsReader(curresp, curlen, frtm+512, 0, 0);
            TransmitFor18092_AsReader(curresp, curlen, NULL, 0, 0);

            //switch back
            FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 | FPGA_HF_ISO18092_FLAG_NOMOD);

            FelicaFrameReset();
            listenmode = true;
            curlen = 0;
            curresp = NULL;
        }
    }

    switch_off();

    //reset framing
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) | AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);

    DbpString("Felica Lite-S sim end");
}

void felica_dump_lite_s() {

    uint8_t ndef[8];
    uint8_t poll[10] = { 0xb2, 0x4d, 0x06, FELICA_POLL_REQ, 0xff, 0xff, 0x00, 0x00, 0x09, 0x21};
    uint16_t liteblks[28] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x90, 0x91, 0x92, 0xa0};

    // setup device.
    iso18092_setup(FPGA_HF_ISO18092_FLAG_READER | FPGA_HF_ISO18092_FLAG_NOMOD);

    uint8_t blknum;
    bool isOK = false;
    uint16_t cnt = 0, cntfails = 0;
    uint8_t *dest = BigBuf_get_addr();

    while (!BUTTON_PRESS() && !data_available()) {

        WDT_HIT();

        // polling?
        //TransmitFor18092_AsReader(poll, 10, GetCountSspClk()+512, 1, 0);
        TransmitFor18092_AsReader(poll, 10, NULL, 1, 0);

        if (WaitForFelicaReply(512) && FelicaFrame.framebytes[3] == FELICA_POLL_ACK) {

            // copy 8bytes to ndef.
            memcpy(ndef, FelicaFrame.framebytes + 4, 8);
            // for (c=0; c < 8; c++)
            // ndef[c] = FelicaFrame.framebytes[c+4];

            for (blknum = 0; blknum < sizeof(liteblks);) {

                // block to read.
                BuildFliteRdblk(ndef, 1, &liteblks[blknum]);

                //TransmitFor18092_AsReader(frameSpace, frameSpace[2]+4, GetCountSspClk()+512, 1, 0);
                TransmitFor18092_AsReader(frameSpace, frameSpace[2] + 4, NULL, 1, 0);

                // read block
                if (WaitForFelicaReply(1024) && FelicaFrame.framebytes[3] == FELICA_RDBLK_ACK) {

                    dest[cnt++] = liteblks[blknum];

                    uint8_t *fb = FelicaFrame.framebytes;
                    dest[cnt++] = fb[12];
                    dest[cnt++] = fb[13];

                    //memcpy(dest+cnt, FelicaFrame.framebytes + 15, 16);
                    //cnt += 16;
                    for (uint8_t j = 0; j < 16; j++)
                        dest[cnt++] = fb[15 + j];

                    blknum++;
                    cntfails = 0;

                    // // print raw log.
                    // Dbprintf("LEN %u | Dump bytes count %u ", FelicaFrame.len, cnt);
                    Dbhexdump(FelicaFrame.len, FelicaFrame.framebytes + 15, 0);
                } else {
                    cntfails++;
                    if (cntfails > 12) {
                        blknum++;
                        cntfails = 0;
                    }
                }
            }
            isOK = true;
            break;
        }
    }

    switch_off();

    //Resetting Frame mode (First set in fpgaloader.c)
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) | AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);

    //setting tracelen - important!  it was set by buffer overflow before
    set_tracelen(cnt);
    reply_old(CMD_ACK, isOK, cnt, 0, 0, 0);
}
