//-----------------------------------------------------------------------------
// Jonathan Westhues, split Nov 2006
// Modified by Greg Jones, Jan 2009
// Modified by Adrian Dabrowski "atrox", Mar-Sept 2010,Oct 2011
// Modified by Christian Herrmann "iceman", 2017
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 15693. This includes both the reader software and
// the `fake tag' modes, but at the moment I've implemented only the reader
// stuff, and that barely.
// Modified to perform modulation onboard in arm rather than on PC
// Also added additional reader commands (SELECT, READ etc.)
//-----------------------------------------------------------------------------
// The ISO 15693 describes two transmission modes from reader to tag, and 4
// transmission modes from tag to reader. As of Mar 2010 this code only
// supports one of each: "1of4" mode from reader to tag, and the highspeed
// variant with one subcarrier from card to reader.
// As long, as the card fully support ISO 15693 this is no problem, since the
// reader chooses both data rates, but some non-standard tags do not. Further for
// the simulation to work, we will need to support all data rates.
//
// VCD (reader) -> VICC (tag)
// 1 out of 256:
//  data rate: 1,66 kbit/s (fc/8192)
//  used for long range
// 1 out of 4:
//  data rate: 26,48 kbit/s (fc/512)
//  used for short range, high speed
//
// VICC (tag) -> VCD (reader)
// Modulation:
//    ASK / one subcarrier (423,75 khz)
//    FSK / two subcarriers (423,75 khz && 484,28 khz)
// Data Rates / Modes:
//  low ASK: 6,62 kbit/s
//  low FSK: 6.67 kbit/s
//  high ASK: 26,48 kbit/s
//  high FSK: 26,69 kbit/s
//-----------------------------------------------------------------------------
// added "1 out of 256" mode (for VCD->PICC) - atrox 20100911


// Random Remarks:
// *) UID is always used "transmission order" (LSB), which is reverse to display order

// TODO / BUGS / ISSUES:
// *) writing to tags takes longer: we miss the answer from the tag in most cases
//    -> tweak the read-timeout times
// *) signal decoding from the card is still a bit shaky.
// *) signal decoding is unable to detect collissions.
// *) add anti-collission support for inventory-commands
// *) read security status of a block
// *) sniffing and simulation do only support one transmission mode. need to support
//    all 8 transmission combinations
// *) remove or refactor code under "depricated"
// *) document all the functions

#include "proxmark3.h"
#include "util.h"
#include "apps.h"
#include "string.h"
#include "iso15693tools.h"
#include "cmd.h"

///////////////////////////////////////////////////////////////////////
// ISO 15693 Part 2 - Air Interface
// This section basicly contains transmission and receiving of bits
///////////////////////////////////////////////////////////////////////

// 32 + 2 crc + 1
#define ISO15_MAX_FRAME 35
#define CMD_ID_RESP     5
#define CMD_READ_RESP   13
#define CMD_INV_RESP    12

#define FrameSOF              Iso15693FrameSOF
#define Logic0                Iso15693Logic0
#define Logic1                Iso15693Logic1
#define FrameEOF              Iso15693FrameEOF

//#define Crc(data, len)        Crc(CRC_15693, (data), (len))
#define CheckCrc15(data, len)   check_crc(CRC_15693, (data), (len))
#define AddCrc15(data, len)     compute_crc(CRC_15693, (data), (len), (data)+(len), (data)+(len)+1)

#define sprintUID(target,uid) Iso15693sprintUID((target), (uid))

static void BuildIdentifyRequest(uint8_t *cmdout);
//static void BuildReadBlockRequest(uint8_t *cmdout, uint8_t *uid, uint8_t blockNumber );
static void BuildInventoryResponse(uint8_t *cmdout, uint8_t *uid);

// ---------------------------
// Signal Processing
// ---------------------------

// prepare data using "1 out of 4" code for later transmission
// resulting data rate is 26,48 kbit/s (fc/512)
// cmd ... data
// n ... length of data
static void CodeIso15693AsReader(uint8_t *cmd, int n) {
    int i, j;

    ToSendReset();

    // Give it a bit of slack at the beginning
    for (i = 0; i < 24; i++)
        ToSendStuffBit(1);

    // SOF for 1of4
    ToSendStuffBit(0);
    ToSendStuffBit(1);
    ToSendStuffBit(1);
    ToSendStuffBit(1);
    ToSendStuffBit(1);
    ToSendStuffBit(0);
    ToSendStuffBit(1);
    ToSendStuffBit(1);
    for (i = 0; i < n; i++) {
        for (j = 0; j < 8; j += 2) {
            int these = (cmd[i] >> j) & 3;
            switch (these) {
                case 0:
                    ToSendStuffBit(1);
                    ToSendStuffBit(0);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    break;
                case 1:
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(0);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    break;
                case 2:
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(0);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    break;
                case 3:
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(1);
                    ToSendStuffBit(0);
                    break;
            }
        }
    }
    // EOF
    ToSendStuffBit(1);
    ToSendStuffBit(1);
    ToSendStuffBit(0);
    ToSendStuffBit(1);

    // And slack at the end, too.
    for (i = 0; i < 24; i++)
        ToSendStuffBit(1);
}

// encode data using "1 out of 256" sheme
// data rate is 1,66 kbit/s (fc/8192)
// is designed for more robust communication over longer distances
static void CodeIso15693AsReader256(uint8_t *cmd, int n) {
    int i, j;

    ToSendReset();

    // Give it a bit of slack at the beginning
    for (i = 0; i < 24; i++)
        ToSendStuffBit(1);

    // SOF for 1of256
    ToSendStuffBit(0);
    ToSendStuffBit(1);
    ToSendStuffBit(1);
    ToSendStuffBit(1);
    ToSendStuffBit(1);
    ToSendStuffBit(1);
    ToSendStuffBit(1);
    ToSendStuffBit(0);

    for (i = 0; i < n; i++) {
        for (j = 0; j <= 255; j++) {
            if (cmd[i] == j) {
                ToSendStuffBit(1);
                ToSendStuffBit(0);
            } else {
                ToSendStuffBit(1);
                ToSendStuffBit(1);
            }
        }
    }
    // EOF
    ToSendStuffBit(1);
    ToSendStuffBit(1);
    ToSendStuffBit(0);
    ToSendStuffBit(1);

    // And slack at the end, too.
    for (i = 0; i < 24; i++)
        ToSendStuffBit(1);
}

// Transmit the command (to the tag) that was placed in ToSend[].
static void TransmitTo15693Tag(const uint8_t *cmd, int len, int *samples, int *wait) {

    int c;
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX);

    if (wait) {
        for (c = 0; c < *wait;) {
            if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
                AT91C_BASE_SSC->SSC_THR = 0x00; // For exact timing!
                ++c;
            }
            WDT_HIT();
        }
    }

    c = 0;
    for (;;) {
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = cmd[c];
            if (++c >= len) break;
        }
        WDT_HIT();
    }

    if (samples) {
        if (wait)
            *samples = (c + *wait) << 3;
        else
            *samples = c << 3;
    }
}

//-----------------------------------------------------------------------------
// Transmit the command (to the reader) that was placed in ToSend[].
//-----------------------------------------------------------------------------
static void TransmitTo15693Reader(const uint8_t *cmd, int len, int *samples, int *wait) {
    int c = 0;
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_MODULATE_424K);

    if (wait) {
        for (c = 0; c < *wait;) {
            if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
                AT91C_BASE_SSC->SSC_THR = 0x00; // For exact timing!
                ++c;
            }
            WDT_HIT();
        }
    }

    c = 0;
    for (;;) {
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = cmd[c];
            if (++c >= len) break;
        }
        WDT_HIT();
    }
    if (samples) {
        if (wait)
            *samples = (c + *wait) << 3;
        else
            *samples = c << 3;
    }
}

//-----------------------------------------------------------------------------
// DEMODULATE tag answer
//-----------------------------------------------------------------------------
static int DemodAnswer(uint8_t *received, uint8_t *dest, uint16_t samplecount) {

    int i, j;
    int max = 0, maxPos = 0, skip = 4;
    int k = 0; // this will be our return value

    // First, correlate for SOF
    for (i = 0; i < samplecount; i++) {
        int corr = 0;
        for (j = 0; j < ARRAYLEN(FrameSOF); j += skip) {
            corr += FrameSOF[j] * dest[i + (j / skip)];
        }
        if (corr > max) {
            max = corr;
            maxPos = i;
        }
    }
    // DbpString("SOF at %d, correlation %d", maxPos,max/(ARRAYLEN(FrameSOF)/skip));

    // greg - If correlation is less than 1 then there's little point in continuing
    if ((max / (ARRAYLEN(FrameSOF) / skip)) < 1)
        return k;

    i = maxPos + ARRAYLEN(FrameSOF) / skip;

    uint8_t outBuf[ISO15_MAX_FRAME];
    memset(outBuf, 0, sizeof(outBuf));
    uint8_t mask = 0x01;
    for (;;) {
        int corr0 = 0, corr1 = 0, corrEOF = 0;
        for (j = 0; j < ARRAYLEN(Logic0); j += skip) {
            corr0 += Logic0[j] * dest[i + (j / skip)];
        }
        for (j = 0; j < ARRAYLEN(Logic1); j += skip) {
            corr1 += Logic1[j] * dest[i + (j / skip)];
        }
        for (j = 0; j < ARRAYLEN(FrameEOF); j += skip) {
            corrEOF += FrameEOF[j] * dest[i + (j / skip)];
        }
        // Even things out by the length of the target waveform.
        corr0 *= 4;
        corr1 *= 4;
        // if (DBGLEVEL >= DBG_EXTENDED)
        // Dbprintf("Corr1 %d, Corr0 %d, CorrEOF %d", corr1, corr0, corrEOF);

        if (corrEOF > corr1 && corrEOF > corr0)
            break;

        if (corr1 > corr0) {
            i += ARRAYLEN(Logic1) / skip;
            outBuf[k] |= mask;
        } else {
            i += ARRAYLEN(Logic0) / skip;
        }

        mask <<= 1;

        if (mask == 0) {
            k++;
            mask = 0x01;
        }

        if ((i + (int)ARRAYLEN(FrameEOF)) >= samplecount - 1) {
            //Dbprintf("[!] ran off end!  %d | %d",( i + (int)ARRAYLEN(FrameEOF)), samplecount-1);
            break;
        }
    }

    if (DBGLEVEL >= DBG_EXTENDED) Dbprintf("ice: demod bytes %u", k);

    if (mask != 0x01) { // this happens, when we miss the EOF

        // TODO: for some reason this happens quite often
        if (DBGLEVEL >= DBG_ERROR && k != 0) Dbprintf("[!] error, uneven octet! (extra bits!) mask %02x", mask);
        //if (mask < 0x08) k--; // discard the last uneven octet;
        // 0x08 is an assumption - but works quite often
    }

    for (i = 0; i < k; i++)
        received[i] = outBuf[i];

    // return the number of bytes demodulated
    return k;
}

// Read from Tag
// Parameters:
//  received
//  samples
//  elapsed
// returns:
//  number of decoded bytes
// logging enabled
static int GetIso15693AnswerFromTag(uint8_t *received, int *elapsed) {

#define SIGNAL_BUFF_SIZE 15000
    // get current clock
    uint32_t time_0 = GetCountSspClk();
    uint32_t time_stop = 0;
    bool getNext = false;
    int counter = 0, ci, cq = 0;
    uint8_t *buf = BigBuf_malloc(SIGNAL_BUFF_SIZE);

    if (elapsed) *elapsed = 0;

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);

    for (;;) {
        WDT_HIT();

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = 0x00; //0x43;
            // To make use of exact timing of next command from reader!!
            if (elapsed)(*elapsed)++;
        }
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {

            ci = (int8_t)AT91C_BASE_SSC->SSC_RHR;
            ci = ABS(ci);

            // The samples are correlations against I and Q versions of the
            // tone that the tag AM-modulates, so every other sample is I,
            // every other is Q. We just want power, so abs(I) + abs(Q) is
            // close to what we want.
            // iceman 2016, amplitude sqrt(abs(i) + abs(q))
            if (getNext) {

                buf[counter++] = (uint8_t)(MAX(ci, cq) + (MIN(ci, cq) >> 1));

                if (counter >= SIGNAL_BUFF_SIZE)
                    break;
            } else {
                cq = ci;
            }
            getNext = !getNext;
        }
    }
    time_stop = GetCountSspClk() - time_0 ;
    int len = DemodAnswer(received, buf, counter);
    LogTrace(received, len, time_0 << 4, time_stop << 4, NULL, false);
    BigBuf_free();
    return len;
}


// Now the GetISO15693 message from sniffing command
// logging enable,
static int GetIso15693AnswerFromSniff(uint8_t *received, int *samples, int *elapsed) {

    bool getNext = false;
    int counter = 0, ci, cq = 0;
    uint32_t time_0 = 0, time_stop = 0;
    uint8_t *buf = BigBuf_get_addr();

    // get current clock
    time_0 = GetCountSspClk();

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);

    for (;;) {
        WDT_HIT();

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {

            ci = (int8_t)AT91C_BASE_SSC->SSC_RHR;
            ci = ABS(ci);

            // The samples are correlations against I and Q versions of the
            // tone that the tag AM-modulates, so every other sample is I,
            // every other is Q. We just want power, so abs(I) + abs(Q) is
            // close to what we want.
            if (getNext) {

                buf[counter++] = (uint8_t)(MAX(ci, cq) + (MIN(ci, cq) >> 1));

                if (counter >= 20000)
                    break;
            } else {
                cq = ci;
            }
            getNext = !getNext;
        }
    }

    time_stop = GetCountSspClk() - time_0;
    int k = DemodAnswer(received, buf, counter);
    LogTrace(received, k, time_0 << 4, time_stop << 4, NULL, false);
    return k;
}

//-----------------------------------------------------------------------------
// Start to read an ISO 15693 tag. We send an identify request, then wait
// for the response. The response is not demodulated, just left in the buffer
// so that it can be downloaded to a PC and processed there.
//-----------------------------------------------------------------------------
void AcquireRawAdcSamplesIso15693(void) {
    int c = 0, getNext = false;
    int ci, cq = 0;

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
    FpgaSetupSsc();

    // Now send the command
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX);
    SpinDelay(200);

    uint8_t *buf = BigBuf_get_addr();

    uint32_t time_start = GetCountSspClk();
    uint8_t cmd[CMD_ID_RESP] = {0};
    BuildIdentifyRequest(cmd);

    // sending command
    c = 0;
    for (;;) {
        WDT_HIT();

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = ToSend[c];
            c++;
            if (c == ToSendMax + 3) {
                break;
            }
        }
    }


    LogTrace(cmd, CMD_ID_RESP, time_start << 4, (GetCountSspClk() - time_start) << 4, NULL, true);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);

    c = 0;
    for (;;) {
        WDT_HIT();

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {

            ci = (int8_t)AT91C_BASE_SSC->SSC_RHR;
            ci = ABS(ci);

            // The samples are correlations against I and Q versions of the
            // tone that the tag AM-modulates, so every other sample is I,
            // every other is Q. We just want power, so abs(I) + abs(Q) is
            // close to what we want.
            // iceman 2016, amplitude sqrt(abs(i) + abs(q))
            if (getNext) {

                buf[c++] = (uint8_t)(MAX(ci, cq) + (MIN(ci, cq) >> 1));

                if (c >= 7000) break;

            } else {
                cq = ci;
            }
            getNext = !getNext;
        }
    }
}

// switch_off,  initreader, no logging
void RecordRawAdcSamplesIso15693(void) {

    int c = 0, getNext = false;
    int ci, cq = 0;

    Iso15693InitReader();

    uint8_t *buf = BigBuf_get_addr();

    for (;;) {
        WDT_HIT();

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {

            ci = (int8_t)AT91C_BASE_SSC->SSC_RHR;
            ci = ABS(ci);
            // The samples are correlations against I and Q versions of the
            // tone that the tag AM-modulates, so every other sample is I,
            // every other is Q. We just want power, so abs(I) + abs(Q) is
            // close to what we want.
            if (getNext) {

                buf[c++] = (uint8_t)(MAX(ci, cq) + (MIN(ci, cq) >> 1));

                if (c >= 7000)
                    break;
            } else {
                cq = ci;
            }

            getNext = !getNext;
        }
    }

    Dbprintf("done");
    switch_off();
}

// Initialize the proxmark as iso15k reader
// (this might produces glitches that confuse some tags
void Iso15693InitReader(void) {
    LEDsoff();
    clear_trace();
    set_tracing(true);

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // Start from off (no field generated)
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    SpinDelay(10);

    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

    FpgaSetupSsc();

    // Give the tags time to energize
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
    SpinDelay(200);

    // Start the timer
    StartCountSspClk();

    LED_A_ON();
}

///////////////////////////////////////////////////////////////////////
// ISO 15693 Part 3 - Air Interface
// This section basicly contains transmission and receiving of bits
///////////////////////////////////////////////////////////////////////

// Encode (into the ToSend buffers) an identify request, which is the first
// thing that you must send to a tag to get a response.
// It expects "cmdout" to be at least CMD_ID_RESP large
static void BuildIdentifyRequest(uint8_t *cmdout) {
    uint8_t cmd[CMD_ID_RESP] = {0, ISO15_CMD_INVENTORY, 0, 0, 0};
    // flags
    cmd[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
    // no mask
    cmd[2] = 0x00;
    // CRC
    AddCrc15(cmd, 3);
    // coding as high speed (1 out of 4)
    CodeIso15693AsReader(cmd, CMD_ID_RESP);
    memcpy(cmdout, cmd, CMD_ID_RESP);
}

// uid is in transmission order (which is reverse of display order)
/*
static void BuildReadBlockRequest(uint8_t **out, uint8_t *uid, uint8_t blockNumber ) {
    uint8_t cmd[CMD_READ_RESP] = {0,0,0,0,0,0,0,0,0,0,0,0,0};
    // If we set the Option_Flag in this request, the VICC will respond with the secuirty status of the block
    // followed by teh block data
    // one sub-carrier, inventory, 1 slot, fast rate
    cmd[0] = (1 << 6)| (1 << 5) | (1 << 1); // no SELECT bit, ADDR bit, OPTION bit
    // READ BLOCK command code
    cmd[1] = 0x20;
    // UID may be optionally specified here
    // 64-bit UID
    cmd[2] = uid[0];
    cmd[3] = uid[1];
    cmd[4] = uid[2];
    cmd[5] = uid[3];
    cmd[6] = uid[4];
    cmd[7] = uid[5];
    cmd[8] = uid[6];
    cmd[9] = uid[7]; // 0xe0; // always e0 (not exactly unique)
    // Block number to read
    cmd[10] = blockNumber;//0x00;
    // CRC
    AddCrc15(cmd, 11);
    CodeIso15693AsReader(cmd, CMD_READ_RESP);
    memcpy(out, cmd, CMD_ID_RESP);
}
*/

// Now the VICC>VCD responses when we are simulating a tag
// It expects "out" to be at least CMD_INV_RESP large
static void BuildInventoryResponse(uint8_t *cmdout, uint8_t *uid) {

    uint8_t cmd[CMD_INV_RESP] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    // one sub-carrier, inventory, 1 slot, fast rate
    // AFI is at bit 5 (1<<4) when doing an INVENTORY
    //(1 << 2) | (1 << 5) | (1 << 1);
    cmd[0] = 0; //
    cmd[1] = 0; // DSFID (data storage format identifier).  0x00 = not supported
    // 64-bit UID
    cmd[2] = uid[7]; //0x32;
    cmd[3] = uid[6]; //0x4b;
    cmd[4] = uid[5]; //0x03;
    cmd[5] = uid[4]; //0x01;
    cmd[6] = uid[3]; //0x00;
    cmd[7] = uid[2]; //0x10;
    cmd[8] = uid[1]; //0x05;
    cmd[9] = uid[0]; //0xe0;
    // CRC
    AddCrc15(cmd, 10);
    CodeIso15693AsReader(cmd, CMD_INV_RESP);
    memcpy(cmdout, cmd, CMD_INV_RESP);
}

// Universal Method for sending to and recv bytes from a tag
//  init ... should we initialize the reader?
//  speed ... 0 low speed, 1 hi speed
//  **recv will return you a pointer to the received data
//  If you do not need the answer use NULL for *recv[]
//  return: lenght of received data
// logging enabled
int SendDataTag(uint8_t *send, int sendlen, bool init, int speed, uint8_t *outdata) {

    int t_samples = 0, wait = 0, elapsed = 0, answer_len = 0;

    LEDsoff();

    if (init) Iso15693InitReader();

    LED_A_ON();

    if (!speed)
        CodeIso15693AsReader256(send, sendlen); // low speed (1 out of 256)
    else
        CodeIso15693AsReader(send, sendlen); // high speed (1 out of 4)

    LED_A_INV();

    uint32_t time_start = GetCountSspClk();

    TransmitTo15693Tag(ToSend, ToSendMax, &t_samples, &wait);
    LogTrace(send, sendlen, time_start << 4, (GetCountSspClk() - time_start) << 4, NULL, true);

    // Now wait for a response
    if (outdata != NULL) {
        LED_B_INV();
        answer_len = GetIso15693AnswerFromTag(outdata, &elapsed);
    }

    LEDsoff();
    return answer_len;
}

// --------------------------------------------------------------------
// Debug Functions
// --------------------------------------------------------------------

// Decodes a message from a tag and displays its metadata and content
#define DBD15STATLEN 48
void DbdecodeIso15693Answer(int len, uint8_t *d) {

    if (len > 3) {
        char status[DBD15STATLEN + 1] = {0};
        if (d[0] & (1 << 3))
            strncat(status, "ProtExt ", DBD15STATLEN - strlen(status));
        if (d[0] & 1) {
            // error
            strncat(status, "Error ", DBD15STATLEN - strlen(status));
            switch (d[1]) {
                case 0x01:
                    strncat(status, "01: not supported", DBD15STATLEN - strlen(status));
                    break;
                case 0x02:
                    strncat(status, "02: not recognized", DBD15STATLEN - strlen(status));
                    break;
                case 0x03:
                    strncat(status, "03: opt not supported", DBD15STATLEN - strlen(status));
                    break;
                case 0x0f:
                    strncat(status, "0F: no info", DBD15STATLEN - strlen(status));
                    break;
                case 0x10:
                    strncat(status, "10: dont exist", DBD15STATLEN - strlen(status));
                    break;
                case 0x11:
                    strncat(status, "11: lock again", DBD15STATLEN - strlen(status));
                    break;
                case 0x12:
                    strncat(status, "12: locked", DBD15STATLEN - strlen(status));
                    break;
                case 0x13:
                    strncat(status, "13: program error", DBD15STATLEN - strlen(status));
                    break;
                case 0x14:
                    strncat(status, "14: lock error", DBD15STATLEN - strlen(status));
                    break;
                default:
                    strncat(status, "unknown error", DBD15STATLEN - strlen(status));
            }
            strncat(status, " ", DBD15STATLEN - strlen(status));
        } else {
            strncat(status, "No error ", DBD15STATLEN - strlen(status));
        }

        if (CheckCrc15(d, len))
            strncat(status, "[+] crc OK", DBD15STATLEN - strlen(status));
        else
            strncat(status, "[!] crc fail", DBD15STATLEN - strlen(status));

        if (DBGLEVEL >= DBG_ERROR) Dbprintf("%s", status);
    }
}

///////////////////////////////////////////////////////////////////////
// Functions called via USB/Client
///////////////////////////////////////////////////////////////////////

//-----------------------------------------------------------------------------
// Act as ISO15693 reader, perform anti-collision and then attempt to read a sector
// all demodulation performed in arm rather than host. - greg
//-----------------------------------------------------------------------------
// ok
// parameter is unused !?!
void ReaderIso15693(uint32_t parameter) {
    int answerLen1 = 0;
    int tsamples = 0, wait = 0, elapsed = 0;
    // set up device/fpga
    Iso15693InitReader();

    uint8_t *answer1 = BigBuf_malloc(50);
    uint8_t *answer2 = BigBuf_malloc(50);

    // Blank arrays
    memset(answer1, 0x00, 50);
    memset(answer2, 0x00, 50);

    // Now send the IDENTIFY command
    // FIRST WE RUN AN INVENTORY TO GET THE TAG UID
    // THIS MEANS WE CAN PRE-BUILD REQUESTS TO SAVE CPU TIME
    uint32_t time_start = GetCountSspClk();
    uint8_t cmd[CMD_ID_RESP] = {0};
    BuildIdentifyRequest(cmd);
    TransmitTo15693Tag(ToSend, ToSendMax, &tsamples, &wait);
    LogTrace(cmd, CMD_ID_RESP, time_start << 4, (GetCountSspClk() - time_start) << 4, NULL, true);

    // Now wait for a response
    answerLen1 = GetIso15693AnswerFromTag(answer1, &elapsed) ;

    // we should do a better check than this
    if (answerLen1 >= 12) {
        uint8_t uid[8];
        uid[0] = answer1[9]; // always E0
        uid[1] = answer1[8]; // IC Manufacturer code
        uid[2] = answer1[7];
        uid[3] = answer1[6];
        uid[4] = answer1[5];
        uid[5] = answer1[4];
        uid[6] = answer1[3];
        uid[7] = answer1[2];

        if (DBGLEVEL >= DBG_EXTENDED) {
            Dbprintf("[+] UID = %02X%02X%02X%02X%02X%02X%02X%02X",
                     uid[0], uid[1], uid[2], uid[3],
                     uid[4], uid[5], uid[5], uid[6]
                    );
        }
        // send UID back to client.
        // arg0 = 1 = OK
        // arg1 = len of response (12 bytes)
        // arg2 = rtf
        // asbytes = uid.
        reply_old(CMD_ACK, 1, sizeof(uid), 0, uid, sizeof(uid));
    }

    if (DBGLEVEL >= DBG_EXTENDED) {
        Dbprintf("[+] %d octets read from IDENTIFY request:", answerLen1);
        DbdecodeIso15693Answer(answerLen1, answer1);
        Dbhexdump(answerLen1, answer1, true);
    }

    switch_off();
}

// Simulate an ISO15693 TAG, perform anti-collision and then print any reader commands
// all demodulation performed in arm rather than host. - greg
void SimTagIso15693(uint32_t parameter, uint8_t *uid) {

    LEDsoff();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
    FpgaSetupSsc();
    // Start from off (no field generated)
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    SpinDelay(200);

    LED_A_ON();

    uint32_t time_start;
    int samples = 0, tsamples = 0;
    int wait = 0, elapsed = 0;

    Dbprintf("ISO-15963 Simulating uid: %02X%02X%02X%02X%02X%02X%02X%02X", uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7]);

    uint8_t buf[ISO15_MAX_FRAME];
    memset(buf, 0x00, sizeof(buf));

    LED_C_ON();

    // Build a suitable reponse to the reader INVENTORY cocmmand
    // not so obsvious, but in the call to BuildInventoryResponse,  the command is copied to the global ToSend buffer used below.
    uint8_t cmd[CMD_INV_RESP] = {0};
    BuildInventoryResponse(cmd, uid);

    while (!BUTTON_PRESS() && !data_available()) {
        WDT_HIT();

        // Listen to reader
        int ans = GetIso15693AnswerFromSniff(buf, &samples, &elapsed) ;

        // we should do a better check than this
        if (ans >= 1) {

            time_start = GetCountSspClk();
            TransmitTo15693Reader(ToSend, ToSendMax, &tsamples, &wait);
            LogTrace(cmd, CMD_INV_RESP, time_start << 4, (GetCountSspClk() - time_start) << 4, NULL, true);

            if (DBGLEVEL >= DBG_EXTENDED) {
                Dbprintf("[+] %d octets read from reader command: %x %x %x %x %x %x %x %x", ans,
                         buf[0], buf[1], buf[2], buf[3],
                         buf[4], buf[5], buf[6], buf[7]
                        );
            }
        }
    }
    switch_off();
}

// Since there is no standardized way of reading the AFI out of a tag, we will brute force it
// (some manufactures offer a way to read the AFI, though)
void BruteforceIso15693Afi(uint32_t speed) {

    uint8_t data[7] = {0, 0, 0, 0, 0, 0, 0};
    uint8_t buf[ISO15_MAX_FRAME];
    memset(buf, 0x00, sizeof(buf));
    int datalen = 0, recvlen = 0;

    Iso15693InitReader();

    // first without AFI
    // Tags should respond wihtout AFI and with AFI=0 even when AFI is active

    data[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
    data[1] = ISO15_CMD_INVENTORY;
    data[2] = 0; // mask length
    AddCrc15(data, 3);
    datalen += 2;

    recvlen = SendDataTag(data, datalen, false, speed, buf);

    WDT_HIT();

    if (recvlen >= 12) {
        Dbprintf("NoAFI UID = %s", sprintUID(NULL, buf + 2));
    }

    // now with AFI
    data[0] |= ISO15_REQINV_AFI;
    //data[1] = ISO15_CMD_INVENTORY;
    data[2] = 0; // AFI
    data[3] = 0; // mask length

    for (uint16_t i = 0; i < 256; i++) {
        data[2] = i & 0xFF;
        AddCrc15(data, 4);
        datalen += 2;
        recvlen = SendDataTag(data, datalen, false, speed, buf);
        WDT_HIT();
        if (recvlen >= 12) {
            Dbprintf("AFI = %i  UID = %s", i, sprintUID(NULL, buf + 2));
        }

        if (BUTTON_PRESS()) {
            DbpString("button pressed, aborting..");
            break;
        }
    }

    DbpString("AFI Bruteforcing done.");
    switch_off();
}

// Allows to directly send commands to the tag via the client
// Has to increase dialog between device and client.
void DirectTag15693Command(uint32_t datalen, uint32_t speed, uint32_t recv, uint8_t *data) {

    bool init = true;
    int buflen = 0;
    uint8_t buf[ISO15_MAX_FRAME];
    memset(buf, 0x00, sizeof(buf));

    if (DBGLEVEL >= DBG_EXTENDED) {
        DbpString("[+] SEND");
        Dbhexdump(datalen, data, true);
    }

    buflen = SendDataTag(data, datalen, init, speed, (recv ? buf : NULL));

    if (recv) {
        buflen = (buflen > ISO15_MAX_FRAME) ? ISO15_MAX_FRAME : buflen;

        LED_B_ON();
        reply_old(CMD_ACK, buflen, 0, 0, buf, buflen);
        LED_B_OFF();

        if (DBGLEVEL >= DBG_EXTENDED) {
            DbpString("[+] RECV");
            DbdecodeIso15693Answer(buflen, buf);
            Dbhexdump(buflen, buf, true);
        }
    } else {
        reply_old(CMD_ACK, 1, 0, 0, 0, 0);
    }
}
