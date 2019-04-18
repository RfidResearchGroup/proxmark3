//-----------------------------------------------------------------------------
// (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
//     2016 Iceman
//     2018 AntiCat
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEGIC RF simulation code
//-----------------------------------------------------------------------------
#include "legicrf.h"

#include "ticks.h"              /* timers */
#include "crc.h"                /* legic crc-4 */
#include "legic_prng.h"         /* legic PRNG impl */
#include "legic.h"              /* legic_card_select_t struct */

static uint8_t *legic_mem;      /* card memory, used for read, write */
static legic_card_select_t card;/* metadata of currently selected card */
static crc_t legic_crc;

//-----------------------------------------------------------------------------
// Frame timing and pseudorandom number generator
//
// The Prng is forwarded every 100us (TAG_BIT_PERIOD), except when the reader is
// transmitting. In that case the prng has to be forwarded every bit transmitted:
//  - 60us for a 0 (RWD_TIME_0)
//  - 100us for a 1 (RWD_TIME_1)
//
// The data dependent timing makes writing comprehensible code significantly
// harder. The current aproach forwards the prng data based if there is data on
// air and time based, using GET_TICKS, during computational and wait periodes.
//
// To not have the necessity to calculate/guess exection time dependend timeouts
// tx_frame and rx_frame use a shared timestamp to coordinate tx and rx timeslots.
//-----------------------------------------------------------------------------

static uint32_t last_frame_end; /* ts of last bit of previews rx or tx frame */

#define RWD_TIME_PAUSE       30 /* 20us */
#define RWD_TIME_1          150 /* READER_TIME_PAUSE 20us off + 80us on = 100us */
#define RWD_TIME_0           90 /* READER_TIME_PAUSE 20us off + 40us on = 60us */
#define RWD_FRAME_WAIT      330 /* 220us from TAG frame end to READER frame start */
#define TAG_FRAME_WAIT      495 /* 330us from READER frame end to TAG frame start */
#define TAG_BIT_PERIOD      150 /* 100us */
#define TAG_WRITE_TIMEOUT    60 /* 40 * 100us (write should take at most 3.6ms) */

#define LEGIC_CARD_MEMSIZE 1024 /* The largest Legic Prime card is 1k */
#define WRITE_LOWERLIMIT      4 /* UID and MCC are not writable */

#define INPUT_THRESHOLD       8 /* heuristically determined, lower values */
/* lead to detecting false ack during write */

//-----------------------------------------------------------------------------
// I/O interface abstraction (FPGA -> ARM)
//-----------------------------------------------------------------------------

static inline uint8_t rx_byte_from_fpga() {
    for (;;) {
        WDT_HIT();

        // wait for byte be become available in rx holding register
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            return AT91C_BASE_SSC->SSC_RHR;
        }
    }
}

//-----------------------------------------------------------------------------
// Demodulation
//-----------------------------------------------------------------------------

// Returns am aproximated power measurement
//
// The FPGA running on the xcorrelation kernel samples the subcarrier at ~3 MHz.
// The kernel was initialy designed to receive BSPK/2-PSK. Hance, it reports an
// I/Q pair every 18.9us (8 bits i and 8 bits q).
//
// The subcarrier amplitude can be calculated using Pythagoras sqrt(i^2 + q^2).
// To reduce CPU time the amplitude is approximated by using linear functions:
//   am = MAX(ABS(i),ABS(q)) + 1/2*MIN(ABS(i),ABSq))
//
// Note: The SSC receiver is never synchronized the calculation may be performed
// on a i/q pair from two subsequent correlations, but does not matter.
static inline int32_t sample_power() {
    int32_t q = (int8_t)rx_byte_from_fpga();
    q = ABS(q);
    int32_t i = (int8_t)rx_byte_from_fpga();
    i = ABS(i);

    return MAX(i, q) + (MIN(i, q) >> 1);
}

// Returns a demedulated bit
//
// An aproximated power measurement is available every 18.9us. The bit time
// is 100us. The code samples 5 times and uses the last (most stable) sample.
//
// Note: The demodulator would be drifting (18.9us * 5 != 100us), rx_frame
// has a delay loop that aligns rx_bit calls to the TAG tx timeslots.
static inline bool rx_bit() {
    int32_t power;

    for (size_t i = 0; i < 5; ++i) {
        power = sample_power();
    }

    return (power > INPUT_THRESHOLD);
}

//-----------------------------------------------------------------------------
// Modulation
//
// I've tried to modulate the Legic specific pause-puls using ssc and the default
// ssc clock of 105.4 kHz (bit periode of 9.4us) - previous commit. However,
// the timing was not precise enough. By increasing the ssc clock this could
// be circumvented, but the adventage over bitbang would be little.
//-----------------------------------------------------------------------------

static inline void tx_bit(bool bit) {
    // insert pause
    LOW(GPIO_SSC_DOUT);
    last_frame_end += RWD_TIME_PAUSE;
    while (GET_TICKS < last_frame_end) { };
    HIGH(GPIO_SSC_DOUT);

    // return to high, wait for bit periode to end
    last_frame_end += (bit ? RWD_TIME_1 : RWD_TIME_0) - RWD_TIME_PAUSE;
    while (GET_TICKS < last_frame_end) { };
}

//-----------------------------------------------------------------------------
// Frame Handling
//
// The LEGIC RF protocol from card to reader does not include explicit frame
// start/stop information or length information. The reader must know beforehand
// how many bits it wants to receive.
// Notably: a card sending a stream of 0-bits is indistinguishable from no card
// present.
//-----------------------------------------------------------------------------

static void tx_frame(uint32_t frame, uint8_t len) {
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX);

    // wait for next tx timeslot
    last_frame_end += RWD_FRAME_WAIT;
    while (GET_TICKS < last_frame_end) { };

    // backup ts for trace log
    uint32_t last_frame_start = last_frame_end;

    // transmit frame, MSB first
    for (uint8_t i = 0; i < len; ++i) {
        bool bit = (frame >> i) & 0x01;
        tx_bit(bit ^ legic_prng_get_bit());
        legic_prng_forward(1);
    };

    // add pause to mark end of the frame
    LOW(GPIO_SSC_DOUT);
    last_frame_end += RWD_TIME_PAUSE;
    while (GET_TICKS < last_frame_end) { };
    HIGH(GPIO_SSC_DOUT);

    // log
    uint8_t cmdbytes[] = {len, BYTEx(frame, 0), BYTEx(frame, 1), BYTEx(frame, 2)};
    LogTrace(cmdbytes, sizeof(cmdbytes), last_frame_start, last_frame_end, NULL, true);
}

static uint32_t rx_frame(uint8_t len) {
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR
                      | FPGA_HF_READER_RX_XCORR_848_KHZ
                      | FPGA_HF_READER_RX_XCORR_QUARTER);

    // hold sampling until card is expected to respond
    last_frame_end += TAG_FRAME_WAIT;
    while (GET_TICKS < last_frame_end) { };

    // backup ts for trace log
    uint32_t last_frame_start = last_frame_end;

    uint32_t frame = 0;
    for (uint8_t i = 0; i < len; ++i) {
        frame |= (rx_bit() ^ legic_prng_get_bit()) << i;
        legic_prng_forward(1);

        // rx_bit runs only 95us, resync to TAG_BIT_PERIOD
        last_frame_end += TAG_BIT_PERIOD;
        while (GET_TICKS < last_frame_end) { };
    }

    // log
    uint8_t cmdbytes[] = {len, BYTEx(frame, 0), BYTEx(frame, 1)};
    LogTrace(cmdbytes, sizeof(cmdbytes), last_frame_start, last_frame_end, NULL, false);

    return frame;
}

static bool rx_ack() {
    // change fpga into rx mode
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR
                      | FPGA_HF_READER_RX_XCORR_848_KHZ
                      | FPGA_HF_READER_RX_XCORR_QUARTER);

    // hold sampling until card is expected to respond
    last_frame_end += TAG_FRAME_WAIT;
    while (GET_TICKS < last_frame_end) { };

    // backup ts for trace log
    uint32_t last_frame_start = last_frame_end;

    uint32_t ack = 0;
    for (uint8_t i = 0; i < TAG_WRITE_TIMEOUT; ++i) {
        // sample bit
        ack = rx_bit();
        legic_prng_forward(1);

        // rx_bit runs only 95us, resync to TAG_BIT_PERIOD
        last_frame_end += TAG_BIT_PERIOD;
        while (GET_TICKS < last_frame_end) { };

        // check if it was an ACK
        if (ack) {
            break;
        }
    }

    // log
    uint8_t cmdbytes[] = {1, BYTEx(ack, 0)};
    LogTrace(cmdbytes, sizeof(cmdbytes), last_frame_start, last_frame_end, NULL, false);

    return ack;
}

//-----------------------------------------------------------------------------
// Legic Reader
//-----------------------------------------------------------------------------

static int init_card(uint8_t cardtype, legic_card_select_t *p_card) {
    p_card->tagtype = cardtype;

    switch (p_card->tagtype) {
        case 0x0d:
            p_card->cmdsize = 6;
            p_card->addrsize = 5;
            p_card->cardsize = 22;
            break;
        case 0x1d:
            p_card->cmdsize = 9;
            p_card->addrsize = 8;
            p_card->cardsize = 256;
            break;
        case 0x3d:
            p_card->cmdsize = 11;
            p_card->addrsize = 10;
            p_card->cardsize = 1024;
            break;
        default:
            p_card->cmdsize = 0;
            p_card->addrsize = 0;
            p_card->cardsize = 0;
            return 2;
    }
    return 0;
}

static void init_reader(bool clear_mem) {
    // configure FPGA
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR
                      | FPGA_HF_READER_RX_XCORR_848_KHZ
                      | FPGA_HF_READER_RX_XCORR_QUARTER);
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
    LED_A_ON();

    // configure SSC with defaults
    FpgaSetupSsc();

    // re-claim GPIO_SSC_DOUT as GPIO and enable output
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
    HIGH(GPIO_SSC_DOUT);

    // reserve a cardmem, meaning we can use the tracelog function in bigbuff easier.
    legic_mem = BigBuf_get_EM_addr();
    if (legic_mem) {
        memset(legic_mem, 0x00, LEGIC_CARD_MEMSIZE);
    }

    // start trace
    clear_trace();
    set_tracing(true);

    // init crc calculator
    crc_init(&legic_crc, 4, 0x19 >> 1, 0x05, 0);

    // start us timer
    StartTicks();
}

// Setup reader to card connection
//
// The setup consists of a three way handshake:
//  - Transmit initialisation vector 7 bits
//  - Receive card type 6 bits
//  - Transmit Acknowledge 6 bits
static uint32_t setup_phase(uint8_t iv) {
    // init coordination timestamp
    last_frame_end = GET_TICKS;

    // Switch on carrier and let the card charge for 5ms.
    last_frame_end += 7500;
    while (GET_TICKS < last_frame_end) { };

    legic_prng_init(0);
    tx_frame(iv, 7);

    // configure prng
    legic_prng_init(iv);
    legic_prng_forward(2);

    // receive card type
    int32_t card_type = rx_frame(6);
    legic_prng_forward(3);

    // send obsfuscated acknowledgment frame
    switch (card_type) {
        case 0x0D:
            tx_frame(0x19, 6); // MIM22 | READCMD = 0x18 | 0x01
            break;
        case 0x1D:
        case 0x3D:
            tx_frame(0x39, 6); // MIM256 | READCMD = 0x38 | 0x01
            break;
    }

    return card_type;
}

static uint8_t calc_crc4(uint16_t cmd, uint8_t cmd_sz, uint8_t value) {
    crc_clear(&legic_crc);
    crc_update(&legic_crc, (value << cmd_sz) | cmd, 8 + cmd_sz);
    return crc_finish(&legic_crc);
}

static int16_t read_byte(uint16_t index, uint8_t cmd_sz) {
    uint16_t cmd = (index << 1) | LEGIC_READ;

    // read one byte
    LED_B_ON();
    legic_prng_forward(2);
    tx_frame(cmd, cmd_sz);
    legic_prng_forward(2);
    uint32_t frame = rx_frame(12);
    LED_B_OFF();

    // split frame into data and crc
    uint8_t byte = BYTEx(frame, 0);
    uint8_t crc = BYTEx(frame, 1);

    // check received against calculated crc
    uint8_t calc_crc = calc_crc4(cmd, cmd_sz, byte);
    if (calc_crc != crc) {
        Dbprintf("!!! crc mismatch: %x != %x !!!",  calc_crc, crc);
        return -1;
    }

    legic_prng_forward(1);

    return byte;
}

// Transmit write command, wait until (3.6ms) the tag sends back an unencrypted
// ACK ('1' bit) and forward the prng time based.
bool write_byte(uint16_t index, uint8_t byte, uint8_t addr_sz) {
    uint32_t cmd = index << 1 | LEGIC_WRITE;          // prepare command
    uint8_t  crc = calc_crc4(cmd, addr_sz + 1, byte); // calculate crc
    cmd |= byte << (addr_sz + 1);                     // append value
    cmd |= (crc & 0xF) << (addr_sz + 1 + 8);          // and crc

    // send write command
    LED_C_ON();
    legic_prng_forward(2);
    tx_frame(cmd, addr_sz + 1 + 8 + 4); // cmd_sz = addr_sz + cmd + data + crc
    legic_prng_forward(3);
    LED_C_OFF();

    // wait for ack
    return rx_ack();
}

//-----------------------------------------------------------------------------
// Command Line Interface
//
// Only this functions are public / called from appmain.c
//-----------------------------------------------------------------------------
void LegicRfInfo(void) {
    // configure ARM and FPGA
    init_reader(false);

    // establish shared secret and detect card type
    uint8_t card_type = setup_phase(0x01);
    if (init_card(card_type, &card) != 0) {
        reply_old(CMD_ACK, 0, 0, 0, 0, 0);
        goto OUT;
    }

    // read UID
    for (uint8_t i = 0; i < sizeof(card.uid); ++i) {
        int16_t byte = read_byte(i, card.cmdsize);
        if (byte == -1) {
            reply_old(CMD_ACK, 0, 0, 0, 0, 0);
            goto OUT;
        }
        card.uid[i] = byte & 0xFF;
    }

    // read MCC and check against UID
    int16_t mcc = read_byte(4, card.cmdsize);
    int16_t calc_mcc = CRC8Legic(card.uid, 4);;
    if (mcc != calc_mcc) {
        reply_old(CMD_ACK, 0, 0, 0, 0, 0);
        goto OUT;
    }

    // OK
    reply_old(CMD_ACK, 1, 0, 0, (uint8_t *)&card, sizeof(legic_card_select_t));

OUT:
    switch_off();
    StopTicks();
}

void LegicRfReader(uint16_t offset, uint16_t len, uint8_t iv) {
    // configure ARM and FPGA
    init_reader(false);

    // establish shared secret and detect card type
    uint8_t card_type = setup_phase(iv);
    if (init_card(card_type, &card) != 0) {
        reply_old(CMD_ACK, 0, 0, 0, 0, 0);
        goto OUT;
    }

    // do not read beyond card memory
    if (len + offset > card.cardsize) {
        len = card.cardsize - offset;
    }

    for (uint16_t i = 0; i < len; ++i) {
        int16_t byte = read_byte(offset + i, card.cmdsize);
        if (byte == -1) {
            reply_old(CMD_ACK, 0, 0, 0, 0, 0);
            goto OUT;
        }
        legic_mem[i] = byte;
    }

    // OK
    reply_old(CMD_ACK, 1, len, 0, legic_mem, len);

OUT:
    switch_off();
    StopTicks();
}

void LegicRfWriter(uint16_t offset, uint16_t len, uint8_t iv, uint8_t *data) {
    // configure ARM and FPGA
    init_reader(false);

    // uid is not writeable
    if (offset <= WRITE_LOWERLIMIT) {
        reply_old(CMD_ACK, 0, 0, 0, 0, 0);
        goto OUT;
    }

    // establish shared secret and detect card type
    uint8_t card_type = setup_phase(iv);
    if (init_card(card_type, &card) != 0) {
        reply_old(CMD_ACK, 0, 0, 0, 0, 0);
        goto OUT;
    }

    // do not write beyond card memory
    if (len + offset > card.cardsize) {
        len = card.cardsize - offset;
    }

    // write in reverse order, only then is DCF (decremental field) writable
    while (len-- > 0 && !BUTTON_PRESS()) {
        if (!write_byte(len + offset, data[len], card.addrsize)) {
            Dbprintf("operation failed | %02X | %02X | %02X", len + offset, len, data[len]);
            reply_old(CMD_ACK, 0, 0, 0, 0, 0);
            goto OUT;
        }
    }

    // OK
    reply_old(CMD_ACK, 1, len, 0, legic_mem, len);

OUT:
    switch_off();
    StopTicks();
}
