//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "hitag2.h"
#include "hitag2/hitag2_crypto.h"
#include "string.h"
#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "fpga_loader.h"
#include "fpga_apis.h"
#include "ticks_apis.h"
#include "dbprint.h"
#include "util.h"
#include "lfadc.h"
#include "hitag_common.h"
#include "lfsampling.h"
#include "lfdemod.h"
#include "commonutil.h"
#include "appmain.h"
#include "protocols.h"

#define test_bit(data, i)  (*(data + (i/8)) >> (7-(i % 8))) & 1
#define set_bit(data, i)   *(data + (i/8)) |= (1 << (7-(i % 8)))
#define clear_bit(data, i) *(data + (i/8)) &= ~(1 << (7-(i % 8)))
#define flip_bit(data, i)  *(data + (i/8)) ^= (1 << (7-(i % 8)))

// Successful crypto auth
static bool bCrypto;
// Is in auth stage
static bool bAuthenticating;

// How many times the reader re-sends the password when the tag's answer to it is
// not heard.  See the case 0 handler in hitag2_password().
// Public Mode C inserts a Program Mode Check phase between each 128 bit block.
// HT2 datasheet rev 2.1 section 4.2.4 gives t_PMC as 384 T0 typical, out of a
// 9120 T0 total against 8192 for the data.
#define HITAG2_T_PMC 384

#define HITAG2_PWD_RETRIES 3

// How many times a single block read is retried in crypto mode before the block
// is given up on and zero filled.  Password mode has had this since the reader
// fixes went in; crypto mode skipped straight to the fill, so one marginal block
// - the receive still loses an edge now and then - put 00000000 in the dump and
// moved on.  Measured against the simulator: crypto reads came back with all of
// blocks 0..7 correct except a single zeroed one, and which block it was moved
// between runs, so nothing about the block itself was wrong.
#define HITAG2_CRYPTO_RETRIES 3
static uint8_t pwd_retries;
static uint8_t crypto_retries;
// Successful password auth
static bool bSelecting;
static bool bCollision;
static bool bPwd;
static bool bSuccessful;

/*
Password Mode : 0x06 - 0000 0110
Crypto Mode   : 0x0E - 0000 1110
Public Mode A : 0x02 - 0000 0010
Public Mode B : 0x00 - 0000 0000
Public Mode C : 0x04 - 0000 0100
*/

// Content presented by a bare `lf hitag sim` when nothing has been loaded with
// `lf hitag eload`.  Kept separate from `tag` because `tag` is mutated while a
// simulation runs - reader writes land in tag.sectors - so it cannot serve as
// its own pristine default on a second run.
static const uint8_t hitag2_demo_sectors[12][4] = {
    [0]  = { 0x02, 0x4e, 0x02, 0x20}, // UID                          | UID
    [1]  = { 0x4d, 0x49, 0x4b, 0x52}, // Password RWD                 | 32 bit LSB key
    [2]  = { 0x20, 0xf0, 0x4f, 0x4e}, // Reserved                     | 16 bit MSB key, 16 bit reserved
    [3]  = { 0x06, 0xaa, 0x48, 0x54}, // Configuration, password TAG  | Configuration, password TAG
    [4]  = { 0x46, 0x5f, 0x4f, 0x4b}, // Data: F_OK
    [5]  = { 0x55, 0x55, 0x55, 0x55}, // Data: UUUU
    [6]  = { 0xaa, 0xaa, 0xaa, 0xaa}, // Data: ....
    [7]  = { 0x55, 0x55, 0x55, 0x55}, // Data: UUUU
    [8]  = { 0x00, 0x00, 0x00, 0x00}, // RSK Low
    [9]  = { 0x00, 0x00, 0x00, 0x00}, // RSK High
    [10] = { 0x00, 0x00, 0x00, 0x00}, // RCF
    [11] = { 0x00, 0x00, 0x00, 0x00}, // SYNC
    // up to index 15 reserved for HITAG 1/HITAG S public data
};

static hitag2_t tag = {
    .state = TAG_STATE_RESET,
};

// see the START_AUTH case in hitag2_handle_reader_command(): a real transponder
// answers every second START_AUTH and treats the one in between as a reset.
//
// Which of the two we answer matters.  A Paxton reader was captured sending
// START_AUTH in pairs 1750 T0 apart, with ~17000..19000 T0 between pairs, and
// the datasheet is explicit that it is the SECOND that resets the state machine
// - so the tag answers the first of a pair and the reader listens after it.
// Carrying the alternation across the gap between pairs locks onto the wrong
// element of every pair: we answered the reset instead of the request.
//
// This threshold therefore has to sit above the intra-pair gap and below the
// inter-pair gap.  An earlier value of 100000 covered both and was wrong.
#define HITAG2_T_SESSION_IDLE  5000

// Step for the FPGA's slope edge detector, in ADC counts over its 32 us
// baseline.  See lf_edge_detect.v for the sweep behind this value and for why it
// is not scaled to the tracked span.  -t overrides it.
// Opening value for the auto-tune sweep, and what an explicit -t 0 settles on.
// The sensitive end of the measured working band - see thr_cand[].
#define HITAG2_SLOPE_THRESHOLD 20

// What the simulator opens on, and the first candidate its sweep scores.
//
// The sniffer keeps 20 above; only a listener, it is not judged on whether a
// reader accepted an answer, and 20 is what its capture was verified at.  The
// simulator is judged exactly that way, and 20 loses on both rigs measured: 0 of
// 8 pages against a Proxmark reader, and 59% legal framing against a Paxton.  It
// stays in thr_cand[] as the fallback for a rig neither represents.
//
// Keep this equal to thr_cand[0].  Set independently once, and the simulator
// opened on 20 while the sweep believed it was scoring 32 - it read 0 of 8 pages
// on a rig that had just read 8 of 8.
#define HITAG2_SIM_THRESHOLD 32

// Frames scored per candidate by the threshold sweep.  Large enough that one
// stray frame does not decide a candidate, small enough that walking the whole
// list is quick - eleven candidates at this window is a couple of seconds of
// ordinary reader traffic.
// Commands scored per candidate.  Too small and a marginal threshold passes on a
// lucky run - at four, a value that managed 0 reads of 3 produced a flawless
// window and locked.  Too large and the sweep outlives a reader that gives up
// after a handful of attempts.
// Modulation depth at or above which the rig is the strongly coupled kind and
// wants 32; below it, 20.  Fitted on 44 runs across both rigs - see the decision
// site for the distribution and the two samples that cross it.
#define HITAG2_SPAN_STRONG 210

// Silence, in T0, after which the reader counts as gone and the threshold
// measurement re-arms.  125000 T0 is one second at 125 kHz - about six and a half
// Paxton poll cycles, so it cannot trip on a gap inside a live exchange.
#define HITAG2_FIELD_GONE_T0 125000

// Blanking window after our own answer, in T0, before the edge detector is
// re-armed.  Covers our coil release; t_WAIT2 (HT2 datasheet 3.5) puts the
// reader's earliest real command at 90 T0, so this must stay under that.
//
// 32 was enough while the release transient landed within a few T0, but it is
// not a fixed property of the firmware - it moves with the coupling.  After the
// rig was re-seated the echo arrived ~80 T0 after transmission instead, escaped
// the guard, opened a frame, and the 80 T0 EOF timeout that closed it ran past
// the reader's next command at +190 T0.  The exchange died there: Paxton sent
// its AUTH, we were not listening, and it fell back to re-polling.
//
// 84 covers the observed echo with the whole t_WAIT2 window still ahead of it.
#define HITAG2_TX_TAIL_GUARD 32

#define HITAG2_THR_WINDOW 8



// flags bit1: answer every START_AUTH instead of every second one
static bool s_no_alternation = false;

// flags bit5: which one of a START_AUTH pair to answer.  A reader that polls in
// pairs gets an answer to the first by default; setting this answers the second.
// HT2 datasheet rev 2.1 section 4.2.2 says a repeated START_AUTH resets the state
// machine and the transponder responds to every second one, so which element of
// the pair the reader is actually listening after is worth being able to flip.
static bool s_alt_phase = false;
static bool start_auth_answered = false;
static uint32_t last_start_auth = 0;

static enum {
    WRITE_STATE_START = 0x0,
    WRITE_STATE_PAGENUM_WRITTEN,
    WRITE_STATE_PROG
} writestate;

// ToDo: define a meaningful maximum size for auth_table. The bigger this is, the lower will be the available memory for traces.
// Historically it used to be FREE_BUFFER_SIZE, which was 2744.
#define AUTH_TABLE_LENGTH 2744
static uint8_t *auth_table;
static size_t auth_table_pos = 0;
static size_t auth_table_len = AUTH_TABLE_LENGTH;

static uint8_t password[4];
static uint8_t NrAr[8];
static uint8_t key[8];
static uint8_t writedata[4];
static uint8_t logdata_0[4], logdata_1[4];
static uint8_t nonce[4];
static uint8_t key_no;
static uint64_t cipher_state;

static int16_t blocknr;
static uint32_t byte_value = 0;

static void hitag2_reset(void) {
    tag.state = TAG_STATE_RESET;
    tag.crypto_active = 0;
}

static void hitag2_init(void) {
    hitag2_reset();
}

// The input-capture timer (StartInputCapture, see common_arm/ticks) runs at
// TIMER_CLOCK3 = MCK/32 = 1.5 MHz. Hitag units (T0) have a duration of 8 us
// (1/125000 s, the carrier period), so T0 = 1.5 MHz / 125 kHz = 12 counter ticks.
#ifndef HITAG_T0
#define HITAG_T0               12
#endif

#define HITAG_FRAME_LEN  20
#define HITAG_FRAME_BIT_COUNT   (8 * HITAG_FRAME_LEN)
#define HITAG_T_STOP     36 /* T_EOF should be > 36 */
// hitag_common.h defines these for Hitag S/u; this file keeps its own values,
// the working reader and writer paths below are timed against them
#undef HITAG_T_LOW
#define HITAG_T_LOW      6  /* T_LOW should be 4..10 */
#undef HITAG_T_0_MIN
#define HITAG_T_0_MIN    15 /* T[0] should be 18..22 */
#define HITAG_T_0        20 /* T[0] should be 18..22 */
#undef HITAG_T_1_MIN
#define HITAG_T_1_MIN    25 /* T[1] should be 26..30 */
#undef HITAG_T_1
#define HITAG_T_1        30 /* T[1] should be 26..30 */
/* HT2 datasheet rev 2.1, sections 3.5 and 4.2.2: t_WAIT1, the transponder's
   receive-to-transmit turnaround, is 199..206 T0 measured from the reader's
   LAST BIT.  Our reference is different: hitag_tag_receive_frame_ex() returns
   HITAG_T_EOF after the last FALLING edge, and in BPLM that edge sits at the
   start of the final bit, one t_low + T[0/1] (roughly 26..40 T0) before the bit
   actually ends.  Answering 202 from the falling edge therefore lands about a
   bit-period early; a genuine fob sniffed on this rig answers noticeably later.
   Add a bit period so the answer lands inside the real window. */
/* t_WAIT1, HT2 datasheet 3.5, is 199..206 T0 measured from the END of the
   reader's command.  Our reference is the reader's last FALLING edge, which in
   BPLM sits at the start of the final bit: the rest of that bit (T_LOW 6 plus
   T[0]-T_LOW = 14) and the T_STOP 36 that closes the frame still have to run,
   about 56 T0 in total.  Counting the datasheet window from the falling edge
   therefore answers a bit period and a half too early.

   That matters because the reader is not merely indifferent to an early reply,
   it is not listening yet: ReaderHitag() waits t_wait_1 - t_wait_1_guard
   (199 - 8 = 191 T0) after its command before sampling, then gives
   lf_count_edge_periods(128) to see a first edge.  The usable window is
   191..319 T0 after the command ends, so aim for the middle of it. */
#define HITAG2_T_CMD_TAIL   56

/* Measured, against a genuine Paxton fob talking to a genuine Paxton reader on
   this rig, with the Proxmark sandwiched between them listening.  The fob's first
   answer edge lands 227 T0 after the reader's last edge, three independent times
   in the same capture and stable across cycles:

     frame         last edge   fob answers   delta
     START_AUTH      8767         8994        227
     password       11116        11343        227
     READ PAGE(4)   12972        13201        229

   (Each logged frame end is last_edge + HITAG_T_EOF, so the 80 is subtracted.)

   The reasoning below arrived at 202 + 56 = 258, which is 31 T0 late.  It is not
   wrong about the tail - the datasheet's 199..206 is measured from the end of the
   frame, and the frame does not end until t_stop has run - it just aimed at the
   middle of OUR reader's window (191..319) rather than at what a real tag does.
   227 sits comfortably inside that window too, so this does not cost us the
   Proxmark to Proxmark path. */
#define HITAG2_T_WAIT_RESP  227

// runtime override for HITAG2_T_WAIT_RESP, so the turnaround can be swept
// against a real reader without reflashing.  0 keeps the default.
static uint16_t s_t_wait_resp = HITAG2_T_WAIT_RESP;
/* hitag_tag_send_frame() holds the line high for this many periods before the
   SOF (the "STD + ADV" pause), so the wait below has to be shortened by it */
#define HITAG2_T_SEND_LEADIN 20
#undef HITAG_T_EOF
#define HITAG_T_EOF      80 /* T_EOF should be > 36    and must be larger than HITAG_T_TAG_CAPTURE_FOUR_HALF */
#define HITAG_T_WAIT_1_MIN   199 /* T_wresp should be 199..206 */
#define HITAG_T_WAIT_2_MIN   90 /* T_wait2 should be at least 90 */
#define HITAG_T_WAIT_MAX 300 /* bit more than HITAG_T_WAIT_1 + HITAG_T_WAIT_2 */
#define HITAG_T_PROG     614
#define HITAG_T_WAIT_POWERUP   313 /* transponder internal powerup time is 312.5 */
#define HITAG_T_WAIT_START_AUTH_MAX   232 /* transponder waiting time to receive the START_AUTH command is 232.5, then it enters public mode */

#define HITAG_T_TAG_ONE_HALF_PERIOD     10
#define HITAG_T_TAG_TWO_HALF_PERIOD     25
#define HITAG_T_TAG_THREE_HALF_PERIOD   41
#define HITAG_T_TAG_FOUR_HALF_PERIOD    57

#define HITAG_T_TAG_HALF_PERIOD         16
#define HITAG_T_TAG_FULL_PERIOD         32

#define HITAG_T_TAG_CAPTURE_ONE_HALF    13
#define HITAG_T_TAG_CAPTURE_TWO_HALF    25
#define HITAG_T_TAG_CAPTURE_THREE_HALF  41
#define HITAG_T_TAG_CAPTURE_FOUR_HALF   57

#define HT2_MAX_NRSZ  ((8 * HITAG_FRAME_LEN + 5) * 2)


// sim
static void hitag2_handle_reader_command(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen) {
    uint8_t rx_air[HITAG_FRAME_LEN];

    // Copy the (original) received frame how it is send over the air
    memcpy(rx_air, rx, nbytes(rxlen));

    if (tag.crypto_active) {
        ht2_hitag2_cipher_transcrypt(&(tag.cs), rx, rxlen / 8, rxlen % 8);
    }

    // Reset the transmission frame length
    *txlen = 0;

    // Any other command ends the START_AUTH session.
    //
    // The datasheet's rule is that "the instruction START_AUTH cannot be
    // repeated.  A second START_AUTH resets the statemachine", so the transponder
    // answers every second one - but that is about a START_AUTH immediately
    // following another, not one arriving after the reader has said something
    // else in between.  Once a real command has gone by, the next START_AUTH
    // opens a fresh session and has to be answered.
    //
    // Measured against a genuine Paxton reader, sniffed with a third Proxmark:
    //
    //   Rdr  5: 18            START AUTH
    //   Tag 32: CE 12 99 11   UID
    //   Rdr 64: ...           AUTH Nr/Ar      crypto probe
    //   Rdr  5: 18            START AUTH      <- fob ANSWERS this one
    //   Tag 32: CE 12 99 11   UID
    //   Rdr 32: BD F5 E8 46   PWD             <- and now the password
    //
    // That second START_AUTH lands about 3500 T0 after the first, inside
    // HITAG2_T_SESSION_IDLE, so without this reset it counts as the repeat and we
    // stay silent.  The reader then never reaches the password step at all, which
    // is exactly what it did with this simulator all day: START_AUTH, our UID,
    // crypto probe, and round again, dozens of times, never once a password.
    // A frame of a length the protocol does not have is not a command at all.
    //
    // A Hitag 2 reader frame is 5, 10, 32 or 64 bits.  Anything else fell through
    // the switch below and did nothing - except that it still passed through the
    // session reset that follows, and that is what broke writing.
    //
    // Measured on two Proxmarks, tracing the simulator through `lf hitag wrbl`:
    // the exchange runs correctly as far as the password, and then
    //
    //     Rdr  5: 18              START AUTH
    //     Tag 32: CE 12 99 11     UID
    //     Rdr 32: BD F5 E8 46     PWD
    //     Tag 32: 06 F9 07 C2     configuration page
    //     Rdr  1: 00              one T0 after our answer ends
    //
    // That one bit frame is our own modulation tail coming back through the edge
    // detector, not the reader - it starts a single T0 after our transmission
    // ends, where a real command cannot.  Dispatched here it rewound the state
    // machine, so the WRITE PAGE that genuinely followed found the session reset
    // and every write failed.  Discard it before it can do that.
    if ((rxlen != 5) && (rxlen != 10) && (rxlen != 32) && (rxlen != 64)) {
        return;
    }

    if (rxlen != 5) {
        start_auth_answered = false;
    }

    // Try to find out which command was send by selecting on length (in bits)
    switch (rxlen) {
        // Received 11000 from the reader, request for UID, send UID
        case 5: {
            // Always send over the air in the clear plaintext mode
            if (rx_air[0] != HITAG2_START_AUTH) {
                // Unknown frame ?
                return;
            }

            // HT2 datasheet rev 2.1 section 4.2.2: "The instruction START_AUTH
            // cannot be repeated.  A second START_AUTH resets the statemachine.
            // Therefore the transponder only responds to every second
            // START_AUTH."  Answering every one presents a reader with a reply
            // where a real tag stays silent.
            //
            // This gate was once removed on the strength of a sniffer capture
            // that appeared to show a genuine fob answering every START_AUTH.
            // That capture was bogus: the tag side decoder fabricates rows, and
            // a control sniff with no card and no simulator present produced the
            // same 1231 "Tag" rows.  With no real counter-evidence the datasheet
            // stands.
            //
            // TIMESTAMP is free running wall time scaled to carrier periods - it
            // does NOT stall when the field goes, whatever this comment used to
            // claim - so a gap larger than the idle threshold means a fresh
            // session rather than the repeat that resets the state machine.
            // That is all this needs; only the elapsed time matters here.
            uint32_t now = TIMESTAMP;
            if ((now - last_start_auth) > HITAG2_T_SESSION_IDLE) {
                // A fresh session.  Starting it as "already answered" skips the
                // first START_AUTH of the pair and answers the second instead.
                start_auth_answered = s_alt_phase;
            }
            last_start_auth = now;

            if (s_no_alternation) {
                start_auth_answered = false;
            }

            if (start_auth_answered) {
                start_auth_answered = false;
                tag.crypto_active = 0;
                tag.state = TAG_STATE_RESET;
                return;
            }
            start_auth_answered = true;

            // START_AUTH resets the state machine (HT2 datasheet 4.2.2), and that
            // has to include a pending write.  A garbled reader frame decoding as
            // WRITE PAGE leaves tag.state at TAG_STATE_WRITING, and the next 32 bit
            // frame - the reader's password - is then swallowed as write data and
            // stored over emulator memory instead of being checked.  Seen on this
            // rig: the reader's follow up commands arrived as 8, 9 and 11 bit
            // fragments, one of them annotated WRITE PAGE (255), and every
            // exchange after it failed to authenticate.
            tag.state = TAG_STATE_RESET;

            *txlen = 32;
            memcpy(tx, tag.sectors[0], 4);
            tag.crypto_active = 0;
        }
        break;

        // Read/Write command: ..xx x..y  yy with yyy == ~xxx, xxx is sector number
        case 10: {
            uint16_t sector = (~(((rx[0] << 2) & 0x04) | ((rx[1] >> 6) & 0x03)) & 0x07);

            // Verify complement of sector index
            if (sector != ((rx[0] >> 3) & 0x07)) {
                DBG DbpString("Transmission error (read/write)");
                return;
            }

            switch (rx[0] & 0xC6) {
                // Read command: 11xx x00y
                case HITAG2_READ_PAGE: {
                    memcpy(tx, tag.sectors[sector], 4);
                    *txlen = 32;
                    break;
                }
                // Inverted Read command: 01xx x10y
                case HITAG2_READ_PAGE_INVERTED: {
                    for (size_t i = 0; i < 4; i++) {
                        tx[i] = tag.sectors[sector][i] ^ 0xff;
                    }
                    *txlen = 32;
                    break;
                }
                // Write command: 10xx x01y
                case HITAG2_WRITE_PAGE: {
                    // Prepare write, acknowledge by repeating command
                    memcpy(tx, rx, nbytes(rxlen));
                    *txlen = rxlen;
                    tag.active_sector = sector;
                    tag.state = TAG_STATE_WRITING;
                    break;
                }
                // Unknown command
                default: {
                    DBG Dbprintf("Unknown command: %02x %02x", rx[0], rx[1]);
                    return;
                }
            }
        }
        break;

        // Writing data or Reader password
        case 32: {
            if (tag.state == TAG_STATE_WRITING) {
                // These are the sector contents to be written. We don't have to do anything else.
                memcpy(tag.sectors[tag.active_sector], rx, nbytes(rxlen));

                // Mirror the write into emulator memory.
                //
                // Simulation serves `tag.sectors`, which is loaded from emulator
                // memory once at start up and never written back, so a reader
                // could write a page, read it back correctly over the air, and
                // `lf hitag eview` would still show the old content - measured on
                // this rig, page 4 read back as 11223344 while eview reported the
                // loaded B6447420.  `lf hitag esave` would then have written the
                // pre-write dump.  Only the tag's own pages: sectors 8..11 hold
                // crypto state, not tag content.
                if (tag.active_sector < HITAG2_MAX_BLOCKS) {
                    uint8_t *emw = BigBuf_get_EM_addr();
                    if (emw != NULL) {
                        memcpy(emw + (tag.active_sector * HITAG_BLOCK_SIZE), rx, HITAG_BLOCK_SIZE);
                    }
                }

                tag.state = TAG_STATE_RESET;
                return;
            } else {
                // Received RWD password, respond with configuration and our password.
                //
                // Password mode only.  In crypto mode a 32 bit frame at this point
                // is an enciphered command, not a plaintext password, and checking
                // it against page 1 would both fail and answer the wrong thing.
                if ((tag.sectors[3][0] & 0x08) != 0) {
                    DBG DbpString("plaintext password to a crypto mode tag, ignoring");
                    return;
                }

                if (memcmp(rx, tag.sectors[1], 4) != 0) {
                    DBG DbpString("Reader password is wrong");
                    return;
                }
                *txlen = 32;
                memcpy(tx, tag.sectors[3], 4);
            }
        }
        break;

        // Received RWD authentication challenge and response
        case 64: {
            // Only a crypto mode tag answers this.
            //
            // Bit 3 of the configuration byte in page 3 selects the mode - 0x06 is
            // password, 0x0E is crypto - and this used to run the cipher regardless
            // of what the loaded tag actually says it is.  A password mode tag has
            // no business authenticating a crypto challenge, and a real one does
            // not: measured against a genuine Paxton reader, it opens with a 64 bit
            // Nr/Ar, the password mode fob stays completely silent, and only then
            // does the reader fall back and send the 32 bit password.  Simulating
            // the tag means following the config block that was loaded, not
            // answering whatever arrives.
            if ((tag.sectors[3][0] & 0x08) == 0) {
                DBG DbpString("crypto auth to a password mode tag, ignoring");
                return;
            }

            // Store the authentication attempt
            if (auth_table_len + 8 <= AUTH_TABLE_LENGTH) {
                memcpy(auth_table + auth_table_len, rx, 8);
                auth_table_len += 8;
            }

            // Reset the cipher state
            ht2_hitag2_cipher_reset(&tag, rx);

            // Check if the authentication was correct
            if (!ht2_hitag2_cipher_authenticate(&(tag.cs), rx + 4)) {
                // The reader failed to authenticate, do nothing
                DBG Dbprintf("auth: %02x%02x%02x%02x%02x%02x%02x%02x Failed!", rx[0], rx[1], rx[2], rx[3], rx[4], rx[5], rx[6], rx[7]);
                return;
            }
            // Activate encryption algorithm for all further communication
            tag.crypto_active = 1;

            // Use the tag password as response
            memcpy(tx, tag.sectors[3], 4);
            *txlen = 32;
        }
        break;
    }

    // LogTraceBits(rx, rxlen, 0, 0, false);
    // LogTraceBits(tx, txlen, 0, 0, true);

    if (tag.crypto_active) {
        ht2_hitag2_cipher_transcrypt(&(tag.cs), tx, *txlen / 8, *txlen % 8);
    }
}

// reader/writer
// returns how long it took
static uint32_t hitag2_reader_send_bit(int bit) {
    // Binary pulse length modulation (BPLM) is used to encode the data stream
    // This means that a transmission of a one takes longer than that of a zero

    // Enable modulation, which means, drop the field
    lf_modulation(true);

    // Wait for 4-10 times the carrier period
    lf_wait_periods(HITAG_T_LOW); // wait for 4-10 times the carrier period
    uint32_t wait = HITAG_T_LOW;

    // Disable modulation, just activates the field again
    lf_modulation(false);

    if (bit == 0) {
        // Zero bit: |_-|
        lf_wait_periods(HITAG_T_0 - HITAG_T_LOW); // wait for 18-22 times the carrier period
        wait += HITAG_T_0 - HITAG_T_LOW;
    } else {
        // One bit: |_--|
        lf_wait_periods(HITAG_T_1 - HITAG_T_LOW); // wait for 26-32 times the carrier period
        wait += HITAG_T_1 - HITAG_T_LOW;
    }

    return wait;
}

// reader / writer commands
// frame_len is in number of bits?
static uint32_t hitag2_reader_send_frame(const uint8_t *frame, size_t frame_len) {
    WDT_HIT();

    uint32_t wait = 0;
    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        wait += hitag2_reader_send_bit((frame[i / 8] >> (7 - (i % 8))) & 1);
    }

    // Send EOF
    // Enable modulation, which means, drop the field
    lf_modulation(true);

    // Wait for 4-10 times the carrier period
    lf_wait_periods(HITAG_T_LOW);
    wait += HITAG_T_LOW;

    // Disable modulation, just activates the field again
    lf_modulation(false);

    // t_stop, high field for stop condition (> 36)
    lf_wait_periods(HITAG_T_STOP);
    wait += HITAG_T_STOP;
    WDT_HIT();
    return wait;
}

// reader / writer commands
// frame_len is in number of bits?
static uint32_t hitag2_reader_send_framebits(const uint8_t *frame, size_t frame_len) {

    WDT_HIT();

    uint32_t wait = 0;
    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        wait += hitag2_reader_send_bit(frame[i]);
    }

    // Send EOF
    // Enable modulation, which means, drop the field
    // set GPIO_SSC_DOUT to HIGH
    lf_modulation(true);

    // Wait for 4-10 times the carrier period
    lf_wait_periods(HITAG_T_LOW);
    wait += HITAG_T_LOW;

    // Disable modulation, just activates the field again
    // set GPIO_SSC_DOUT to LOW
    lf_modulation(false);

    // t_stop, high field for stop condition (> 36)
    lf_wait_periods(HITAG_T_STOP);
    wait += HITAG_T_STOP;

    WDT_HIT();
    return wait;
}

static uint8_t hitag_crc(uint8_t *data, size_t n) {
    uint8_t crc = 0xFF;
    for (size_t i = 0; i < ((n + 7) / 8); i++) {
        crc ^= *(data + i);
        uint8_t bit = n < (8 * (i + 1)) ? (n % 8) : 8;
        while (bit--) {
            if (crc & 0x80) {
                crc <<= 1;
                crc ^= 0x1D;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

/*
void fix_ac_decoding(uint8_t *input, size_t len) {
    // Reader routine tries to decode AC data after Manchester decoding
    // AC has double the bitrate, extract data from bit-pairs
    uint8_t temp[len / 16];
    memset(temp, 0, sizeof(temp));

    for (size_t i = 1; i < len; i += 2) {
        if (test_bit(input, i) && test_bit(input, (i + 1))) {
            set_bit(temp, (i / 2));
        }
    }
    memcpy(input, temp, sizeof(temp));
}
*/


// looks at number of received bits.
// 0 = collision?
// 32 =  good response
static bool hitag1_plain(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen, bool hitag_s) {
    *txlen = 0;
    switch (rxlen) {
        case 0: {
            // retry waking up card
            /*tx[0] = 0xb0; // Rev 3.0*/
            tx[0] = HITAG1_SET_CC; // Rev 2.0
            *txlen = 5;

            if (bCollision == false) {
                blocknr--;
            }

            if (blocknr < 0) {
                blocknr = 0;
            }

            if (hitag_s == false) {
                if (blocknr > 1 && blocknr < 31) {
                    blocknr = 31;
                }
            }
            bCollision = true;
            return true;
        }
        case 32: {
            uint8_t crc;
            if (bCollision) {
                // Select card by serial from response
                tx[0] = HITAG1_SELECT | rx[0] >> 5;
                tx[1] = rx[0] << 3 | rx[1] >> 5;
                tx[2] = rx[1] << 3 | rx[2] >> 5;
                tx[3] = rx[2] << 3 | rx[3] >> 5;
                tx[4] = rx[3] << 3;
                crc = hitag_crc(tx, 37);
                tx[4] |= crc >> 5;
                tx[5] = crc << 3;
                *txlen = 45;
                bCollision = false;
            } else {
                memcpy(tag.sectors[blocknr], rx, 4);
                blocknr++;

                if (hitag_s == false) {
                    if (blocknr > 1 && blocknr < 31) {
                        blocknr = 31;
                    }
                }

                if (blocknr > 63) {
                    DbpString("Read successful!");
                    *txlen = 0;
                    bSuccessful = true;
                    return false;
                }
                // read next page of card until done
                Dbprintf("Reading page %02u", blocknr);
                tx[0] = HITAG1_RDPPAGE | blocknr >> 4; // RDPPAGE
                tx[1] = blocknr << 4;
                crc = hitag_crc(tx, 12);
                tx[1] |= crc >> 4;
                tx[2] = crc << 4;
                *txlen = 20;
            }
            break;
        }
        default: {
            Dbprintf("Unknown frame length: %d", rxlen);
            return false;
        }
    }
    return true;
}

static bool hitag1_authenticate(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen) {
    uint8_t crc;
    *txlen = 0;
    switch (rxlen) {
        case 0: {
            // retry waking up card
            /*tx[0] = 0xb0; // Rev 3.0*/
            tx[0] = HITAG1_SELECT; // Rev 2.0
            *txlen = 5;

            if (bCrypto && byte_value <= 0xff) {
                // to retry
                bCrypto = false;
            }

            if (bCollision == false) {
                blocknr--;
            }

            if (blocknr < 0) {
                blocknr = 0;
            }

            bCollision = true;
            // will receive 32-bit UID
            break;
        }
        case 2: {
            if (bAuthenticating) {
                // received Auth init ACK, send nonce
                // TODO Roel, bit-manipulation goes here
                /*nonce[0] = 0x2d;*/
                /*nonce[1] = 0x74;*/
                /*nonce[2] = 0x80;*/
                /*nonce[3] = 0xa5;*/
                nonce[0] = byte_value;
                byte_value++;
                /*set_bit(nonce,flipped_bit);*/
                memcpy(tx, nonce, 4);
                *txlen = 32;
                // will receive 32 bit encrypted Logdata
            } else if (bCrypto) {
                // authed, start reading
                tx[0] = HITAG1_RDCPAGE | blocknr >> 4; // RDCPAGE
                tx[1] = blocknr << 4;
                crc = hitag_crc(tx, 12);
                tx[1] |= crc >> 4;
                tx[2] = crc << 4;
                *txlen = 20;
                // will receive 32-bit encrypted page
            }
            break;
        }
        case 32: {
            if (bCollision) {
                // Select card by serial from response
                tx[0] = HITAG1_SELECT | rx[0] >> 5;
                tx[1] = rx[0] << 3 | rx[1] >> 5;
                tx[2] = rx[1] << 3 | rx[2] >> 5;
                tx[3] = rx[2] << 3 | rx[3] >> 5;
                tx[4] = rx[3] << 3;
                crc = hitag_crc(tx, 37);
                tx[4] |= crc >> 5;
                tx[5] = crc << 3;
                *txlen = 45;
                bCollision = false;
                bSelecting = true;
                // will receive 32-bit configuration page
            } else if (bSelecting) {
                // Initiate auth
                tx[0] = HITAG1_WRCPAGE | (key_no); // WRCPAGE
                tx[1] = blocknr << 4;
                crc = hitag_crc(tx, 12);
                tx[1] |= crc >> 4;
                tx[2] = crc << 4;
                *txlen = 20;
                bSelecting = false;
                bAuthenticating = true;
                // will receive 2-bit ACK
            } else if (bAuthenticating) {
                // received 32-bit logdata 0
                // TODO decrypt logdata 0, verify against logdata_0
                memcpy(tag.sectors[0], rx, 4);
                memcpy(tag.sectors[1], tx, 4);
                Dbprintf("%02x%02x%02x%02x %02x%02x%02x%02x", rx[0], rx[1], rx[2], rx[3], tx[0], tx[1], tx[2], tx[3]);
                // TODO replace with secret data stream
                // TODO encrypt logdata_1
                memcpy(tx, logdata_1, 4);
                *txlen = 32;
                bAuthenticating = false;
                bCrypto = true;
                // will receive 2-bit ACK
            } else if (bCrypto) {
                // received 32-bit encrypted page
                // TODO decrypt rx
                memcpy(tag.sectors[blocknr], rx, 4);
                blocknr++;
                if (blocknr > 63) {
                    DbpString("Read successful!");
                    bSuccessful = true;
                    return false;
                }

                // TEST
                Dbprintf("Successfully authenticated with logdata:");
                Dbhexdump(4, logdata_1, false);
                bSuccessful = true;
                return false;
                /*
                                // read next page of card until done
                                tx[0] = HITAG1_RDCPAGE | blocknr >> 4; // RDCPAGE
                                tx[1] = blocknr << 4;
                                crc = hitag_crc(tx, 12);
                                tx[1] |= crc >> 4;
                                tx[2] = crc << 4;
                                *txlen = 20;
                */
            }
            break;
        }
        default: {
            Dbprintf("Unknown frame length: %d", rxlen);
            return false;
        }
    }

    return true;
}

//-----------------------------------------------------------------------------
// Hitag 2 operations
//-----------------------------------------------------------------------------

static bool hitag2_write_page(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen) {
    switch (writestate) {
        case WRITE_STATE_START: {
            *txlen = 10;
            tx[0] = HITAG2_WRITE_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2);
            tx[1] = ((blocknr ^ 7) << 6);
            writestate = WRITE_STATE_PAGENUM_WRITTEN;
            break;
        }
        case WRITE_STATE_PAGENUM_WRITTEN: {
            // Check if page number was received correctly
            if ((rxlen == 10)
                    && (rx[0] == (HITAG2_WRITE_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2)))
                    && (rx[1] == (((blocknr & 0x3) ^ 0x3) << 6))) {

                *txlen = 32;
                memset(tx, 0, HITAG_FRAME_LEN);
                memcpy(tx, writedata, 4);
                writestate = WRITE_STATE_PROG;
            } else {
                Dbprintf("hitag2_write_page: Page number was not received correctly: rxlen %d rx %02x%02x%02x%02x"
                         , rxlen
                         , rx[0], rx[1], rx[2], rx[3]
                        );
                bSuccessful = false;
                return false;
            }
            break;
        }
        case WRITE_STATE_PROG: {
            if (rxlen == 0) {
                bSuccessful = true;
            } else {
                bSuccessful = false;
                Dbprintf("hitag2_write_page: unexpected rx data (%d) after page write", rxlen);
            }
            return false;
        }
        default: {
            Dbprintf("hitag2_write_page: Unknown state " _RED_("%d"), writestate);
            bSuccessful = false;
            return false;
        }
    }
    return true;
}

static bool hitag2_password(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen, bool write) {
    // Reset the transmission frame length
    *txlen = 0;

    if (bPwd && (bAuthenticating == false) && write) {

        // A frame we did not hear is not a failed write.
        //
        // Every call landed straight in hitag2_write_page(), rxlen == 0 included,
        // and that reads a missing answer as a protocol error: state
        // WRITE_STATE_PAGENUM_WRITTEN wants exactly 10 bits back, so it declares
        // "page number was not received correctly" and the whole write is
        // abandoned.  The read path has retried a missed answer for a while now -
        // this one never did.
        //
        // Measured against a simulator whose own trace shows it answering
        // correctly: three writes, two lost a single frame to one merged interval
        // in the tag's answer - WRXSTAT undecodable=1, the frame arriving as 35
        // bits where 36 is the minimum - and both failed on that one frame.  The
        // third had a clean run and succeeded.  Re-sending the outstanding command
        // costs one exchange and gives up nothing, exactly as on the read side.
        if ((rxlen == 0) && (pwd_retries < HITAG2_PWD_RETRIES)) {

            pwd_retries++;

            if (writestate == WRITE_STATE_PAGENUM_WRITTEN) {
                // still waiting for the page number echo - ask again
                *txlen = 10;
                tx[0] = HITAG2_WRITE_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2);
                tx[1] = ((blocknr ^ 7) << 6);
                return true;
            }

            if (writestate == WRITE_STATE_PROG) {
                // the data went out and the tag answers nothing when it programs,
                // so silence here is success, not a lost frame
                bSuccessful = true;
                return false;
            }
        }

        SpinDelay(2);
        if (hitag2_write_page(rx, rxlen, tx, txlen) == false) {
            return false;
        }

    } else {
        // Try to find out which command was send by selecting on length (in bits)
        switch (rxlen) {
            // No answer, try to resurrect
            case 0: {
                if (bPwd) {

                    // Missing the tag's answer to the password is not proof that
                    // the password was wrong - it is usually just a frame we did
                    // not hear.  The reader has to listen 174 T0 after its own
                    // 890 T0 transmission, and its front end is still recovering
                    // from that; measured against a simulator whose trace shows it
                    // answering correctly, this is the frame the reader misses
                    // while the shorter exchanges around it decode fine.
                    //
                    // The contents of that answer are discarded at this stage
                    // anyway - see the bAuthenticating branch below - so retrying
                    // the password costs one exchange and gives up nothing.  Only
                    // give up once the retries are spent.
                    if (bAuthenticating && (pwd_retries < HITAG2_PWD_RETRIES)) {
                        pwd_retries++;
                        memcpy(tx, password, 4);
                        *txlen = 32;
                        break;
                    }

                    // Past authentication the same applies to a page read: one
                    // answer we did not hear is not a reason to abandon the whole
                    // dump.  Re-send the READ PAGE for the block we are on.
                    // Measured against a simulator that answers every command
                    // correctly, a single undecodable frame in eight page reads
                    // ended the read with one block returned.
                    if ((bAuthenticating == false) && (pwd_retries < HITAG2_PWD_RETRIES)) {
                        pwd_retries++;
                        *txlen = 10;
                        tx[0] = HITAG2_READ_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2);
                        tx[1] = ((blocknr ^ 7) << 6);
                        break;
                    }

                    DBG DbpString("Password failed!");
                    return false;
                }
                *txlen = 5;
                memcpy(tx, "\xC0", nbytes(*txlen));
                break;
            }

            // Received UID, tag password
            case 32: {
                // stage 1, got UID
                if (bPwd == false) {
                    bPwd = true;
                    bAuthenticating = true;
                    memcpy(tx, password, 4);
                    *txlen = 32;
                } else {
                    // stage 2, got config byte+password TAG, discard as will read later
                    if (bAuthenticating) {
                        bAuthenticating = false;

                        if (write) {

                            if (!hitag2_write_page(rx, rxlen, tx, txlen)) {
                                return false;
                            }
                            break;
                        }
                    }
                    // stage 2+, got data block
                    else {
                        memcpy(tag.sectors[blocknr], rx, 4);
                        blocknr++;
                        pwd_retries = 0;
                    }

                    if (blocknr > 7) {
                        bSuccessful = true;
                        return false;
                    }

                    *txlen = 10;
                    tx[0] = HITAG2_READ_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2);
                    tx[1] = ((blocknr ^ 7) << 6);
                }
                break;
            }
            // Unexpected response
            default: {
                DBG Dbprintf("Unknown frame length: " _RED_("%d"), rxlen);
                return false;
            }
        }
    }

    return true;
}

static bool hitag2_crypto(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen, bool write) {
    // Reset the transmission frame length
    *txlen = 0;

    if (bCrypto) {
        ht2_hitag2_cipher_transcrypt(&cipher_state, rx, rxlen / 8, rxlen % 8);
    }

    if (bCrypto && (bAuthenticating == false) && write) {

        SpinDelay(2);
        if (hitag2_write_page(rx, rxlen, tx, txlen) == false) {
            return false;
        }

    } else {

        // Try to find out which command was send by selecting on length (in bits)
        switch (rxlen) {
            // No answer, try to resurrect
            case 0: {
                // Stop if there is no answer while we are in crypto mode (after sending NrAr)
                if (bCrypto) {
                    // Failed during authentication
                    if (bAuthenticating) {
                        DBG DbpString("Authentication failed!");
                        return false;
                    } else if (crypto_retries < HITAG2_CRYPTO_RETRIES) {

                        // Try this block again rather than giving up on it.
                        //
                        // Re-authenticating is what makes the retry safe: the
                        // cipher stream has advanced by our unanswered command,
                        // so simply re-sending it would decrypt against the wrong
                        // keystream.  Dropping bCrypto restarts from START_AUTH,
                        // which resynchronises both sides, and blocknr is left
                        // where it is so the same page is asked for again.
                        crypto_retries++;
                        bCrypto = false;

                    } else {
                        // Failed reading a block, could be (read/write) locked, skip block and re-authenticate
                        crypto_retries = 0;
                        if (blocknr == 1) {
                            // Write the low part of the key in memory
                            memcpy(tag.sectors[1], key + 2, 4);
                        } else if (blocknr == 2) {
                            // Write the high part of the key in memory
                            tag.sectors[2][0] = 0x00;
                            tag.sectors[2][1] = 0x00;
                            tag.sectors[2][2] = key[0];
                            tag.sectors[2][3] = key[1];
                        } else {
                            // Just put zero's in the memory (of the unreadable block)
                            memset(tag.sectors[blocknr], 0x00, 4);
                        }
                        blocknr++;
                        bCrypto = false;
                    }
                } else {
                    *txlen = 5;
                    memcpy(tx, "\xc0", nbytes(*txlen));
                }
                break;
            }
            // Received UID, crypto tag answer
            case 32: {
                // stage 1, got UID
                if (bCrypto == false) {

                    uint64_t ui64key = key[0] |
                                       ((uint64_t)key[1]) << 8 |
                                       ((uint64_t)key[2]) << 16 |
                                       ((uint64_t)key[3]) << 24 |
                                       ((uint64_t)key[4]) << 32 |
                                       ((uint64_t)key[5]) << 40;

                    uint32_t ui32uid = MemLeToUint4byte(rx);

                    DBG Dbprintf("hitag2_crypto: key array ");
                    DBG Dbhexdump(6, key, false);
                    DBG Dbprintf("hitag2_crypto: key=0x%x%x uid=0x%x"
                                 , (uint32_t)((REV64(ui64key)) >> 32)
                                 , (uint32_t)((REV64(ui64key)) & 0xffffffff)
                                 , REV32(ui32uid)
                                );

                    cipher_state = ht2_hitag2_init(REV64(ui64key), REV32(ui32uid), 0);

                    // PRN  00 00 00 00
                    memset(tx, 0x00, 4);
                    // Secret data FF FF FF FF
                    memset(tx + 4, 0xff, 4);
                    ht2_hitag2_cipher_transcrypt(&cipher_state, tx + 4, 4, 0);
                    *txlen = 64;
                    bCrypto = true;
                    bAuthenticating = true;
                } else {

                    // stage 2, got config byte+password TAG, discard as will read later
                    if (bAuthenticating) {

                        bAuthenticating = false;

                        if (write) {
                            if (hitag2_write_page(rx, rxlen, tx, txlen) == false) {
                                return false;
                            }
                            break;
                        }

                    } else { // stage 2+, got data block

                        // Store the received block
                        memcpy(tag.sectors[blocknr], rx, 4);
                        blocknr++;
                        crypto_retries = 0;
                    }

                    if (blocknr > 7) {
                        DBG DbpString("Read successful!");
                        bSuccessful = true;
                        return false;
                    } else {
                        *txlen = 10;
                        tx[0] = HITAG2_READ_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2);
                        tx[1] = ((blocknr ^ 7) << 6);
                    }
                }
                break;
            }
            default: {
                DBG Dbprintf("Unknown frame length: " _RED_("%d"), rxlen);
                return false;
            }
        }
    }

    // try to avoid double encryption calls
    if (bCrypto && bAuthenticating == false) {
        ht2_hitag2_cipher_transcrypt(&cipher_state, tx, *txlen / 8, *txlen % 8);
    }

    return true;
}

static bool hitag2_authenticate(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen, bool write) {
    // Reset the transmission frame length
    *txlen = 0;

    // Try to find out which command was send by selecting on length (in bits)
    switch (rxlen) {
        case 0: {
            // No answer, try to resurrect
            // Stop if there is no answer while we are in crypto mode (after sending NrAr)
            if (bCrypto) {
                DBG DbpString("No answer after sending NrAr!");
                return false;
            } else {

                // Failed during authentication
                if (bAuthenticating) {
                    DBG DbpString("Authentication - failed!");
                    return false;
                }

                DBG DbpString("Authenticating - send 0xC0");
                *txlen = 5;
                memcpy(tx, "\xC0", nbytes(*txlen));
            }
            break;
        }
        case 32: {
            // Received UID or crypto tag answer
            if (bCrypto == false) {
                *txlen = 64;
                memcpy(tx, NrAr, sizeof(NrAr));
                bCrypto = true;
                bAuthenticating = true;
                DBG DbpString("Authenticating sending NrAr");
            } else {
                DBG DbpString("Authentication successful!");

                // stage 2, got config byte+password TAG, discard as will read later
                if (bAuthenticating) {

                    bAuthenticating = false;

                    if (write) {
                        if (hitag2_write_page(rx, rxlen, tx, txlen) == false) {
                            return false;
                        }
                        break;
                    }

                } else { // stage 2+, got data block

                    // Store the received block
                    memcpy(tag.sectors[blocknr], rx, 4);
                    blocknr++;
                }

                if (blocknr > 7) {
                    DBG DbpString("Read successful!");
                    bSuccessful = true;
                    return false;
                } else {

                    DBG Dbprintf("Sending read block %u", blocknr);

                    *txlen = 10;
                    tx[0] = HITAG2_READ_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2);
                    tx[1] = ((blocknr ^ 7) << 6);
                }
            }
            break;
        }
        default: {
            DBG Dbprintf("Unknown frame length: " _RED_("%d"), rxlen);
            return false;
        }
    }
    return true;
}

static bool hitag2_test_auth_attempts(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen) {

    // Reset the transmission frame length
    *txlen = 0;

    // Try to find out which command was send by selecting on length (in bits)
    switch (rxlen) {
        // No answer, try to resurrect
        case 0: {
            // Stop if there is no answer while we are in crypto mode (after sending NrAr)
            if (bCrypto) {
                Dbprintf("auth: %02x%02x%02x%02x%02x%02x%02x%02x Failed, removed entry!", NrAr[0], NrAr[1], NrAr[2], NrAr[3], NrAr[4], NrAr[5], NrAr[6], NrAr[7]);

                // Removing failed entry from authentications table
                memcpy(auth_table + auth_table_pos, auth_table + auth_table_pos + 8, 8);
                auth_table_len -= 8;

                // Return if we reached the end of the authentications table
                bCrypto = false;
                if (auth_table_pos == auth_table_len) {
                    return false;
                }

                // Copy the next authentication attempt in row (at the same position, b/c we removed last failed entry)
                memcpy(NrAr, auth_table + auth_table_pos, 8);
            }
            *txlen = 5;
            memcpy(tx, "\xc0", nbytes(*txlen));
            break;
        }
        // Received UID, crypto tag answer, or read block response
        case 32: {
            if (bCrypto == false) {
                *txlen = 64;
                memcpy(tx, NrAr, 8);
                bCrypto = true;
            } else {
                Dbprintf("auth: %02x%02x%02x%02x%02x%02x%02x%02x ( " _GREEN_("ok") " )", NrAr[0], NrAr[1], NrAr[2], NrAr[3], NrAr[4], NrAr[5], NrAr[6], NrAr[7]);
                bCrypto = false;
                if ((auth_table_pos + 8) == auth_table_len) {
                    return false;
                }
                auth_table_pos += 8;
                memcpy(NrAr, auth_table + auth_table_pos, 8);
            }
            break;
        }
        default: {
            Dbprintf("Unknown frame length: " _RED_("%d"), rxlen);
            return false;
        }
    }
    return true;
}

// Hitag 2 Sniffing
void hitag_sniff(void) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    BigBuf_free();
    BigBuf_Clear_ext(false);
    set_tracing(true);

    // Set up eavesdropping mode, frequency divisor which will drive the FPGA
    // and analog mux selection.
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT  | FPGA_LF_EDGE_DETECT_TOGGLE_MODE);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125); // 125Khz
    SetAdcMuxFor(ADC_MUXSEL_LOPKD);
}


// T0     18-22 fc  (total time ZERO)
// T1     26-32 fc  (total time ONE)
// Tstop  36 >  fc  (high field stop limit)
// Tlow   4-10  fc  (reader field low time)
// One captured falling-edge interval, decoded into the frame in progress.
//
// Factored out of SniffHitag2()'s capture loop so the first edge of a frame -
// which has to be held until the following rising edge says whether this is the
// reader talking or the tag - can be dispatched through exactly the same code
// once it is classified, rather than through a second copy that would drift.
// Returns true when this edge closed the frame in progress.
static bool hitag2_sniff_bit(int rb, bool reader_frame, uint8_t *rx, size_t sizeofrx,
                             size_t *rxlen, int *lastbit, bool *bSkip, int *tag_sof) {

    if ((*rxlen / 8) >= sizeofrx) {
        return false;
    }

    if (reader_frame) {

        // Capture reader frame
        if (rb >= HITAG_T_STOP) {
            // Capture the T0 periods that have passed since last communication or field drop (reset)
            // A gap this long is a frame boundary, but the frame is left
            // to close on the EOF timeout instead of ending here.  Ending
            // it here does stop adjacent frames merging into one long
            // "frame", however capture quality varies so much run to run
            // that neither behaviour could be shown to be better on real
            // hardware.  Left as-is; revisit with a repeatable rig.
            if (*rxlen != 0) {
                DBG Dbprintf("stop gap mid-frame, rxlen %i", (int)*rxlen);
            }

        } else if (rb >= HITAG_T_1_MIN) {
            // '1' bit
            rx[*rxlen / 8] |= 1 << (7 - (*rxlen % 8));
            (*rxlen)++;

        } else if (rb >= HITAG_T_0_MIN) {
            // '0' bit
            rx[*rxlen / 8] |= 0 << (7 - (*rxlen % 8));
            (*rxlen)++;
        }

    } else {

        // Capture tag frame (manchester decoding using only falling edges)
        if (rb >= HITAG_T_EOF) {
            // Capture the T0 periods that have passed since last communication or field drop (reset)
            // We always receive a 'one' first, which has the falling edge after a half period |-_|

            // A gap this long ends the tag's answer, and saying so here is what
            // keeps the reader's next command in a frame of its own.
            //
            // The capture loop otherwise only ends a frame on HITAG_T_EOF of
            // silence measured by the edge counter, and after a tag answer that
            // silence never arrives: the tag's modulation decays rather than
            // stopping, so the slope detector keeps firing across the ~230 T0
            // turnaround.  After a READER frame the field is steady and the
            // counter does time out, which is why tag frames come out perfect
            // while reader frames do not.
            //
            // The consequence is that the reader's opening gap - and sometimes
            // its first bit - is fed to the manchester decoder above before the
            // rising edge has said whose frame this is, and resetting rxlen at
            // that switch then throws the bit away.  Measured against a genuine
            // Paxton reader: 4 of every 6 reader frames came out one bit short
            // with everything shifted left, the 32 bit password reading back as
            // 7BEBD08C where BDF5E846 was sent.
            //
            // Ending the frame on the gap itself costs nothing - the gap carries
            // no bit in either direction - and leaves the opening gap to start
            // the next frame cleanly, which is where every other Hitag 2 receive
            // path in this file already gets it right.
            if (*rxlen > 0) {
                return true;
            }

        } else if (rb >= HITAG_T_TAG_CAPTURE_FOUR_HALF) {
            // Manchester coding example |-_|_-|-_| (101)
            rx[*rxlen / 8] |= 0 << (7 - (*rxlen % 8));
            (*rxlen)++;
            rx[*rxlen / 8] |= 1 << (7 - (*rxlen % 8));
            (*rxlen)++;

        } else if (rb >= HITAG_T_TAG_CAPTURE_THREE_HALF) {
            // Manchester coding example |_-|...|_-|-_| (0...01)
            rx[*rxlen / 8] |= 0 << (7 - (*rxlen % 8));
            (*rxlen)++;
            // We have to skip this half period at start and add the 'one' the second time
            if (*bSkip == false) {
                rx[*rxlen / 8] |= 1 << (7 - (*rxlen % 8));
                (*rxlen)++;
            }
            *lastbit = !*lastbit;
            *bSkip = !*bSkip;

        } else if (rb >= HITAG_T_TAG_CAPTURE_TWO_HALF) {
            // Manchester coding example |_-|_-| (00) or |-_|-_| (11)
            if (*tag_sof) {
                // Ignore bits that are transmitted during SOF
                (*tag_sof)--;
            } else {
                // bit is same as last bit
                rx[*rxlen / 8] |= *lastbit << (7 - (*rxlen % 8));
                (*rxlen)++;
            }
        }
    }

    return false;
}

void SniffHitag2(bool ledcontrol, uint8_t threshold) {

    if (ledcontrol) LED_D_ON();
    hitag_edges_reset();
    g_tx_samples = 0; g_tx_bails = 0; g_tx_frames = 0;

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // a sniff needs the trace, not emulator memory - leave an eload intact
    BigBuf_free_keep_EM();
    BigBuf_Clear_keep_EM();
    // BigBuf_Clear_ext() used to do this for us, BigBuf_Clear_keep_EM() does not
    clear_trace();
    set_tracing(true);

    /*
        lf_init(LF_ADC_SNIFF, LF_ADC_WAV_REVERSED, ledcontrol);

        // no logging of the raw signal
    g_logging = true;
        uint32_t total_count = 0;

    uint8_t rx[HITAG_FRAME_BIT_COUNT * 2];

        while (BUTTON_PRESS() == false) {

            lf_reset_counter();

            WDT_HIT();

            size_t periods = 0;
            uint16_t rxlen = 0;
            memset(rx, 0x00, sizeof(rx));

            // Use the current modulation state as starting point
            uint8_t mod_state = lf_get_reader_modulation();

            while (rxlen < sizeof(rx)) {
                periods = lf_count_edge_periods(64);
                // Evaluate the number of periods before the next edge
                if (periods >= 24 && periods < 64) {
                    // Detected two sequential equal bits and a modulation switch
                    // NRZ modulation: (11 => --|) or (11 __|)
                    rx[rxlen++] = mod_state;
                    if (rxlen < sizeof(rx)) {
                    rx[rxlen++] = mod_state;
                    }
                    // toggle tag modulation state
                    mod_state ^= 1;

                } else if (periods > 0 && periods < 24) {
                    // Detected one bit and a modulation switch
                    // NRZ modulation: (1 => -|) or (0 _|)
                    rx[rxlen++] = mod_state;
                    mod_state ^= 1;
                } else {
                    mod_state ^= 1;
                // The function lf_count_edge_periods() returns > 64 periods, this is not a valid number periods
                Dbprintf("Detected unexpected period count... " _YELLOW_("%zu"), periods);
                    break;
                }

            }

            if (rxlen < 10) {
                continue;
            }

            // tag sends 11111 + uid,
        bool got_tag = (memcmp(rx, "\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00", 10) == 0);

        Dbprintf("periods... %zu   rxlen... %u", periods, rxlen);
        Dbhexdump(rxlen, rx, false);

            if (got_tag) {

                bool bad_man = false;
                uint16_t bitnum = 0;
                // mqnchester decode
                for (uint16_t i = 0; i < rxlen; i += 2) {

                    if (rx[i] == 1 && (rx[i + 1] == 0)) {
                        rx[bitnum++] = 0;
                    } else if ((rx[i] == 0) && rx[i + 1] == 1) {
                        rx[bitnum++] = 1;
                    } else {
                        bad_man = true;
                        break;
                    }
                }
    //                Dbprintf(_YELLOW_("TAG") " rxlen... %u  bitnum... %u", rxlen, bitnum);
                if (bad_man) {
                Dbprintf("bad manchester  ( bitnum %u )", bitnum);
                    continue;;
                }

                if (bitnum < 5) {
                    DbpString("too few bits");
                    continue;
                }

            // Pack the response into a byte array,
            // and skip header 11111  (start at idx 5)
                rxlen = 0;

                for (uint16_t i = 5; i < bitnum; i++) {
                    uint8_t b = rx[i];
                    rx[rxlen >> 3] |= b << (7 - (rxlen % 8));
                    rxlen++;
                }

                // skip spurious bit
                if (rxlen % 8 == 1) {
                    rxlen--;
                }

                // nothing to log
                if (rxlen == 0) {
                    if (ledcontrol) LED_A_INV();
                    continue;
                }

            LogTraceBits(rx, rxlen, 0, periods, false);
                total_count += nbytes(rxlen);

            } else {

                // nothing to log
                if (rxlen < 3) {
                    if (ledcontrol) LED_A_INV();
                    continue;
                }

                uint16_t n = 0;
                for (uint16_t i = 0; i < rxlen; i++) {
                    uint8_t b = rx[i];
                    rx[n >> 3] |= b << (7 - (n % 8));
                    n++;
                }

                // decode reader comms
            LogTraceBits(rx, n, 0, periods, true);
                total_count += nbytes(n);
            }
            if (ledcontrol) LED_A_INV();
        }

        StopTimestamp();
    lf_finalize(ledcontrol);
        Dbprintf("Collected %u bytes", total_count);
    switch_off();
    BigBuf_free();
    }
        */

    // Bring the front end up the same way the simulator does, in slope mode.
    //
    // This used to write the conf word by hand and nothing else, which left two
    // things wrong.  The LF ADC front end was never initialised, and this file's
    // own note on that records the symptom exactly: "a detector free running at
    // ~52 kHz - 633k edges in 12 s with nothing framed, and no value of the
    // threshold making any measurable difference".  And the conf word write
    // resets lf_ed_threshold to 127 in fpga_pm3_top.v, so no threshold was ever
    // in force.  Measured on a live fob-to-Paxton exchange: `lf hitag sniff`
    // returned zero rows and hung, where the simulator's listen only mode
    // captured 1808 frames off the same exchange.
    //
    // hitag_setup_fpga() does the bring up in the right order and sets the
    // threshold after its own conf word write.  Slope mode is what made the
    // simulator's receive work; the level slicing path this used before is the
    // configuration that was measured not to.
    hitag_setup_fpga(FPGA_LF_EDGE_DETECT_SLOPE, threshold, ledcontrol);

    uint8_t active_threshold = threshold;
    if (threshold == 0) {
        active_threshold = HITAG2_SLOPE_THRESHOLD;
        FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, active_threshold);
    }

    // Dont use the FPGA modulation output, we only want to capture the tag/reader comms
    gpio_fpga_mod_only_setup();
    Gpio_SSC_DOUT_Low();

    // Configure the input capture (TC1) via the HAL: it enables the TC1 clock, routes
    // SSC_FRAME to the timer input, resets on each falling edge and captures RB
    // (falling->falling) / RA (falling->rising).
    StartLoEdgeCapture();

    // the trace wants real timestamps, and nothing else in this function starts
    // the counter - without it every logged frame gets a garbage start and end
    StartTimestamp();

    uint32_t frame_start = 0;
    int frame_count = 0, lastbit = 1, tag_sof = 4;

    // Count both ways a reader can try to authenticate.
    //
    // Only the 64 bit crypto challenge was ever tallied, so a capture of a
    // password mode exchange - which is most of them - reported "Auth
    // attempts... 0" however many times the reader had presented its password.
    uint32_t crypto_attempts = 0, pwd_attempts = 0;
    bool reader_frame = false, bSkip = true;

    // HACK -- add one byte to avoid rewriting manchester decoder for edge case
    uint8_t rx[HITAG_FRAME_LEN + 1] = {0};
    size_t rxlen = 0;

    auth_table_len = 0;
    auth_table_pos = 0;

    auth_table = (uint8_t *)BigBuf_calloc(AUTH_TABLE_LENGTH);

    // Only for debug, if we want to see the edge timing of the captured frames
    uint8_t edges[100];
    uint8_t e_count = 0;

    // TEMP DIAG: what the falling edge just before the reader/tag switch was
    // carrying, for the first few reader frames.  If it is a bit length interval
    // (18..32 T0) rather than a long opening gap, the first bit was consumed by
    // the tag path before the switch happened - which is the head bit loss.

    // Candidate first bit of a reader frame, see the switch below.
    bool head_valid = false, head_bit = false;
    uint16_t last_rb = 0;

    // TEMP DIAG: falling-edge intervals of frames that turn out to be TAG frames,
    // so a genuine fob's answer and a simulated one can be diffed edge for edge.
    uint8_t d_cur[24] = {0}, d_curn = 0;
    uint8_t d_tag[2][24] = {{0}}, d_tagn[2] = {0}, d_tagf = 0;


    while ((BUTTON_PRESS() == false) && (data_available() == false)) {

        WDT_HIT();

        // Receive frame, watch for at most HITAG_T0 * HITAG_T_EOF periods since the last edge.
        //
        // Bounded, for the same reason hitag_tag_receive_frame_ex() is: when the
        // edge detector has nothing clean to work with it fires continuously, the
        // capture counter never reaches the EOF limit and this loop never returns
        // - so the outer loop never gets back to its data_available() check and
        // the device wedges with no way back short of a replug.  Measured: this
        // is why `lf hitag sniff` ignored `hw break` and hung the client.  The
        // shared receive already had this guard; this was a private copy that
        // never got it.
        uint32_t guard = HITAG_RX_IDLE_GUARD;
        while (GetLoEdgeCaptureCount() < (HITAG_T0 * HITAG_T_EOF)) {

            if (--guard == 0) {
                break;
            }
            if ((guard & 0x3FF) == 0) {
                WDT_HIT();
            }

            // Read (and clear) the input-capture edge-event flags.
            lo_edge_t lo_edge = GetLoEdgeCaptureStatus();

            // Rising edge: RA holds the falling->rising sub-period (the reader's tlow).
            if (lo_edge == LO_EDGE_RISING) {
                int ra = GetLoEdgeCaptureRising() / HITAG_T0;


                // Shorter periods only happen with reader frames (reader tlow is 4..10 T0,
                // while the shortest tag Manchester half-period is 16 T0).
                if (reader_frame == false && ra < HITAG_T_TAG_CAPTURE_ONE_HALF) {
                    // Switch from tag to reader capture
                    if (ledcontrol) LED_C_OFF();
                    reader_frame = true;
                    rxlen = 0;
                    memset(rx, 0x00, sizeof(rx));

                    // Keep the first bit, if the switch came one edge too late.
                    //
                    // The reader/tag decision is taken on the RISING edge that
                    // closes a gap, but the falling edge that opened it has
                    // already been through the loop - and while reader_frame is
                    // still false that goes to the tag manchester path.  When the
                    // gap being classified is the frame's first BIT rather than
                    // its opener, resetting rxlen here throws that bit away.
                    //
                    // Measured against a genuine Paxton reader: the falling edge
                    // immediately before the switch carried 48, 47, 31, 47, 47,
                    // 31 T0.  The 31s are bit length intervals ('1' is 26..32),
                    // not opening gaps, and the frames they belong to came out
                    // exactly one bit short with everything shifted left - the
                    // 32 bit password read back as 31 bits, 7BEBD08C where
                    // BDF5E846 was sent, and 10 bit READ PAGEs as 9.
                    //
                    // An opening gap is longer than t_stop, so anything shorter
                    // than that is a bit.  Remember it as a candidate head bit
                    // rather than committing to it here: the idle before a frame
                    // can carry noise edges, and seeding on those turned the 5 bit
                    // START_AUTH into 6.  The frame's own length decides, below.
                    //
                    // Where the missing interval comes from.
                    //
                    // Measured, by logging every edge event unfiltered across one
                    // turnaround.  A reader frame that follows a tag answer opens:
                    //
                    //   80fe   RISING  ra=254   no falling preceded this at all
                    //   800a   RISING  ra=10    two risings running: one lost
                    //   001a   FALLING rb=26    ... and the frame decodes from here
                    //
                    // ra is the falling to rising sub period, so ra=254 says the
                    // capture counter had not been reset for 254 T0 - the FPGA
                    // produced no falling edge for that first gap.  The interval
                    // that would have carried bit 0 was therefore never measured,
                    // which is why recovering it from TC_RB, holding the first
                    // falling edge for classification, and closing the tag frame
                    // on its own gap all changed nothing: there was nothing there
                    // to recover.
                    //
                    // Both risings sit one t_low after their own gap, so the
                    // difference between their timestamps IS the gap to gap
                    // interval, and that is bit 0's period.  Fall back to the last
                    // decoded interval when the falling edge was present, which is
                    // the case this used to handle.
                    // Deriving it from the two rising timestamps was tried and is
                    // inert: those two risings straddle the whole turnaround, about
                    // 230 T0, not the missing bit, so the value is never in the bit
                    // range.  Left out rather than left in doing nothing.
                    const uint16_t head_rb = last_rb;

                    head_valid = ((head_rb >= HITAG_T_0_MIN) && (head_rb < HITAG_T_STOP));
                    head_bit = (head_rb >= HITAG_T_1_MIN);
                }
            }

            // Falling edge: RB holds the falling->falling full period (the bit timing).
            if (lo_edge == LO_EDGE_FALLING) {
                int rb = GetLoEdgeCaptureFalling() / HITAG_T0;
                g_hitag_edges++;
                last_rb = (uint16_t)rb;

                if (d_curn < sizeof(d_cur)) {
                    d_cur[d_curn++] = (rb > 255) ? 255 : (uint8_t)rb;
                }

                if (e_count < sizeof(edges)) {
                    edges[e_count++] = rb; // Store the edge timing for debug purposes
                }

                if (frame_start == 0) {
                    frame_start = TIMESTAMP;
                }

                if (ledcontrol) {
                    if (reader_frame) LED_B_ON();
                    else LED_C_ON();
                }

                if (hitag2_sniff_bit(rb, reader_frame, rx, sizeof(rx), &rxlen,
                                     &lastbit, &bSkip, &tag_sof)) {
                    // Frame closed by this gap.  Leave the capture loop so the
                    // frame is logged, and let the gap open the next one.
                    break;
                }
            }
        }  // end while

        // Check if frame was captured.
        //
        // A tag frame has to be long enough to be one: a Hitag 2 answer is 10 or
        // 32 bits behind its SOF, so anything shorter on the tag side is noise
        // that the manchester path above happily turned into bits.  That is what
        // produced the fabricated "Tag" rows - a control sniff with no card and
        // no simulator present still logged 1231 of them - which made every tag
        // side number from this command untrustworthy.  Reader frames keep their
        // own minimum of 1, since START_AUTH is legitimately 5 bits.
        if (rxlen && (reader_frame || (rxlen >= 8))) {

            // Put back the head bit, but only when the length says one is missing.
            //
            // A Hitag 2 reader frame is 5, 10, 32 or 64 bits - START_AUTH, a
            // read/write command, a password or page, or an authentication pair.
            // Landing exactly one short of one of those is the signature of the
            // lost head bit, and nothing else produces it.  Deciding here rather
            // than at the switch means a noise edge in the idle cannot lengthen a
            // frame that was already the right size.
            if (reader_frame && head_valid &&
                    ((rxlen == 4) || (rxlen == 9) || (rxlen == 31) || (rxlen == 63))) {

                const size_t nb = (rxlen + 8) / 8;
                if (nb <= sizeof(rx)) {
                    uint8_t carry = head_bit ? 0x80 : 0x00;
                    for (size_t i = 0; i < nb; i++) {
                        const uint8_t next = (rx[i] & 1) ? 0x80 : 0x00;
                        rx[i] = (uint8_t)(rx[i] >> 1) | carry;
                        carry = next;
                    }
                    rxlen++;
                }
            }
            head_valid = false;

            frame_count++;
            LogTraceBits(rx, rxlen, frame_start, TIMESTAMP, reader_frame);

            // Dump the raw edge timings of tag frames.  A tag answer that decodes
            // to only a bit or two still has all its edges here, which is the only
            // way to see which half-period thresholds it is actually falling into.
            DBG {
                if ((reader_frame == false) && (e_count > 3)) {
                    DBG Dbprintf("TAGEDGES bits=%zu count=%u", rxlen, e_count);
                    Dbhexdump(e_count, edges, false);
                }
            }

            // Check if we recognize a valid authentication attempt
            //
            // 64 bits from the reader is a crypto challenge, 32 bits from the
            // reader is a password.  The same 32 bits from the TAG is page data,
            // so the direction has to be part of the test.
            if (reader_frame) {
                if (rxlen == 64) {
                    crypto_attempts++;
                    // Store the authentication attempt
                    if (auth_table_len + 8 <= AUTH_TABLE_LENGTH) {
                        memcpy(auth_table + auth_table_len, rx, 8);
                        auth_table_len += 8;
                    }
                } else if (rxlen == 32) {
                    pwd_attempts++;
                }
            }

            if (ledcontrol) {
                LED_B_OFF();
                LED_C_OFF();
            }

            // commit the interval trace if this was a real tag answer
            if ((reader_frame == false) && (rxlen >= 8) && (d_tagf < 2)) {
                d_tagn[d_tagf] = d_curn;
                for (uint8_t k = 0; k < d_curn; k++) {
                    d_tag[d_tagf][k] = d_cur[k];
                }
                d_tagf++;
            }

            reader_frame = false;
            lastbit = 1;
            bSkip = true;
            tag_sof = 4;
            e_count = 0;
            frame_start = 0;
        }

        // Reset the frame length and clear the buffer so that '0' bits written
        // by the next frame don't inherit stale '1' bits from this one.
        rxlen = 0;
        d_curn = 0;
        memset(rx, 0x00, sizeof(rx));
    }

    if (ledcontrol) LEDsoff();

    DBG Dbprintf("frames.......... %d", frame_count);
    for (uint8_t i = 0; i < d_tagf; i++) {
        DBG Dbprintf("TAGIV%u n=%u: %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u", i, d_tagn[i],
                 d_tag[i][0], d_tag[i][1], d_tag[i][2], d_tag[i][3],
                 d_tag[i][4], d_tag[i][5], d_tag[i][6], d_tag[i][7],
                 d_tag[i][8], d_tag[i][9], d_tag[i][10], d_tag[i][11],
                 d_tag[i][12], d_tag[i][13], d_tag[i][14], d_tag[i][15]);
    }
    Dbprintf("Auth attempts... crypto %u, password %u",
             (unsigned)crypto_attempts, (unsigned)pwd_attempts);

    // Stop logging raw samples.
    //
    // g_logging is global and this was the only place that ever set it, with
    // nothing to clear it - so one `lf hitag sniff` left sample logging on for
    // the rest of the power cycle.  Every LF command afterwards then calls
    // logSampleSimple() for every ADC sample inside lf_count_edge_periods_ex(),
    // which slows that loop, makes it miss samples, and stretches the bit timings
    // of anything that transmits.  It reads as the reader and writer becoming
    // unreliable until the device is replugged.
    g_logging = false;

    StopLoEdgeCapture();
    StopTimestamp();
    switch_off();
    BigBuf_free_keep_EM();
}


// Measured, so it is not retried: validating each bit duration against the
// datasheet windows - T[0] 18..22, T[1] 26..32, nothing in between or beyond -
// as an extra condition for locking a threshold candidate makes things worse,
// not better.  6 of 10 authentications when applied to START_AUTH, 7 of 10 when
// applied to the password, against 9 of 10 with the frame length alone.  So few
// candidates satisfy it on a recovering envelope that the search never settles.
// It does correctly identify the bad frames - a spurious early edge gives
// 19,20,40,30 where 19,30,30,30 was sent - but rejecting them costs more than the
// occasional wrong bit does.

// Hitag 2 simulation
void SimulateHitag2(uint8_t threshold, uint16_t twait, uint8_t flags, uint8_t sof, uint8_t duty, bool ledcontrol) {

    hitag_tag_set_mod_polarity((flags & 1) != 0);
    hitag_tag_set_mod_duty(duty);
    s_no_alternation = ((flags & 2) != 0);
    s_alt_phase = false;

    // flags bit5: toggle mode.  lo_edge_detect.v drives ssp_frame from
    // edge_toggle instead of edge_state, which its own comment says is there "to
    // enable detecting two consecutive peaks at the same level" - the run of BPLM
    // zeroes we lose a bit in.  edge_state needs the envelope back over a
    // threshold before it will report another gap; toggle only needs the peak.
    // Slope detection is the default, not an option.
    //
    // It used to be opt in behind diagnostic bit 5, which meant a plain
    // `lf hitag sim -2` - the documented command - ran the level slicing path
    // instead and did nothing at all: measured on two Proxmarks 1 cm apart,
    // start_auth=0 answers=0 at the simulator and RXFAIL no_signal=122 at the
    // reader, not one block read.  Everything that works here was developed and
    // verified with bit 5 set, so it is the working configuration and belongs on
    // by default.  Bit 5 stays accepted so existing command lines keep working;
    // it simply no longer changes anything.
    //
    // The level slicing path needs the envelope back over a threshold before it
    // will report another gap, and on a run of BPLM zeroes it never gets there,
    // so two bits merge into one interval.  Slope compares each sample against
    // one 32 us earlier and calls the edge on the difference, which is what a
    // gap looks like whatever the DC level is doing.
    const uint16_t slope = FPGA_LF_EDGE_DETECT_SLOPE;

    // flags bit6: listen only.  Receive and trace the reader exactly as the
    // simulator does, but never answer, so a genuine tag can be watched talking
    // to a real reader over the receive path that is known to work here.
    // `lf hitag sniff` uses the ADC sniff path instead and captures nothing on
    // this rig, so it is no use as a reference.
    const bool listen_only = ((flags & 64) != 0);

    // flags bit4: modulate on the 10k leg alone.  A genuine fob dips our antenna's
    // envelope to ~105 of ~148; both legs together take it to 0.
    const uint16_t weak = ((flags & 16) != 0) ? FPGA_LF_WEAK_LOAD : 0;

    // flags bit7: let the edge detector work on a small tracked span, so the
    // reader's frame is still sliced while our envelope is recovering.  Holding
    // the envelope follower instead (FPGA_LF_EDGE_DETECT_HOLD_TRACKER) was tried
    // and measured to change nothing: the trouble is not the follower's stored
    // min and max, it is that the signal itself is ramping.
    const uint16_t sensitive = ((flags & 128) != 0) ? FPGA_LF_EDGE_DETECT_SENSITIVE : 0;

    start_auth_answered = false;
    last_start_auth = 0;
    hitag_edges_reset();

    s_t_wait_resp = (twait != 0) ? twait : HITAG2_T_WAIT_RESP;

    // Six SOF bits, though the datasheet (HT2 3.3.1) says five.
    //
    // The sixth replaces a compensation that no longer exists.  This used to read
    // "five SOF bits, per the datasheet; the lost head half bit is covered by the
    // lead-in in hitag_tag_send_frame_mc4k_sync()" - but that lead-in was measured
    // to break the frame for our own reader and was taken out, and nothing
    // replaced it.  The answer has been one bit period short ever since.
    //
    // A genuine Paxton reader rejects the short answer outright.  It does not
    // fail loudly: it replies to our UID with a SECOND START_AUTH about 1100 T0
    // later, which the datasheet says resets the state machine, then goes quiet
    // for a whole poll cycle.  In a trace that second START_AUTH decodes as a 3 or
    // 4 bit frame - 06, 0C - and the giveaway is its length, ~190 T0, the same as
    // a real five bit START_AUTH.  Measured on <pm3 - paxton>, no card in field:
    //
    //     sof  answer(T0)  rdr 32-bit  pwd_ok  read_ok
    //      5      1186          0          0        0
    //      6      1218        154        187      747
    //      7      1250          0          0        0
    //      8      1282         20         20       25
    //
    // Six costs nothing anywhere else.  On <pm3 - pm3>, over eight runs each,
    // reads went 6/8 at five and 5/8 at six, and writes 3/3 against 2/3 - the same
    // rig's own run to run spread, not a regression.
    //
    // Not understood: a genuine fob's answer measures 1247 T0 sniffed, which is
    // sof 7 (1250), yet sof 7 fails on the same reader that sof 6 satisfies.  So
    // the fob's extra length is not simply more SOF bits, and this constant is
    // where the evidence points rather than where a derivation ends.
    const int sof_bits = (sof != 0) ? (int)sof : 6;


    // keep emulator memory, that is where eload put the tag content.
    // hitag_setup_fpga() below loads the LF bitstream with the EM-preserving
    // variant and clears the trace, so nothing here may wipe BigBuf wholesale.
    BigBuf_free_keep_EM();
    BigBuf_Clear_keep_EM();

    uint8_t rx[HITAG_FRAME_LEN] = {0};
    uint8_t tx[HITAG_FRAME_LEN] = {0};

    auth_table_len = 0;
    auth_table_pos = 0;
//    auth_table = BigBuf_calloc(AUTH_TABLE_LENGTH);

    DbpString("Starting Hitag 2 simulation");

    // hitag2 state machine?
    hitag2_init();

    // Serve what `lf hitag eload` put in emulator memory.  The static table this
    // file initialises `tag` with is only a fallback: a bare `lf hitag sim` with
    // nothing loaded keeps presenting the built-in demo tag rather than a tag of
    // all zeroes.  Only the 8 real pages come from emulator memory, sectors 8-11
    // hold crypto state (RSK, RCF, SYNC) that is not part of the tag content.
    uint8_t *em = BigBuf_get_EM_addr();
    bool em_empty = true;
    for (size_t i = 0; i < HITAG2_MAX_BYTE_SIZE; i++) {
        if (em[i] != 0) {
            em_empty = false;
            break;
        }
    }

    // Always repopulate, never inherit - a previous run leaves its tag content,
    // and any writes the reader made, behind in the static `tag`.
    if (em_empty) {
        DbpString("Emulator memory is empty, simulating the built-in demo tag");
        memcpy(tag.sectors, hitag2_demo_sectors, sizeof(hitag2_demo_sectors));
    } else {
        memset(tag.sectors, 0, sizeof(tag.sectors));
        for (size_t i = 0; i < HITAG2_MAX_BLOCKS; i++) {
            memcpy(tag.sectors[i], em + (i * HITAG_BLOCK_SIZE), HITAG_BLOCK_SIZE);
        }
    }

    // printing
    uint32_t block = 0;
    // Only the tag's own blocks.  `tag.sectors` is sized for the largest Hitag
    // variant, and sectors 8..11 hold crypto state (RSK, RCF, SYNC) rather than
    // tag content, so printing all twelve showed four rows of 00000000 that are
    // not part of a Hitag 2 at all.
    for (size_t i = 0; i < HITAG2_MAX_BLOCKS; i++) {

        // num2bytes?
        for (size_t j = 0; j < 4; j++) {
            block <<= 8;
            block |= tag.sectors[i][j];
        }
        Dbprintf("| %d | %08x |", i, block);
    }

// SIMULATE
    //
    // Physical layer: the FPGA edge-detect path shared with the Hitag S and u
    // simulators, not the older ADC sample-and-threshold path.  The ADC path
    // compares against a hardcoded avg +/- LIMIT_DEV (20) window, and a 100% ASK
    // reader carrier sits at its own average, so the rising half of every
    // transition can never cross avg+20 and the frame decoding collapses.  The
    // edge detector thresholds in hardware and the level is tunable.
    // Do NOT write the conf word again here.  fpga_pm3_top.v resets the edge
    // detect threshold whenever FPGA_CMD_SET_CONFREG selects LF_EDGE_DETECT:
    //     `FPGA_CMD_SET_CONFREG:
    //         if (shift_reg[8:6] == `FPGA_MAJOR_MODE_LF_EDGE_DETECT)
    //             lf_ed_threshold <= 127;   // default threshold
    // hitag_setup_fpga() sets the threshold straight after its own conf word
    // write, so repeating that write here threw the setting away and -t had no
    // measurable effect at any value.
    // Hold the envelope follower across our own answer.
    //
    // Our load modulation drives the same min/max tracker the edge detector
    // slices against, so a strong load pins it and leaves us deaf for a while
    // after every frame we send.  Measured against a genuine Paxton reader: we
    // heard 96 of its 218 START_AUTH polls, missing the second of every pair,
    // and its follow up command arrives about 269 T0 after our answer - the
    // datasheet allows as little as 90 - so we would have missed that too.
    //
    // Modulating less fixes the deafness and costs us the reader: with the
    // lightest load a Proxmark reader 1 cm away heard nothing at all,
    // RXFAIL no_signal=127.  Freezing the tracker instead keeps the load that
    // works and takes the self-interference out of the reference.  The hold is
    // retriggerable and releases about 340 us after our last transition, which
    // is inside t_WAIT2 either way.
    hitag_setup_fpga(weak | sensitive | slope | FPGA_LF_EDGE_DETECT_HOLD_TRACKER,
                     threshold, ledcontrol);
    uint8_t active_threshold = threshold;

    // Slope mode is not auto-tuned.
    //
    // hitag_autotune_threshold() scores candidates by edge rate, and in slope mode
    // a low threshold produces an edge storm - measured, 1602 edges and not one
    // decodable frame - which that metric reads as the best candidate.  It also
    // runs before any reader traffic exists, so there is nothing but noise to tune
    // on.  Use a value measured to work instead; -t overrides it.
    if ((slope != 0) && (threshold == 0)) {
        active_threshold = HITAG2_SIM_THRESHOLD;
        FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, active_threshold);
        DBG Dbprintf("Slope detect threshold %u", active_threshold);
    } else if (threshold == 0) {
        uint8_t tuned = hitag_autotune_threshold();
        FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, tuned);
        active_threshold = tuned;
        DBG Dbprintf("Edge detect threshold auto-tuned to %u", tuned);
    }

    // hitag_setup_fpga() uses gpio_fpga_mod_only_setup(), which claims SSC_DOUT
    // but leaves SSC_CLK with the SSC peripheral.  SimulateTagLowFrequency(),
    // the LF tag simulator that is known to work on this hardware, claims both
    // via gpio_fpga_mod_feedback_setup() so the peripheral cannot drive the pin
    // while we modulate.  Match it.
    gpio_fpga_mod_feedback_setup();
    Gpio_SSC_DOUT_Low();

    int overflow = 0;

    // TEMP DIAGNOSTIC: counters only, reported after the loop so nothing is
    // printed while the exchange is live (hw dbg perturbs the timing).
    uint32_t d_loops = 0, d_frames = 0, d_bits5 = 0, d_answers = 0;
    uint32_t last_rx_ts = 0, d_meas_n = 0, d_rearm_n = 0;

    // Per-length command census, so a run can be judged without the trace.
    //
    // The trace buffer fills long before the post-answer search settles - one
    // 70 second run against a Paxton reader had the trace end at about 4 seconds
    // while the first complete transaction did not happen until 23 - so counting
    // "did a full read happen" from `trace list` reports failure on runs that
    // actually succeeded.  These count the whole run.
    //
    // d_auth_short is the one that matters: a 64 bit challenge arriving as 60..63
    // bits is the post-answer threshold dropping the last edges, and it is the
    // difference between a reader that authenticates and one that gives up.
    uint32_t d_auth64 = 0, d_auth_short = 0, d_pwd_ok = 0, d_read_ok = 0;
    uint32_t d_post_eval = 0;
    uint8_t d_span = 0;
    bool thr_measured = false;
    uint8_t d_p50 = 0, d_p90 = 0, d_p99 = 0, d_pmax = 0;
    uint32_t d_nsteps = 0, d_nbig = 0, d_meas = 0;

    // TEMP INSTRUMENT: what the receiver actually sees in the window right after
    // we answer.  Nothing is printed while the exchange is live - `hw dbg` and
    // any Dbprintf inside the loop move every timing this is meant to measure -
    // so it is all stored and dumped once the loop has ended.
#define SIMSNAP 1
    static uint16_t s_iv[SIMSNAP][8];
    static uint8_t  s_ivn[SIMSNAP];
    static uint16_t s_rxl[SIMSNAP];
    static uint32_t s_gap[SIMSNAP];    // our answer's end -> next frame's first edge
    static uint32_t s_wait[SIMSNAP];   // rx_end -> answer start (should be t_wait_resp - T_EOF)
    static uint32_t s_txdur[SIMSNAP];  // how long our answer took, in T0
    static uint32_t s_rearm[SIMSNAP];  // answer end -> capture re-armed
    static uint16_t s_skip[SIMSNAP];   // empty receive windows before that frame
    static uint32_t s_clk[SIMSNAP];    // carrier half cycles seen in the 300 T0 after our answer
    static uint16_t s_it[SIMSNAP][8];  // receive loop polls between one edge and the next
#define ADCSNAP 8
    static uint8_t s_adc_mn[ADCSNAP], s_adc_mx[ADCSNAP];
    static bool s_adc_valid = false;
    s_adc_valid = false;   // static, so clear it or a later run dumps stale data
    uint8_t s_nsnap = 0;
    uint32_t d_listen5 = 0;

    // Adaptive slope threshold.
    //
    // A fixed step has to be re-found every time the coupling changes - measured
    // across one session it moved 30, 31, 32, 34, and outside a two or three count
    // window it either chatters or resolves nothing.  Tuning it at startup does
    // not work either: hitag_autotune_threshold() scores candidates by edge rate,
    // and in slope mode the chattering end wins, and there is no reader traffic to
    // judge on yet anyway.
    //
    // So tune on real traffic against something known: a Hitag 2 reader opens with
    // START_AUTH, five bits of 0x18.  Step through candidates until that decodes,
    // then hold; if it stops decoding for a while, resume searching.  Nothing here
    // guesses what the data should be - it only asks whether the framing came out
    // valid, which is the same check the command dispatch already applies.
    // Known good values first, then fill in the range.
    //
    // Two thresholds have been measured to work, each on a different rig: 20 with
    // a genuine Paxton reader, where its 64 bit challenge arrives whole instead of
    // sliced into 21..23 bit fragments, and 32 with a Proxmark reader a centimetre
    // away, where the coupling is far stronger and 20 chatters.  Trying those two
    // first means the common cases settle in at most two scoring windows instead
    // of walking the list; the rest are there for a rig that is neither.
    // Only the two values known to work.
    //
    // 20 with a genuine Paxton reader, where its 64 bit challenge arrives whole
    // instead of sliced into 21..23 bit fragments; 32 with a Proxmark reader a
    // centimetre away, where the coupling is far stronger and 20 chatters.  The
    // intermediate values were never measured to be right anywhere, and every
    // candidate costs a scoring window out of the reader's patience - measured,
    // three `lf hitag read` attempts were spent tuning before one succeeded.
    //
    // This is only the fallback: it runs when the measurement below found no real
    // modulation to work from.
    static const uint8_t thr_cand[] = { HITAG2_SIM_THRESHOLD, 20 };
    uint8_t thr_idx = 0;
    uint16_t thr_seen = 0, thr_hit = 0;
    uint8_t thr_best_idx = 0;
    uint16_t thr_best_hit = 0;
    bool thr_locked = (threshold != 0);   // an explicit -t is taken as given

    // A second threshold, for the window right after we answer.
    //
    // START_AUTH arrives on a settled envelope; the reader's next frame arrives
    // while ours is still recovering from our own modulation, which is a different
    // signal to slice.  One threshold cannot suit both, so the post answer window
    // gets its own, tuned the same way - on whether the framing came out at a
    // length the protocol has (10 for a read, 32 for a password), never on whether
    // the contents match what we expect, which would just be deciding the answer
    // in advance.
    // Two values, the same two the main sweep uses.
    //
    // This list was briefly widened to { 20, 16, 12, 24, 28, 32 } on the theory
    // that a 64 bit challenge arriving as 61 bits meant the step was still too
    // coarse and the search should reach lower.  Measured, that made it worse,
    // not better: two 40 second runs against a Paxton reader decoded no command
    // of any length at all - auth64=0, authshort=0, pwd_ok=0, read_ok=0 - and
    // never locked, because six candidates means most of the run is spent on a
    // value that cannot work, and the reader gives up long before the sweep comes
    // back round.
    //
    // 20 and 32 are the only two values measured to work on any rig, so they are
    // the only two offered.  A short list is not a limitation here, it is the
    // point: settling is what the reader is waiting for.
    static const uint8_t post_cand[] = { 20, 32 };
    uint8_t post_idx = 0;
    uint8_t post_thr = post_cand[0];
    uint16_t post_bad = 0;
    bool post_active = false;
    bool post_locked = false;

    bool snap_next = false;
    uint16_t snap_skipped = 0;
    uint32_t last_tx_end = 0;

    // our answer is traced after the following receive, see below
    bool tx_pending = false;
    size_t tx_pending_len = 0;
    uint32_t tx_pending_start = 0, tx_pending_end = 0;
    uint8_t tx_pending_buf[8] = {0};

    // TEMP flags bit2: hold the coil load on and do nothing else, so the effect of
    // our modulation can be measured directly from the reader's ADC statistics.
    if ((flags & 4) != 0) {
        // Toggle the load at the Hitag 2 Manchester half-bit rate, continuously.
        //
        // Holding it statically was the wrong diagnostic: the reader's LOPKD path
        // peak detects, so a DC load barely shows (it moved the reader's average
        // by 3-4 counts) while a toggling one produces a large swing.  EM410x sim
        // toggles, and swings the same reader's ADC rail to rail from this coil,
        // so this shows whether our toggling is comparable.
        DBG DbpString("Hitag 2: toggling coil load at RF/32 (diagnostic)");
        while ((BUTTON_PRESS() == false) && (data_available() == false)) {
            WDT_HIT();
            for (uint32_t half = 0; half < HITAG_T_TAG_HALF_PERIOD; half++) {
                uint32_t g = 20000;
                while ((Gpio_SSC_CLK_Read() == false) && (--g)) { }
                while ((Gpio_SSC_CLK_Read() == true) && (--g)) { }
            }
            Gpio_SSC_DOUT_High();
            for (uint32_t half = 0; half < HITAG_T_TAG_HALF_PERIOD; half++) {
                uint32_t g = 20000;
                while ((Gpio_SSC_CLK_Read() == false) && (--g)) { }
                while ((Gpio_SSC_CLK_Read() == true) && (--g)) { }
            }
            Gpio_SSC_DOUT_Low();
        }
        Gpio_SSC_DOUT_Low();
        hitag_cleanup(ledcontrol);
        return;
    }

    // Public modes: stop being a Hitag 2 and just talk.
    //
    // HT2 datasheet rev 2.1 sections 4.2.3 and 4.2.4.  Bit 3 of the configuration
    // byte picks password or crypto, and bits 2..1 pick between normal Hitag 2 and
    // the three read only public modes:
    //
    //   0x06  Password mode        command protocol, plain data after password
    //   0x0E  Crypto mode          command protocol, encrypted data
    //   0x02  Public Mode A        Manchester 64 T0, pages 4,5   (uEM H400x)
    //   0x00  Public Mode B        Biphase    32 T0, pages 4..7  (ISO 11784/85)
    //   0x04  Public Mode C        Biphase    64 T0, pages 4..7  (PCF793X)
    //
    // "If the read/write device does not send the instruction START_AUTH within
    // tWAIT START_AUTH after the Power_Up the transponder begins to send the data
    // in one of the public modes" - and past that window it "enters the read-only
    // state", so it stops answering commands altogether.  The simulator has no
    // power up event to time from, the field is already there when it starts, so
    // the config byte alone decides: a public mode config goes straight to
    // transmitting.  Loading a password or crypto config keeps the command
    // protocol exactly as before.
    const uint8_t cfg = tag.sectors[3][0];
    const uint8_t pubmode = (uint8_t)((cfg & 0x06) >> 1);

    if (pubmode != 3) {

        // Manchester for A, biphase for B and C; 64 T0 per bit for the 2 kbit/s
        // modes, 32 for the 4 kbit/s one.
        const bool biphase = (pubmode != 1);
        const uint8_t period = (pubmode == 0) ? 32 : 64;

        // A sends pages 4 and 5, B and C send pages 4 to 7.
        const size_t pages = (pubmode == 1) ? 2 : 4;
        const size_t nbits = pages * 8 * HITAG_BLOCK_SIZE;

        uint8_t pub[4 * HITAG_BLOCK_SIZE] = {0};
        for (size_t i = 0; i < pages; i++) {
            memcpy(pub + (i * HITAG_BLOCK_SIZE), tag.sectors[4 + i], HITAG_BLOCK_SIZE);
        }

        Dbprintf("Hitag 2: public mode %c, config 0x%02x, %s %u T0, pages 4..%u",
                 (pubmode == 1) ? 'A' : ((pubmode == 0) ? 'B' : 'C'),
                 cfg, biphase ? "biphase" : "manchester", period, 3 + pages);

        while ((BUTTON_PRESS() == false) && (data_available() == false)) {
            WDT_HIT();
            hitag_tag_send_public(pub, nbits, period, biphase, ledcontrol);

            // Public Mode C puts a Program Mode Check between blocks; A and B
            // send the pages back to back with no gap at all.
            //
            // Unloaded for the whole phase.  The datasheet gives the PMC only as
            // a waveform drawing with Thi = 64 T0, Tlow1 = 128 T0 and Tlow2 = 192
            // T0 - which do sum to the 384 T0 t_PMC in its timing table - but the
            // drawing does not survive text extraction, so the exact shape is not
            // known here.  Leaving the coil loaded across it, which is what
            // happened when the level was simply held from the last bit, put a
            // 384 T0 DC load in the middle of the stream and the reader's demod
            // could not recover a bitstream at all.
            if (pubmode == 2) {
                // Timed on the precision counter, not lf_wait_periods(): that one
                // counts ADC samples, and simulation runs the FPGA edge detect
                // path rather than the ADC path, so it is not a usable clock here.
                Gpio_SSC_DOUT_Low();
                const uint16_t t_pmc = GetPrecisionCounterRaw();
                while (GetPrecisionCounterDelta(t_pmc) < (HITAG2_T_PMC * T0)) { }
            }
        }

        Gpio_SSC_DOUT_Low();
        hitag_cleanup(ledcontrol);
        return;
    }

    while ((BUTTON_PRESS() == false) && (data_available() == false)) {

        uint32_t start_time = 0;
        size_t rxlen = 0, txlen = 0;

        d_loops++;
        WDT_HIT();

        // Leaving the field re-arms the threshold measurement.
        //
        // The reader going away ends the session, and is the moment to forget what
        // was learned from it: the next field may be a different reader at a
        // different distance, and the two readers here want different thresholds,
        // 20 and 32, so carrying the old decision across is wrong.  This is what
        // makes the normal way of using the simulator work - started away from any
        // reader and then presented to one - rather than only the desktop case
        // where it was already sitting on the reader when `sim` was typed.
        //
        // Silence is the field detector.  Watching the clock instead does not
        // work: this file used to assert that TIMESTAMP is carrier derived and
        // stops advancing when the field goes away, and that is simply untrue -
        // GetTimestamp() reads TC2 clocked from MCK/32 and only scales the result
        // into carrier periods, so it is free running wall time and never stalls.
        // A re-arm built on it can never fire, and measured, never did.
        //
        // A reader in range talks: a Paxton polls every 18875 T0, and a Proxmark
        // reader is bursty but never quiet for long.  So no frame at all for a
        // second means no reader, which needs no ADC and cannot disturb a receive.
        if ((threshold == 0) && thr_measured &&
                ((TIMESTAMP - last_rx_ts) > HITAG2_FIELD_GONE_T0)) {
            thr_measured = false;
            d_rearm_n++;
            last_rx_ts = TIMESTAMP;
        }



        // Receive a command from the reader
        // Hitag 2 counts the opening gap as the frame's first '1' bit

        hitag_tag_receive_frame_ex(rx, sizeof(rx), &rxlen, &start_time, ledcontrol, &overflow, true);
        if (rxlen > 0) { d_frames++; last_rx_ts = TIMESTAMP; }
        if (rxlen == 64) { d_auth64++; }
        if ((rxlen >= 56) && (rxlen <= 63)) { d_auth_short++; }
        if (rxlen == 5) { d_bits5++; }

        // Judge the frame that followed our answer, then go back to the settled
        // threshold for the next START_AUTH.
        if (post_active) {

            // A frame of an illegal length does not spend the post-answer window.
            //
            // Our own modulation tail comes back as a 1 or 2 bit frame a few T0
            // after we stop transmitting, and it used to arrive first, clear
            // post_active, and put the main threshold back - so the reader's real
            // command, which follows it, was judged outside the window that exists
            // precisely for it.  Traced against a Paxton:
            //
            //     Tag 32: 06 F9 07 C2   our answer, ends 8753
            //     Rdr  1: 00            9724   self-echo, spends the window
            //     Rdr  8: FE            9999   the READ PAGE, now mis-sliced
            //
            // The window belongs to the next real frame, so hold it open until one
            // arrives.  See the same reasoning at the dispatcher, which discards
            // these frames rather than letting them reset the session.
            const bool legal_len = (rxlen == 5) || (rxlen == 10) ||
                                   (rxlen == 32) || (rxlen == 64);
            if ((rxlen > 0) && (legal_len == false)) {
                goto post_hold;
            }

            post_active = false;
            d_post_eval++;
            if ((rxlen == 64) || (rxlen == 32) || (rxlen == 10)) {
                // A protocol length: this candidate works, hold it.
                //
                // 64 belongs here and its absence hid the whole problem.  A
                // Paxton reader answers our UID with a 64 bit crypto challenge,
                // and with only 32 and 10 accepted, a candidate that sliced that
                // challenge perfectly scored as a failure and was stepped away
                // from.
                //
                // Deliberately not also requiring ht2_intervals_sane() here.  It
                // was tried and measured worse - 7 of 10 authentications against
                // 9 - because so few candidates satisfy it on the recovering
                // envelope that the search never settles.  The strict check earns
                // its place on the short START_AUTH, where it is cheap to satisfy.
                post_bad = 0;
                post_locked = true;
            } else if (post_locked) {
                // Hold through the odd bad frame before giving up on a candidate
                // that has proved itself, so noise does not send it wandering.
                if (++post_bad > 2) {
                    post_bad = 0;
                    post_locked = false;
                }
            } else {
                // Still searching - walk the candidates.
                //
                // This used to be gated on the measurement block not having run.
                // That block no longer decides the threshold, so the gate only
                // switched the search off permanently.
                //
                // Stepping directionally instead was tried, on the theory that
                // hearing nothing means the step is too high to slice anything and
                // a wrong length means it is low enough to pick up noise.  It
                // measured worse, 5 of 12 against 10 of 15, and the reason is
                // instructive: hearing nothing after we answer is usually our own
                // post-transmission deafness, not the threshold, so the search
                // reads it as "go lower" and walks 32, 28, 24, 20, 16 chasing a
                // signal that is not there yet.
                post_idx = (post_idx + 1) % ARRAYLEN(post_cand);
                post_thr = post_cand[post_idx];
            }
            if (threshold == 0) {
                FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, active_threshold);
            }
post_hold:
            ;
        }

        // Reference for the T_wresp wait below.  TIMESTAMP is free running, so
        // unlike the precision counter it needs no reset - resetting that one
        // either spins inside the capture loop or stalls us on the stream of
        // one bit noise frames, and both cost us real reader bits.
        // The receive above returns once the line has been quiet for
        // HITAG_T_EOF periods, so that much of the wait is already spent.
        uint32_t rx_end = TIMESTAMP;

        // Always snapshot the very first frame with edges, answered or not, so a
        // reader we never reply to - the writer, while it cannot get past
        // START_AUTH - can still be seen at the interval level.
        if ((s_nsnap < SIMSNAP) && (snap_next == false) && (g_hitag_rx_iv_count > 0) && (rxlen >= 30) && (tag.state == TAG_STATE_WRITING)) {
            snap_next = true;
            snap_skipped = 0;
            last_tx_end = rx_end;
        }

        if (snap_next) {
            // The receive right after an answer covers only HITAG_T_EOF (80 T0)
            // of silence and returns empty - the reader does not start its next
            // command until ~276 T0.  Keep looking until a window actually sees
            // edges, or until the reader has plainly given up.
            bool got = (g_hitag_rx_iv_count > 0);
            bool expired = ((TIMESTAMP - last_tx_end) > 6000);
            if (got || expired) {
                snap_next = false;
                if (s_nsnap < SIMSNAP) {
                    s_rxl[s_nsnap] = (uint16_t)rxlen;
                    s_gap[s_nsnap] = (start_time != 0) ? (start_time - last_tx_end) : 0;
                    s_skip[s_nsnap] = snap_skipped;
                    uint32_t n = g_hitag_rx_iv_count;
                    if (n > ARRAYLEN(s_iv[0])) n = ARRAYLEN(s_iv[0]);
                    s_ivn[s_nsnap] = (uint8_t)n;
                    for (uint32_t k = 0; k < n; k++) {
                        s_iv[s_nsnap][k] = g_hitag_rx_iv[k];
                        s_it[s_nsnap][k] = g_hitag_rx_it[k];
                    }
                    s_nsnap++;
                }
            } else {
                snap_skipped++;
            }
        }

        if (tx_pending) {
            LogTraceBits(tx_pending_buf, tx_pending_len, tx_pending_start, tx_pending_end, false);
            tx_pending = false;
        }

        // Every captured frame goes through the stop/enable capture cycle below,
        // noise included: skipping it for short frames changes the capture
        // timing enough to misread the following reader bits.
        if (rxlen > 0) {

            LogTraceBits(rx, rxlen, start_time, TIMESTAMP, true);

            // Stop the capture while we answer.  Leaving it clocked was tried, on
            // the grounds that cycling it is slow, but our own modulation then
            // fills it: the reader's password frame came back as 7 bits holding
            // only its last byte (46 of BD F5 E8 46), because capture did not
            // recover until ~1150 T0 after our answer had finished.
            StopLoEdgeCapture();

            // Process the incoming frame (rx) and prepare the outgoing frame (tx)
            // Set the threshold from the reader's own modulation depth, once.
            //
            // The threshold is a slew rate discriminator - how many ADC counts the
            // envelope must move within 32 us to count as an edge - so the value
            // that works scales with how strongly this antenna is coupled to the
            // reader.  That is why no constant suits every rig: a Proxmark reader
            // a centimetre away wants about 32, a genuine Paxton reader about 20,
            // and the wrong one either truncates the reader's long commands or
            // chatters on ringing.
            //
            // Triggered by the first received frame, so the reader is known to be
            // talking - measuring at start up returns 3 counts of idle ripple.
            // Once only, and from reader traffic before this simulator has
            // answered anything, which is what makes it different from the
            // continuous version recorded as a failure in lf_edge_detect.v: that
            // one was normalising against a span our own load modulation drove.
            if ((slope != 0) && (threshold == 0) && (thr_measured == false)) {

                const uint32_t meas_t0 = TIMESTAMP;

                // Wait for the field, then measure - do not wait for a frame.
                //
                // Triggering on a decoded frame is circular: decoding one needs a
                // working threshold, which is the thing being measured.  Entering
                // the field is the event that actually matters and it needs no
                // decoding at all - the envelope simply goes from nothing to a
                // carrier, so a level well above the noise floor says the reader
                // is there and its traffic is about to arrive.

                // Measure the same quantity the detector measures.
                //
                // lf_edge_detect.v fires when |v[i] - v[i-32]| reaches the
                // threshold, so sample exactly that and take a high percentile of
                // it.  max - min was tried first and is too fragile: it is set by
                // single outlying samples, and back to back runs on an unchanged
                // rig measured spans of 124, 137, 157 and 158 - a 27% spread that
                // lands straight on the threshold.  A percentile cannot be moved
                // by one sample, and being in the detector's own units means the
                // number needs no interpretation.
                uint8_t ring[32] = {0};
                uint8_t rp = 0;
                uint16_t hist[64] = {0};
                uint32_t nsteps = 0, nbig = 0;

                FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | weak);

                // Field present?  An unpowered coil sits near zero; a reader's
                // carrier lifts the envelope a long way above that.  Give it a
                // bounded wait so a simulator started with no reader in front of
                // it still returns and runs.
                bool in_field = false;
                for (uint32_t i = 0; i < 100000; i++) {
                    uint32_t g = 20000;
                    while ((FPGA_SSC_RX_Ready() == false) && (--g)) { }
                    if (g == 0) {
                        break;
                    }
                    if ((uint8_t)FPGA_SSC_RX_Value() > 40) {
                        in_field = true;
                        break;
                    }
                }

                for (uint32_t i = 0; (i < 200000) && in_field; i++) {
                    uint32_t g = 20000;
                    while ((FPGA_SSC_RX_Ready() == false) && (--g)) { }
                    if (g == 0) {
                        break;
                    }
                    const uint8_t v = (uint8_t)FPGA_SSC_RX_Value();
                    const uint8_t old = ring[rp];
                    ring[rp] = v;
                    rp = (uint8_t)((rp + 1) & 31);

                    if (nsteps < 0xFFFFFFFF) {
                        const uint8_t step = (v > old) ? (uint8_t)(v - old) : (uint8_t)(old - v);
                        hist[step >> 2]++;
                        nsteps++;
                        if (step >= 60) {
                            nbig++;
                        }
                    }

                    // Keep going until the window actually contains the reader's
                    // gaps, not just however many samples.
                    //
                    // A fixed sample count measures whatever happened to be on the
                    // air.  Paxton polls every 151 ms, so a 40 ms window often
                    // catches nothing but idle ripple and the percentile then
                    // describes noise: measured on one rig, back to back runs gave
                    // spans of 252 and 144, and thresholds of 31 and 18 from the
                    // same coupling.  Counting the big steps instead means the
                    // measurement ends when it has seen enough real modulation to
                    // describe, whenever that is.
                    if ((nbig >= 300) || (nsteps >= 190000)) {
                        break;
                    }
                }

                FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | weak | sensitive | slope);

                // Walk the histogram down from the largest bin, recording the
                // step size at each percentile on the way.  The single number the
                // threshold is derived from is not enough to understand a rig:
                // two rigs wanting 20 and 32 differ in the SHAPE of this
                // distribution, not just its tail, so keep the shape and report
                // it.  Ripple and noise fill the bins near zero, the reader's gap
                // transitions form the tail.
                // Clear the percentiles before every walk.
                //
                // They are latched with "if still zero", which was safe only while
                // this block ran exactly once per simulation.  Now that a failed
                // attempt leaves thr_measured clear so the next field entry can
                // retry, stale values survive into the next walk, big is never
                // assigned, and span comes out 0 - which fails the validity check
                // below, which schedules another retry, forever.  One attempt made
                // outside a field poisoned every attempt after it: measured, the
                // threshold stayed at its 32 default with measured=0 on a rig that
                // had reported span=176 a moment earlier.
                d_p50 = 0;
                d_p90 = 0;
                d_p99 = 0;
                d_pmax = 0;

                uint32_t acc = 0;
                uint8_t big = 0;
                for (int b = 63; b >= 0; b--) {
                    acc += hist[b];
                    const uint8_t sz = (uint8_t)(b << 2);
                    if ((d_p50 == 0) && (acc >= (nsteps / 2)))  d_p50 = sz;
                    if ((d_p90 == 0) && (acc >= (nsteps / 10))) d_p90 = sz;
                    if ((d_p99 == 0) && (acc >= (nsteps / 100))) {
                        d_p99 = sz;
                        big = sz;
                    }
                    if ((d_pmax == 0) && (hist[b] > 0)) d_pmax = sz;
                }
                d_nsteps = nsteps;
                d_nbig = nbig;

                const uint8_t span = big;
                d_span = span;

                // Only accept a measurement taken in a reader's field.
                //
                // This used to be latched at the top of the block, unconditionally
                // and once per run, which made the whole decision depend on where
                // the Proxmark happened to be when `sim` was typed.  Started on a
                // reader, as in a desktop test, it measured properly; started away
                // from the field, which is the normal way to use it, there was
                // nothing to measure, and it locked a threshold chosen from an
                // empty window and never looked again - so presenting the tag to
                // the reader afterwards ran on a decision made before the reader
                // existed.  Identical firmware then passes or fails depending on
                // the order of two physical actions, which is exactly the
                // irreproducibility this cost a long time chasing.
                if ((in_field == false) || (span == 0)) {
                    // Nothing to learn from.  Leave thr_measured clear so entering
                    // a field re-runs this.
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | weak | sensitive | slope);
                    FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, active_threshold);
                    goto meas_done;
                }
                thr_measured = true;
                d_meas_n++;
                d_meas = TIMESTAMP - meas_t0;

                // Only trust a measurement with a real modulation step in it.  If
                // the tail is small there was nothing but ripple in the window, so
                // leave thr_locked clear and let the candidate sweep below do the
                // work instead of acting on a number that means nothing.
                // The measurement no longer picks the threshold, only the order
                // the two candidates are tried in.
                //
                // It used to set it outright, as span/4 clamped to 14..40.  That
                // is measurably wrong.  The estimator itself is reproducible -
                // three runs against a genuine Paxton reader gave a 99th
                // percentile of 180, 184 and 168 - but forcing each candidate by
                // hand on that same rig shows what those numbers should have
                // produced:
                //
                //     -t 20   188 frames   110 START_AUTH    94 answers
                //     -t 26   108 frames    95 START_AUTH    95 answers
                //     -t 32    94 frames    94 START_AUTH    94 answers
                //     -t 40   194 frames     0 START_AUTH     0 answers
                //
                // 32 is exactly right, and 40 does not decode a single command -
                // yet span/4 turns 180 into 45 and the clamp lands it on 40.  No
                // divisor fitted on one rig can be trusted to choose between 20
                // and 32 when the statistic it reads barely moves between them,
                // 168..184, and the outcome swings from perfect to dead.
                //
                // The frame lengths do separate them, cleanly: at 32 every frame
                // that arrives has a legal length, at 20 four in ten are noise,
                // and at 40 nothing decodes at all.  So the candidate sweep below
                // decides, and the modulation depth is used only to guess which of
                // the two to try first - a wrong guess costs one scoring window,
                // not the run.
                //
                // Ordering the candidates by coupling strength was tried here and
                // removed.  The idea was that a weakly coupled rig wants 20 and a
                // strongly coupled one 32, with the sweep left to correct a wrong
                // guess.  Measured on both rigs available, 20 is not the answer to
                // either:
                //
                //     rig            span    -t 20              -t 32
                //     pm3 - paxton    172    59% legal frames   100% legal frames
                //     pm3 - pm3       224    0 of 8 pages       8 of 8 pages
                //
                // Both measure well above any boundary that would have selected
                // the weak branch, so it was never once taken, and a boundary
                // fitted on no weak samples at all is a guess wearing a constant's
                // clothing.  32 is the only value measured to work anywhere, so it
                // is simply tried first; 20 stays in the list for a rig neither of
                // these represents, and the sweep will find it in one window.
                //
                // span is left measured because it is worth seeing in the log, but
                // nothing is decided from it.
                // Two rigs, two values, one number to tell them apart.
                //
                // The modulation depth does separate the rigs - it just had to be
                // read against the right objective.  Scored on how cleanly the
                // reader's polls decode, a Paxton rig looks like it wants 32; but
                // decoding polls is not the job, and against reader ACCEPTANCE it
                // wants 20, which is where the earlier fit went wrong.
                //
                // 44 measurements, all runs on both rigs:
                //
                //     rig A  <pm3 - paxton>   112, 168..196 (14 samples), one 216
                //     rig B  <pm3 - pm3>      one 216, 224..240 (28 samples)
                //
                // A boundary at 210 places 42 of the 44 correctly; the two 216
                // samples, one from each rig, are the only crossings.  Everything
                // else clears it by 14 counts or more.
                //
                // Decide once, here, and hold.  No sweep: a sweep costs the reader
                // a scoring window per candidate, and the reader is not waiting -
                // measured, a six candidate post-answer sweep spent 23 seconds
                // before its first complete transaction and two 40 second runs
                // never decoded a single command.  This is a comparison, and it is
                // finished before the reader's second poll.
                active_threshold = (span >= HITAG2_SPAN_STRONG) ? 32 : 20;
                thr_locked = true;
                thr_best_idx = (active_threshold == 32) ? 0 : 1;
                thr_idx = thr_best_idx;

                // The post-answer window follows it.  That search existed because
                // the main threshold was a guess; with the sweep judging real
                // framing there is nothing left for it to discover, and left
                // running it never settles - measured, 3810 candidate steps in a
                // single run, every one reprogramming the FPGA mid-receive.
                post_thr = active_threshold;
                post_locked = true;

                FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, active_threshold);
meas_done:
                ;
            }

            hitag2_handle_reader_command(rx, rxlen, tx, &txlen);

            // Adaptive threshold: score each candidate on whether the reader's
            // commands can actually be ACTED ON, then keep the best.
            //
            // Judging on frame length alone is not enough.  A Hitag 2 reader frame
            // is 5, 10, 32 or 64 bits, and it is tempting to score on that - but a
            // slightly wrong threshold produces frames of plausible length and
            // wrong content, which scores perfectly and still fails: measured on
            // two Proxmarks, length scoring locked at 24 with a flawless window
            // and managed 1 read of 3, where 32 does 3 of 3.
            //
            // Answering is the stronger signal because it is semantic.  We only
            // answer a 32 bit password if it matched page 1, and a 10 bit command
            // if its address survived the datasheet's inverted-address check, so
            // an answer to anything longer than a START_AUTH means the frame
            // arrived intact.  START_AUTH itself is excluded: five bits decode at
            // almost any threshold and answering one proves nothing, which is
            // exactly how the original lock-on-START_AUTH search settled on a
            // value far too coarse for everything else.
            //
            // Tuning runs once per simulation, at the start of the conversation:
            // thr_locked is never cleared again, so a threshold that has proved
            // itself is not re-judged while the reader is mid exchange.
            if ((slope != 0) && (threshold == 0) && (thr_locked == false) && (rxlen > 5)) {

                // Score on whether the frame could be ACTED ON, not on its length.
                //
                // Length purity was tried here and is wrong for a short exchange.
                // It reads well in bulk - against a Paxton reader polling for
                // twenty seconds, 100% of frames are a legal length at 32, 59% at
                // 20 and 0% at 40 - but `lf hitag read` is one brief burst, and
                // scoring every arrival means a single noise frame inside the
                // eight frame window moves the sweep off a threshold that was
                // working, in the middle of the read.  Measured on two Proxmarks:
                // 8 of 8 pages became 0 of 8, three runs in a row, with the sweep
                // ending on 20 every time.
                //
                // Answering is the stronger signal because it is semantic, and it
                // separates the two rigs where length does not.  With a Proxmark
                // reader at -t 20, 94 START_AUTH frames decode and not one command
                // is ever answered - perfectly legal lengths, nothing behind them:
                //
                //     -t 20   121 frames   94 START_AUTH    0 answers   0 of 8 pages
                //     -t 32    18 frames    1 START_AUTH   10 answers   8 of 8 pages
                //
                // We answer a 32 bit password only if it matched page 1, and a 10
                // bit command only if its address survived the datasheet's
                // inverted-address check, so an answer means the frame arrived
                // intact.  START_AUTH is excluded from the window for the reason
                // it always was: five bits decode almost anywhere, and we answer
                // only every second one by design, so counting them would score a
                // flawless poll train at half marks.
                const bool legal = (rxlen == 10) || (rxlen == 32) || (rxlen == 64);

                thr_seen++;
                if (legal && (txlen > 0)) {
                    thr_hit++;
                }

                if (thr_seen >= HITAG2_THR_WINDOW) {

                    if (thr_hit >= thr_best_hit) {
                        thr_best_hit = thr_hit;
                        thr_best_idx = thr_idx;
                    }

                    if (thr_hit == thr_seen) {
                        // every command acted on - nothing better to find
                        thr_locked = true;
                    } else {
                        thr_idx++;
                        if (thr_idx >= ARRAYLEN(thr_cand)) {
                            // swept the list, settle on the best it saw
                            thr_idx = thr_best_idx;
                            thr_locked = true;
                        }
                        active_threshold = thr_cand[thr_idx];
                        FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, active_threshold);
                    }

                    thr_seen = 0;
                    thr_hit = 0;
                }
            }

            if (listen_only) {
                txlen = 0;

                // Listening to a genuine tag: capture the envelope across the
                // window where its answer falls, so its modulation shape can be
                // compared with ours.  t_WAIT1 is ~200 T0 after the command, and
                // the answer runs 1184 T0, so start straight away and let the
                // 1536 T0 capture cover it.
                d_listen5++;
                if (((flags & 8) != 0) && (rxlen == 5) && (s_adc_valid == false)) {
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | weak);
                    for (uint32_t i = 0; i < ADCSNAP; i++) {
                        uint8_t mn = 255, mx = 0;
                        for (uint32_t k = 0; k < 16; k++) {
                            uint32_t g = 20000;
                            while ((FPGA_SSC_RX_Ready() == false) && (--g)) { }
                            uint8_t v = (uint8_t)FPGA_SSC_RX_Value();
                            if (v < mn) mn = v;
                            if (v > mx) mx = v;
                        }
                        s_adc_mn[i] = mn;
                        s_adc_mx[i] = mx;
                    }
                    s_adc_valid = true;
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | weak | sensitive | slope);
                    if (active_threshold != 127) {
                        FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, active_threshold);
                    }
                }
            }

            // Wait T_wresp carrier periods after the last reader bit.  The counter
            // runs from the rising edge while T_wait1 is specified from the falling
            // edge, so wait (T_WAIT_1 - T_LOW) periods.  All values are in T0 units.
            // Send and store the tag answer (if there is any).  A Hitag 2 tag
            // answers Manchester at 4 kbit/s behind a five bit start-of-frame.
            if (txlen > 0) {

                // Answer T_wresp after the reader's last bit, not immediately.
                // Only on frames we actually answer: waiting on the noise frames
                // leaves the receiver blind and drops the next reader command.
                // TIMESTAMP counts carrier periods.  rx_end was taken once the
                // receiver gave up, which is HITAG_T_EOF periods after the
                // reader's last bit, so only the remainder is waited here.
                // Aim for the middle of the 199..206 window rather than its edge.
                // rx_end was taken once the receiver gave up, HITAG_T_EOF periods
                // after the reader's last edge, so only the remainder is waited.
                // There is no send lead-in any more, the frame starts immediately.
                // bounded: TIMESTAMP is derived from the carrier, so it stops
                // advancing the moment the reader's field goes away.  An
                // unbounded spin here wedges the device with no way back.
                uint32_t guard = 200000;
                while ((TIMESTAMP - rx_end) < (uint32_t)(s_t_wait_resp - HITAG_T_EOF)) {
                    WDT_HIT();
                    if (--guard == 0) {
                        break;
                    }
                }

                start_time = TIMESTAMP;
                if (s_nsnap < SIMSNAP) {
                    s_wait[s_nsnap] = start_time - rx_end;
                }
                // Clock the answer off the reader's carrier, not our timer
hitag_tag_send_frame_mc4k_sync(tx, txlen, sof_bits, ledcontrol);

                last_tx_end = TIMESTAMP;
                if (s_nsnap < SIMSNAP) {
                    s_txdur[s_nsnap] = last_tx_end - start_time;
                }
                snap_next = true;
                snap_skipped = 0;

                // TEMP DIAGNOSTIC (flags bit3): what does the envelope actually
                // do while we are deaf?
                //
                // The edge detect mode gives us edges or nothing, and after our
                // own answer it gives nothing for about 1200 T0 - but that says
                // nothing about whether the signal is missing or the detector is
                // asleep.  Switching to raw ADC streaming for that window shows
                // the envelope itself: min and max over each group of samples, so
                // both the level and the reader's modulation depth are visible.
                // It costs the window we are blind in anyway.
                if ((flags & 8) != 0) {
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | weak);
                    for (uint32_t i = 0; i < ADCSNAP; i++) {
                        uint8_t mn = 255, mx = 0;
                        for (uint32_t k = 0; k < 16; k++) {
                            uint32_t g = 20000;
                            while ((FPGA_SSC_RX_Ready() == false) && (--g)) { }
                            uint8_t v = (uint8_t)FPGA_SSC_RX_Value();
                            if (v < mn) mn = v;
                            if (v > mx) mx = v;
                        }
                        s_adc_mn[i] = mn;
                        s_adc_mx[i] = mx;
                    }
                    s_adc_valid = true;
                }

                FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | weak | sensitive | slope);
                if (active_threshold != 127) {
                    FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, active_threshold);
                }


                if ((slope != 0) && (threshold == 0)) {
                    FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, post_thr);
                    post_active = true;
                }

                // Let our own coil release pass before arming the detector.
                //
                // Re-arming at once makes the detector's first event our own
                // modulation ending, which is why every answer used to be
                // followed in the trace by a spurious one bit frame beginning
                // 2 T0 after it:
                //
                //     3896513 | 3897731 | Tag |32: 06 F9 07 C2   our answer
                //     3897733 | 3897815 | Rdr | 1: 00            2 T0 later
                //     3897919 | 3898223 | Rdr |10: E0 C0         the real command
                //
                // One edge, then HITAG_T_EOF of quiet closes it as a frame.  It
                // was harmless - discarded at the dispatcher, held out of the
                // post-answer window - but it is not a reader frame, and the
                // honest fix is to not manufacture it rather than to filter it
                // out of the trace afterwards.
                //
                // t_WAIT2 (HT2 datasheet 3.5) guarantees the reader cannot begin
                // its next command until 90 T0 after our answer ends, so blanking
                // a short window costs nothing real.  The release transient is
                // over within a few T0 - the slope detector compares across 32 us,
                // which is 4 T0 - so this has wide margin at both ends.
                // Bounded, like every other wait in this file.  An unbounded
                // spin here wedged the device hard enough to need a reflash: if
                // the timestamp is not advancing at this point the condition
                // never clears, and there is no WDT_HIT() inside to save it.
                uint32_t tail_spin = 20000;
                while (((TIMESTAMP - last_tx_end) < HITAG2_TX_TAIL_GUARD) && (--tail_spin)) { }

                // Back to listening: the reader may start its next frame only
                // t_WAIT2 (90 T0) after our answer ends.
                //
                // TEMP DIAGNOSTIC (flags bit6): EnableLoEdgeCapture() only sets
                // CLKEN|SWTRG.  StartLoEdgeCapture() additionally re-routes
                // SSC_FRAME to the timer input and rewrites TC_CMR, so if the
                // answer disturbed any of that, only the full form restores it.
                if ((flags & 64) != 0) {
                    StartLoEdgeCapture();
                } else {
                    EnableLoEdgeCapture();
                }

                // Throw away the edge event latched while we were transmitting.
                //
                // Our own answer, and the FPGA's idle re-arm that follows it, both
                // leave an edge flag set in TC_SR.  Re-enabling capture does not
                // clear it, so the first thing the receive loop sees is that stale
                // event - reported as a 1 bit frame whose 80 T0 EOF timeout then
                // runs past the reader's next command.
                //
                // It is not an analogue artefact at a fixed time: it tracks the
                // blanking window exactly.  With HITAG2_TX_TAIL_GUARD at 32 it was
                // traced 48 T0 after our answer, and at 84 it moved to 1 T0 after -
                // always immediately on re-enable.  Widening the guard therefore
                // cannot remove it; reading the status once does, and costs
                // nothing.
                (void)GetLoEdgeCaptureStatus();

                if (s_nsnap < SIMSNAP) {
                    s_rearm[s_nsnap] = TIMESTAMP - last_tx_end;
                }

                // The reader starts its next frame only ~276 T0 after our answer
                // ends (measured: it opens 1582 T0 after the START_AUTH it just
                // sent).  Anything done here is done deaf, and edges that arrive
                // meanwhile only latch the most recent one, so the start of the
                // reader's frame is lost.  Defer our own trace write until after
                // the next receive has returned.
                tx_pending = true;
                tx_pending_len = txlen;
                tx_pending_start = start_time;
                tx_pending_end = TIMESTAMP;
                memcpy(tx_pending_buf, tx, (txlen + 7) / 8);
                d_answers++;
                if (rxlen == 32) { d_pwd_ok++; }
                if (rxlen == 10) { d_read_ok++; }

            } else {
                EnableLoEdgeCapture();
            }

            memset(rx, 0x00, sizeof(rx));

            if (ledcontrol) LED_B_OFF();
        }

        // Carry the timer overflow, it is 0 whenever a frame was received
        overflow += (GetLoEdgeCaptureCount() / T0);
        ResetLoEdgeCapture();
    }

    DBG Dbprintf("LISTEN blocks=%u adc_valid=%u flags=%u", d_listen5, s_adc_valid, flags);

    if (s_adc_valid) {
        DBG for (uint32_t k = 0; k < ADCSNAP; k += 8) {
            Dbprintf("  env[%u] %u-%u %u-%u %u-%u %u-%u %u-%u %u-%u %u-%u %u-%u",
                     k * 16,
                     s_adc_mn[k],     s_adc_mx[k],     s_adc_mn[k + 1], s_adc_mx[k + 1],
                     s_adc_mn[k + 2], s_adc_mx[k + 2], s_adc_mn[k + 3], s_adc_mx[k + 3],
                     s_adc_mn[k + 4], s_adc_mx[k + 4], s_adc_mn[k + 5], s_adc_mx[k + 5],
                     s_adc_mn[k + 6], s_adc_mx[k + 6], s_adc_mn[k + 7], s_adc_mx[k + 7]);
        }
    }

    DBG for (uint8_t i = 0; i < s_nsnap; i++) {
        Dbprintf("SNAP%u wait=%u txdur=%u rearm=%u gap=%u rxlen=%u edges=%u skip=%u clk300=%u",
                 i, s_wait[i], s_txdur[i], s_rearm[i], s_gap[i], s_rxl[i], s_ivn[i], s_skip[i], s_clk[i]);
        // The first two exchanges: the START_AUTH the threshold locked on, and the
        // password that follows.  More than that overruns the print path.
        for (uint8_t k = 0; k < s_ivn[i] && k < 12; k += 4) {
            uint16_t v[4] = {0}, w[4] = {0};
            for (uint8_t j = 0; j < 4 && (k + j) < s_ivn[i]; j++) {
                v[j] = s_iv[i][k + j];
                w[j] = s_it[i][k + j];
            }
            Dbprintf("  T0/polls [%u] %u/%u %u/%u %u/%u %u/%u",
                     k, v[0], w[0], v[1], w[1], v[2], w[2], v[3], w[3]);
        }
    }

    DBG Dbprintf("TXSTAT frames=%u samples=%u bails=%u (a full answer = 1184 samples)",
                 (unsigned)g_tx_frames, (unsigned)g_tx_samples, (unsigned)g_tx_bails);
    // The step distribution goes in THRSTAT rather than a line of its own.
    //
    // Adding further Dbprintf calls to this burst loses them: two extra lines here
    // never appeared at all while the ones either side of them printed every time,
    // on a device confirmed to be running the build that contained them.  Six
    // arguments in an existing line is what reliably gets through.
    //
    // p50 is the idle carrier, p90 the ripple shoulder, p99 the reader's gap
    // transitions.  The threshold has to sit between the shoulder and the tail, so
    // it is their separation that matters, not any one of them.
    DBG Dbprintf("THRSTAT thr=%u p50=%u p90=%u p99=%u max=%u n=%u",
             active_threshold, d_p50, d_p90, d_p99, d_pmax, d_nsteps);
    DBG Dbprintf("THRSTAT2 span=%u big=%u locked=%u post=%u",
             d_span, d_nbig, thr_locked, post_thr);
    DBG Dbprintf("THRSTAT3 settle_t0=%u measured=%u rearmed=%u", d_meas, d_meas_n, d_rearm_n);
    DBG Dbprintf("POSTSTAT evaluated=%u", d_post_eval);
    DBG Dbprintf("SIMSTAT loops=%u edges=%u frames=%u start_auth=%u answers=%u tracelen=%u",
             d_loops, (unsigned)g_hitag_edges, d_frames, d_bits5, d_answers,
             (unsigned)BigBuf_get_traceLen());
    DBG Dbprintf("SIMSTAT2 auth64=%u authshort=%u pwd_ok=%u read_ok=%u",
             d_auth64, d_auth_short, d_pwd_ok, d_read_ok);


    hitag_cleanup(ledcontrol);

    // release BigBuf, but keep emulator memory for eview / esave
    BigBuf_free_keep_EM();

    DbpString("Sim stopped");

//    reply_ng(CMD_LF_HITAG_SIMULATE, (checked == -1) ? PM3_EOPABORTED : PM3_SUCCESS, (uint8_t *)tag.sectors, tag_size);
}

static bool ht2_receive(uint32_t *resp_start, uint32_t *resp_duration, uint8_t *nrz_samples, size_t *samples);

// TEMP INSTRUMENT: the half-bit period counts ht2_receive() measured for the most
// recent answer.  A tag half bit is 16 carrier periods and two of them 32, and the
// classifier splits at 24 - so the actual values are the only way to tell a
// misclassified gap from a genuinely missing edge.
static uint8_t g_ht2_per[16];
static uint32_t g_ht2_per_n;
static void ht2_normalise_head(uint8_t *nrz_samples, size_t *nrzs);

void ReaderHitag(const lf_hitag_data_t *payload, bool ledcontrol) {
    uint32_t d_norx = 0, d_nodec = 0;
    uint16_t d_lastn = 0;

    uint32_t command_start = 0, command_duration = 0;
    uint32_t response_start = 0, response_duration = 0;

    uint8_t rx[HITAG_FRAME_LEN] = {0};
    size_t rxlen = 0;
    uint8_t txbuf[HITAG_FRAME_LEN] = {0};
    uint8_t *tx = txbuf;
    size_t txlen = 0;

    int t_wait_1 = 204;
    int t_wait_1_guard = 8;
    int t_wait_2 = 128;
    size_t tag_size = 48;
    bool bStop = false;


    // Reset the return status
    bSuccessful = false;
    bCrypto = false;

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    // Check configuration
    switch (payload->cmd) {
        case HT1F_PLAIN: {
            DBG Dbprintf("Read public blocks in plain mode");
            // this part will be unreadable
            memset(tag.sectors + 2, 0x0, 30);
            blocknr = 0;
            break;
        }
        case HT1F_AUTHENTICATE: {
            DBG Dbprintf("Read all blocks in authed mode");

            memcpy(nonce, payload->nonce, 4);
            memcpy(key, payload->key, 4);
            memcpy(logdata_0, payload->logdata_0, 4);
            memcpy(logdata_1, payload->logdata_1, 4);

            // TEST
            memset(nonce, 0x0, 4);
            memset(logdata_1, 0x00, 4);

            byte_value = 0;
            key_no = payload->key_no;

            DBG Dbprintf("Authenticating using key #%u :", key_no);
            DBG Dbhexdump(4, key, false);
            DBG DbpString("Nonce:");
            DBG Dbhexdump(4, nonce, false);
            DBG DbpString("Logdata_0:");
            DBG Dbhexdump(4, logdata_0, false);
            DBG DbpString("Logdata_1:");
            DBG Dbhexdump(4, logdata_1, false);
            blocknr = 0;
            break;
        }
        case HT2F_PASSWORD: {
            DBG Dbprintf("List identifier in password mode");
            if (memcmp(payload->pwd, "\x00\x00\x00\x00", 4) == 0) {
                memcpy(password, tag.sectors[1], sizeof(password));
            } else {
                memcpy(password, payload->pwd, sizeof(password));
            }
            blocknr = 0;
            bPwd = false;
            bAuthenticating = false;
            pwd_retries = 0;
            crypto_retries = 0;
            break;
        }
        case HT2F_AUTHENTICATE: {
            DBG DbpString("Authenticating using NrAr pair:");
            memcpy(NrAr, payload->NrAr, 8);
            DBG Dbhexdump(8, NrAr, false);
            // We can't read block 0, 1, 2..
            blocknr = 3;
            bCrypto = false;
            bPwd = false;
            bAuthenticating = false;
            break;
        }
        case HT2F_CRYPTO: {
            DBG DbpString("Authenticating using key:");
            memcpy(key, payload->key, 6);  //HACK; 4 or 6??  I read both in the code.
            DBG Dbhexdump(6, key, false);
            DBG DbpString("Nonce:");
            DBG Dbhexdump(4, nonce, false);
            memcpy(nonce, payload->data, 4);
            blocknr = 0;
            bCrypto = false;
            bAuthenticating = false;
            crypto_retries = 0;
            break;
        }
        case HT2F_TEST_AUTH_ATTEMPTS: {
            DBG Dbprintf("Testing " _YELLOW_("%d") " authentication attempts", (auth_table_len / 8));
            auth_table_pos = 0;
            memcpy(NrAr, auth_table, 8);
            bCrypto = false;
            break;
        }
        default: {
            DBG Dbprintf("Error, unknown function: " _RED_("%d"), payload->cmd);
            set_tracing(false);
            reply_ng(CMD_LF_HITAG_READER, PM3_ESOFT, NULL, 0);
            return;
        }
    }

    if (ledcontrol) LED_D_ON();

    // hitag 2 state machine?
    hitag2_init();

    // Tag specific configuration settings (sof, timings, etc.)
// TODO HTS
    /*  if (payload->cmd <= HTS_LAST_CMD) {
            // hitag S settings
            t_wait_1 = 204;
            t_wait_2 = 128;
            flipped_bit = 0;
            tag_size = 8;
            DBG DbpString("Configured for " _YELLOW_("Hitag S") " reader");
        } else */
    if (payload->cmd <= HT1_LAST_CMD) {
        // hitag 1 settings
        t_wait_1 = 204;
        t_wait_2 = 128;
        tag_size = 256;
        DBG DbpString("Configured for " _YELLOW_("Hitag 1") " reader");
    } else if (payload->cmd <= HT2_LAST_CMD) {
        // hitag 2 settings
        t_wait_1 = HITAG_T_WAIT_1_MIN;

        // t_WAIT2 is a minimum (HT2 datasheet 3.5, "at least 90"), so a reader may
        // take longer and a real tag does not care.  Take longer.
        //
        // Measured against a Proxmark simulating a tag: its answer disturbs its own
        // LF front end, and the envelope is still recovering ~580 T0 later when the
        // next command would arrive.  A 10 bit READ PAGE rides through that intact,
        // but a 32 bit password spans ~830 T0 of the recovery ramp and loses an
        // edge partway along - 30 or 31 bits of 32, every time.  Waiting until the
        // envelope has settled costs ~9 ms per exchange against a genuine tag and
        // makes the difference between an exchange that completes and one that
        // cannot.
        t_wait_2 = 1200;
        tag_size = 48;
        DBG DbpString("Configured for " _YELLOW_("Hitag 2") " reader");
    }

    // init as reader
    lf_init(LF_ADC_READER, LF_ADC_WAV_REVERSED, ledcontrol);

    // The timestamp counter has to be running before anything reads TIMESTAMP.
    // Only the sniffer and the simulator ever started it, so in the reader every
    // TIMESTAMP was whatever TC2 happened to hold: response_start, and the frame
    // timestamps handed to LogTraceBits, were meaningless - which is why the
    // reader's own `lf hitag list` came out as rows of 0 | 65535 and
    // 4294967235 | 65474, with none of its own frames placed against them.
    StartTimestamp();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    size_t max_nrzs = (8 * HITAG_FRAME_LEN + 5) * 2; // up to 2 nrzs per bit
    uint8_t nrz_samples[max_nrzs];
    bool turn_on = true;
    size_t nrzs = 0;
    int16_t checked = 0;
    uint32_t signal_size = 10000;

    while (bStop == false && BUTTON_PRESS() == false) {

        // use malloc
        initSampleBufferEx(&signal_size, true);

        WDT_HIT();

        // Poll USB every pass.
        //
        // This used to fire only every 4000th iteration, to save time while
        // collecting samples.  One iteration here is a whole exchange - wait,
        // transmit a frame, wait, receive the answer - so 4000 of them is about a
        // minute during which the Proxmark answers nothing at all: a client that
        // gives up and sends CMD_BREAK_LOOP is not heard, `hw ping` from a second
        // client times out, and the device looks wedged until it comes back on its
        // own.  data_available() is a cheap status read next to an LF exchange.
        if (data_available()) {
            checked = -1;
            break;
        }

        // By default reset the transmission buffer
        tx = txbuf;
        switch (payload->cmd) {
            case HT1F_PLAIN: {
                bStop = !hitag1_plain(rx, rxlen, tx, &txlen, false);
                break;
            }
            case HT1F_AUTHENTICATE: {
                bStop = !hitag1_authenticate(rx, rxlen, tx, &txlen);
                break;
            }
            case HT2F_PASSWORD: {
                bStop = !hitag2_password(rx, rxlen, tx, &txlen, false);
                break;
            }
            case HT2F_AUTHENTICATE: {
                bStop = !hitag2_authenticate(rx, rxlen, tx, &txlen, false);
                break;
            }
            case HT2F_CRYPTO: {
                bStop = !hitag2_crypto(rx, rxlen, tx, &txlen, false);
                break;
            }
            case HT2F_TEST_AUTH_ATTEMPTS: {
                bStop = !hitag2_test_auth_attempts(rx, rxlen, tx, &txlen);
                break;
            }
            default: {
                DBG Dbprintf("Error, unknown function: " _RED_("%d"), payload->cmd);
                goto out;
            }
        }

        if (bStop) {
            break;
        }

        if (turn_on) {
            // Wait 50ms with field off to be sure the transponder gets reset
            SpinDelay(50);
            FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
            turn_on = false;
            // Wait with field on to be in "Wait for START_AUTH" timeframe
            lf_wait_periods(HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4);
            command_start += HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4;
        } else {
            // Wait for t_wait_2 carrier periods after the last tag bit before transmitting,
            lf_wait_periods(t_wait_2);
            command_start += t_wait_2;
        }

        // Transmit the reader frame
        command_duration = hitag2_reader_send_frame(tx, txlen);
        response_start = command_start + command_duration;

        // Let the antenna and ADC values settle
        // And find the position where edge sampling should start.
        //
        // Refresh the ADC reference before listening.
        //
        // lf_count_edge_periods() slices at adc_avg +/- 20, and that average is
        // taken once in lf_init() and never renewed - so by the time we listen for
        // an answer to a 32 bit command, the reference predates both the field
        // settling and our own 890 T0 transmission.  That is the reader side twin
        // of the simulator's post-transmission deafness, and it is why the tag's
        // first answer decodes and its second one does not.
        //
        // lf_sample_mean() consumes exactly 32 carrier periods, so take them out of
        // the wait rather than adding to it and leave the turnaround unchanged.
        //
        // Take it at the END of the wait, not the start.  Both orders cost the
        // same 32 periods and leave the turnaround identical, but the reference
        // has to describe the envelope the answer will actually ride on.  Sampled
        // first, it is taken ~170 T0 earlier, while the field is still recovering
        // from our own transmission, and the +/- 20 slicing band then sits below
        // the settled level - which is where the missed edges come from.
        // Measured symptom: the merges cluster in the first few intervals of the
        // answer, 16 15 17 15 17 30 18 ..., and the frame lands on 35 bits.
        lf_wait_periods(t_wait_1 - t_wait_1_guard - 32);
        lf_sample_mean();

        // Start listening from a known modulation state.
        //
        // ht2_receive() opens with lf_get_tag_modulation(), which reports whatever
        // `rising_edge` was left at - and nothing reset it, so after our own
        // transmission it reflects the last edge of *that*, not the tag's answer.
        // When it comes out 0 the receive concludes it missed the first period and
        // synthesises a leading sample, which shifts every Manchester pair after
        // it.  Measured against a simulator: its answer arrived as 76 samples of
        // 1,0,1,1,0,1,0,1... where the genuine fob gives 1,0,1,0,1,0,1,0... - the
        // same stream with one sample inserted - so the SOF check failed and the
        // whole read was abandoned.  It happens after a 32 bit command and not
        // after a 5 bit one, which is why the UID reads and the password does not.
        lf_reset_counter();

        response_start += t_wait_1 - t_wait_1_guard;

        // Receive the tag's answer through the shared implementation.
        //
        // This used to be a second, near duplicate copy of the receive loop, and
        // the two drifted: fixes that made `lf hitag reader` reliable never
        // reached this path, so a dump would decode the UID only occasionally and
        // otherwise stop dead - the reader's own trace showed its START_AUTH and
        // nothing else, never reaching the password.  One implementation, one set
        // of fixes.
        if (ht2_receive(&response_start, &response_duration, nrz_samples, &nrzs) == false) {
            DBG DbpString("No tag answer");
            d_norx++;
            // Report it as no answer.  rxlen otherwise still holds the length of
            // the *previous* frame, so the state machine is handed a stale 32 and
            // walks on as though the tag had replied.
            rxlen = 0;
            continue;
        }

        ht2_normalise_head((uint8_t *)nrz_samples, &nrzs);


        // decode bitstream
        manrawdecode((uint8_t *)nrz_samples, &nrzs, true, 0);

        // decode frame
        //
        // Shared with the UID path rather than repeated here.  This used to demand
        // exactly five leading ones and pack from a fixed offset of five, which
        // breaks whenever the head of the answer is disturbed - and it routinely
        // is, since the first half bit can be lost on an idle line and a receiver
        // that synthesises a replacement shifts every pair after it.  The result
        // was a payload short by one bit and shifted left: a tag answering
        // CE129911 decoded as 9C253222.

        if (ht2_packbits(nrz_samples, nrzs, rx, &rxlen) == false) {
            DBG Dbprintf("Could not decode the tag answer, %u samples", (unsigned)nrzs);
            d_nodec++;
            d_lastn = (uint16_t)nrzs;
            if (d_nodec == 1) {
                DBG for (uint32_t k = 0; (k + 9) < g_ht2_per_n; k += 10) {
                    Dbprintf("PER[%2u] %3u %3u %3u %3u %3u %3u %3u %3u %3u %3u", k,
                             g_ht2_per[k], g_ht2_per[k+1], g_ht2_per[k+2], g_ht2_per[k+3], g_ht2_per[k+4],
                             g_ht2_per[k+5], g_ht2_per[k+6], g_ht2_per[k+7], g_ht2_per[k+8], g_ht2_per[k+9]);
                }
            }
            // One frame we could not decode is not the end of the exchange.
            // Breaking out abandoned the whole read on a single bad frame, which
            // is why the reader gave up the moment the tag answered its password -
            // and why the retry in hitag2_password() never got a chance to fire.
            rxlen = 0;
            continue;
        }


        // Check if frame was captured and store it
        // response_duration is accumulated from response_start and is therefore
        // already an absolute end time, not a length; adding response_start to it
        // again put the end of every tag frame at roughly twice the real time.
        LogTraceBits(rx, rxlen, response_start, response_duration, false);

// TODO when using cumulative time for command_start, pm3 doesn't reply anymore, e.g. on lf hitag reader --23 -k 4F4E4D494B52
// Use delta time?
        // TODO when using cumulative time for command_start, pm3 doesn't reply anymore, e.g. on lf hitag reader --23 -k 4F4E4D494B52
        // Use delta time?
        //            command_start = response_start + response_duration;
        //
        // Confirmed on hardware: making this cumulative stops the reader reading
        // a tag at all - 0 UID reads out of 12 against a simulator that answered
        // all 12 START_AUTHs, where the same test read the UID before the change.
        // The non monotonic trace (reader frames printing as 4294967015) is the
        // lesser evil until the timing is reworked properly.
        command_start = 0;
        nrzs = 0;
    }

out:

    DBG Dbprintf("RXFAIL no_signal=%u undecodable=%u last_samples=%u", d_norx, d_nodec, d_lastn);

    StopTimestamp();
    lf_finalize(ledcontrol);

    // release allocated memory from BigBuff.
    BigBuf_free();

    if (checked == -1) {
        reply_ng(CMD_LF_HITAG_READER, PM3_ESOFT, NULL, 0);
    }

    reply_ng(CMD_LF_HITAG_READER
             , (bSuccessful) ? PM3_SUCCESS : PM3_EFAILED
             , (uint8_t *)tag.sectors
             , tag_size
            );

}

void WriterHitag(const lf_hitag_data_t *payload, bool ledcontrol) {
    // TEMP INSTRUMENT: why an answer was not taken.  d_noans counts silent
    // windows, d_badn the decodes that failed and d_badnrz their sample counts.
    uint16_t d_noans = 0, d_badn = 0, d_badnrz[6] = {0}, d_badraw[6] = {0};
    uint8_t d_badper[12] = {0}, d_badpern = 0;

    uint32_t command_start = 0;
    uint32_t command_duration = 0;
    uint32_t response_start = 0;
    uint32_t response_duration = 0;

    uint8_t rx[HITAG_FRAME_LEN] = {0};
    size_t rxlen = 0;

    uint8_t txbuf[HITAG_FRAME_LEN];
    uint8_t *tx = txbuf;
    size_t txlen = 0;

    int t_wait_1 = 204;
    int t_wait_1_guard = 8;
    int t_wait_2 = 128;
    size_t tag_size = 48;

    bool bStop = false;

    // Raw demodulation/decoding by sampling edge periods

    // iceman:   Hitag2 is filled with static global vars.
    // these following are globals status indicator  :-|
    // Reset the return status
    bSuccessful = false;

    writestate = WRITE_STATE_START;
    blocknr = 0;

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    // Check configuration
    switch (payload->cmd) {
        case HT2F_CRYPTO: {
            DBG DbpString("Authenticating using key:");
            memcpy(key, payload->key, 6); //HACK; 4 or 6??  I read both in the code.
            memcpy(writedata, payload->data, 4);
            Dbhexdump(6, key, false);
            blocknr = payload->page;
            bCrypto = false;
            bAuthenticating = false;
            break;
        }
        case HT2F_PASSWORD: {
            DBG DbpString("Authenticating using password:");
            if (memcmp(payload->pwd, "\x00\x00\x00\x00", 4) == 0) {
                memcpy(password, tag.sectors[1], sizeof(password));
            } else {
                memcpy(password, payload->pwd, sizeof(password));
            }
            memcpy(writedata, payload->data, 4);
            DBG Dbhexdump(4, password, false);
            blocknr = payload->page;
            bPwd = false;
            bAuthenticating = false;
            break;
        }
        default: {
            DBG Dbprintf("Error, unknown function: " _RED_("%d"), payload->cmd);
            reply_ng(CMD_LF_HITAG2_WRITE, PM3_ESOFT, NULL, 0);
            return;
        }
    }

    if (ledcontrol) LED_D_ON();

    hitag2_init();

    // init as reader
    lf_init(LF_ADC_READER, LF_ADC_WAV_REVERSED, ledcontrol);

    // The timestamp counter has to be running before anything reads TIMESTAMP.
    // Only the sniffer and the simulator ever started it, so in the reader every
    // TIMESTAMP was whatever TC2 happened to hold: response_start, and the frame
    // timestamps handed to LogTraceBits, were meaningless - which is why the
    // reader's own `lf hitag list` came out as rows of 0 | 65535 and
    // 4294967235 | 65474, with none of its own frames placed against them.
    StartTimestamp();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    // Tag specific configuration settings (sof, timings, etc.)
// TODO HTS
    /*    if (payload->cmd <= HTS_LAST_CMD) {
            // hitag S settings
            t_wait_1 = 204;
            t_wait_2 = 128;
            //tag_size = 256;
            flipped_bit = 0;
            tag_size = 8;
            DBG DbpString("Configured for " _YELLOW_("Hitag S") " writer");
        } else
    */
    if (payload->cmd <= HT1_LAST_CMD) {
        // hitag 1 settings
        t_wait_1 = 204;
        t_wait_2 = 128;
        tag_size = 256;
        DBG DbpString("Configured for " _YELLOW_("Hitag 1") " writer");
    } else if (payload->cmd <= HT2_LAST_CMD) {
        // hitag 2 settings
        t_wait_1 = HITAG_T_WAIT_1_MIN;
        // Same as the reader path: t_WAIT2 is a minimum, so wait past the
        // simulator's post-answer recovery.  Left at 90 here, the writer's
        // password landed while a simulated tag was still deaf and came back as a
        // garbled 30 bit frame spanning 3023 T0, so the exchange died straight
        // after the UID.
        t_wait_2 = 1200;
        tag_size = 48;
        DBG DbpString("Configured for " _YELLOW_("Hitag 2") " writer");
    }

    size_t max_nrzs = (8 * HITAG_FRAME_LEN + 5) * 2; // up to 2 nrzs per bit
    uint8_t nrz_samples[max_nrzs];
    size_t nrzs = 0;
    int16_t checked = 0;
    uint32_t signal_size = 10000;
    bool turn_on = true;

    while (bStop == false && BUTTON_PRESS() == false) {

        // use malloc
        initSampleBufferEx(&signal_size, true);

        // Poll USB every pass.
        //
        // This used to fire only every 4000th iteration, to save time while
        // collecting samples.  One iteration here is a whole exchange - wait,
        // transmit a frame, wait, receive the answer - so 4000 of them is about a
        // minute during which the Proxmark answers nothing at all: a client that
        // gives up and sends CMD_BREAK_LOOP is not heard, `hw ping` from a second
        // client times out, and the device looks wedged until it comes back on its
        // own.  data_available() is a cheap status read next to an LF exchange.
        if (data_available()) {
            checked = -1;
            break;
        }

        WDT_HIT();

        // By default reset the transmission buffer
        tx = txbuf;

        switch (payload->cmd) {
            case HT2F_CRYPTO: {
                bStop = !hitag2_crypto(rx, rxlen, tx, &txlen, true);
                break;
            }
            case HT2F_PASSWORD: {
                bStop = !hitag2_password(rx, rxlen, tx, &txlen, true);
                break;
            }
            default: {
                goto out;
            }
        }

        if (bStop) {
            break;
        }

        if (turn_on) {
            // Wait 50ms with field off to be sure the transponder gets reset
            SpinDelay(50);
            FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
            turn_on = false;
            // Wait with field on to be in "Wait for START_AUTH" timeframe
            lf_wait_periods(HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4);
            command_start += HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4;
        } else {
            // Wait for t_wait_2 carrier periods after the last tag bit before transmitting,
            lf_wait_periods(t_wait_2);
            command_start += t_wait_2;
        }

        // Transmit the reader frame
        command_duration = hitag2_reader_send_frame(tx, txlen);

        // global write state variable used
        // tearoff occurred
        if ((writestate == WRITE_STATE_PROG) && (tearoff_hook() == PM3_ETEAROFF)) {
            reply_ng(CMD_LF_HITAG2_WRITE, PM3_ETEAROFF, NULL, 0);
            StopTimestamp();
    lf_finalize(ledcontrol);
            BigBuf_free();
            return;
        }

        response_start = command_start + command_duration;

        // Let the antenna and ADC values settle
        // And find the position where edge sampling should start.
        //
        // Refresh the ADC reference before listening.
        //
        // lf_count_edge_periods() slices at adc_avg +/- 20, and that average is
        // taken once in lf_init() and never renewed - so by the time we listen for
        // an answer to a 32 bit command, the reference predates both the field
        // settling and our own 890 T0 transmission.  That is the reader side twin
        // of the simulator's post-transmission deafness, and it is why the tag's
        // first answer decodes and its second one does not.
        //
        // lf_sample_mean() consumes exactly 32 carrier periods, so take them out of
        // the wait rather than adding to it and leave the turnaround unchanged.
        //
        // Take it at the END of the wait, not the start.  Both orders cost the
        // same 32 periods and leave the turnaround identical, but the reference
        // has to describe the envelope the answer will actually ride on.  Sampled
        // first, it is taken ~170 T0 earlier, while the field is still recovering
        // from our own transmission, and the +/- 20 slicing band then sits below
        // the settled level - which is where the missed edges come from.
        // Measured symptom: the merges cluster in the first few intervals of the
        // answer, 16 15 17 15 17 30 18 ..., and the frame lands on 35 bits.
        lf_wait_periods(t_wait_1 - t_wait_1_guard - 32);
        lf_sample_mean();

        // Start listening from a known modulation state.
        //
        // ht2_receive() opens with lf_get_tag_modulation(), which reports whatever
        // `rising_edge` was left at - and nothing reset it, so after our own
        // transmission it reflects the last edge of *that*, not the tag's answer.
        // When it comes out 0 the receive concludes it missed the first period and
        // synthesises a leading sample, which shifts every Manchester pair after
        // it.  Measured against a simulator: its answer arrived as 76 samples of
        // 1,0,1,1,0,1,0,1... where the genuine fob gives 1,0,1,0,1,0,1,0... - the
        // same stream with one sample inserted - so the SOF check failed and the
        // whole read was abandoned.  It happens after a 32 bit command and not
        // after a 5 bit one, which is why the UID reads and the password does not.
        lf_reset_counter();

        response_start += t_wait_1 - t_wait_1_guard;

        // Receive the tag's answer through the shared implementation.
        //
        // This used to be a second, near duplicate copy of the receive loop, and
        // the two drifted exactly as the reader's copy had: the first edge
        // compensation, the even sample padding and the head normalisation all
        // had to be written twice, and this copy never got the later fixes.  One
        // implementation, one set of fixes.
        bool got_answer = ht2_receive(&response_start, &response_duration, nrz_samples, &nrzs);

        // Store the TX frame, we do this now at this point, to avoid delay in processing
        // and to be able to overwrite the first samples with the trace (since they currently
        // still use the same memory space)
        LogTraceBits(tx, txlen, command_start, command_start + command_duration, true);

        // Reset values for receiving frames
        memset(rx, 0x00, sizeof(rx));
        rxlen = 0;

        // If there is no response, just repeat the loop
        if (got_answer == false) {
            d_noans++;
            continue;
        }

        if (ledcontrol) LED_B_ON();

        ht2_normalise_head((uint8_t *)nrz_samples, &nrzs);

        const uint16_t d_raw = (uint16_t)nrzs;

        // decode bitstream
        manrawdecode((uint8_t *)nrz_samples, &nrzs, true, 0);

        // Decode the frame with the shared packer rather than a private copy.
        //
        // The copy that used to be here had the same two faults the reader path
        // did, and one of its own: it demanded exactly five leading ones and
        // packed from a fixed offset of five, so it could not cope with a frame
        // whose head was disturbed; it ORed into rx without clearing it, so every
        // frame accumulated the ones of all its predecessors; and rx itself was
        // never initialised, so the first frame ORed onto stack garbage.  The
        // "skip spurious bit" fudge below it was papering over the same thing.
        if (ht2_packbits(nrz_samples, nrzs, rx, &rxlen) == false) {
            if (d_badn < ARRAYLEN(d_badnrz)) {
                d_badnrz[d_badn] = (uint16_t)nrzs;
                d_badraw[d_badn] = d_raw;
            }
            if (d_badpern == 0) {
                d_badpern = (g_ht2_per_n > ARRAYLEN(d_badper)) ? ARRAYLEN(d_badper) : (uint8_t)g_ht2_per_n;
                for (uint8_t k = 0; k < d_badpern; k++) {
                    d_badper[k] = g_ht2_per[k];
                }
            }
            d_badn++;
            DBG Dbprintf("Could not decode the tag answer, %u samples", (unsigned)nrzs);
            // One frame we could not decode is not the end of the exchange.
            // Breaking out abandoned the whole read on a single bad frame, which
            // is why the reader gave up the moment the tag answered its password -
            // and why the retry in hitag2_password() never got a chance to fire.
            rxlen = 0;
            continue;
        }

        // Check if frame was captured and store it.
        // response_duration is accumulated from response_start and is therefore
        // already an absolute end time, not a length; adding response_start to it
        // again put the end of every tag frame at roughly twice the real time.
        LogTraceBits(rx, rxlen, response_start, response_duration, false);
        command_start = 0;
        nrzs = 0;
    }

out:
    if (d_badpern) {
        DBG Dbprintf("WRXPER %u %u %u %u %u %u %u %u %u %u %u %u",
                 d_badper[0], d_badper[1], d_badper[2], d_badper[3],
                 d_badper[4], d_badper[5], d_badper[6], d_badper[7],
                 d_badper[8], d_badper[9], d_badper[10], d_badper[11]);
    }
    DBG Dbprintf("WRXSTAT silent=%u undecodable=%u bits: %u %u %u %u raw: %u %u %u %u",
             d_noans, d_badn, d_badnrz[0], d_badnrz[1], d_badnrz[2], d_badnrz[3],
             d_badraw[0], d_badraw[1], d_badraw[2], d_badraw[3]);

    StopTimestamp();
    lf_finalize(ledcontrol);

    // release allocated memory from BigBuff.
    BigBuf_free();

    if (checked == -1) {
        reply_ng(CMD_LF_HITAG2_WRITE, PM3_ESOFT, NULL, 0);
    }

    reply_ng(CMD_LF_HITAG2_WRITE
             , (bSuccessful) ? PM3_SUCCESS : PM3_EFAILED
             , (uint8_t *)tag.sectors
             , tag_size
            );
}


static void ht2_send(bool turn_on, uint32_t *cmd_start
                     , uint32_t *cmd_duration, uint32_t *resp_start
                     , uint8_t *tx, size_t txlen, bool send_bits) {

    // Tag specific configuration settings (sof, timings, etc.)  HITAG2 Settings
#define T_WAIT_1_GUARD  7

    if (turn_on) {
        // Wait 50ms with field off to be sure the transponder gets reset
        SpinDelay(50);
        FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);

        // Wait with field on to be in "Wait for START_AUTH" timeframe
        lf_wait_periods(HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4);
        *cmd_start += HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4;

    } else {
        // Wait for t_wait_2 carrier periods after the last tag bit before transmitting,
        lf_wait_periods(HITAG_T_WAIT_2_MIN + HITAG_T_WAIT_2_MIN);
        *cmd_start += (HITAG_T_WAIT_2_MIN + HITAG_T_WAIT_2_MIN);
    }

    // Transmit the reader frame
    if (send_bits) {
        *cmd_duration = hitag2_reader_send_framebits(tx, txlen);
    } else {
        *cmd_duration = hitag2_reader_send_frame(tx, txlen);
    }

    *resp_start = (*cmd_start + *cmd_duration);

    *resp_start += (HITAG_T_WAIT_1_MIN - T_WAIT_1_GUARD);
    // Let the antenna and ADC values settle
    // And find the position where edge sampling should start
    lf_wait_periods(HITAG_T_WAIT_1_MIN - T_WAIT_1_GUARD);
}

static bool ht2_receive(uint32_t *resp_start, uint32_t *resp_duration, uint8_t *nrz_samples, size_t *samples) {

    // Keep administration of the first edge detection
    bool waiting_for_first_edge = true;

    // set once the first edge has been taken, until the interval after it has been
    // seen and can confirm or reject it - see the resolution below
    bool first_edge_pending = false;

    // set when a half bit sample is synthesised at the head, see the tail fix below
    bool inserted_leading = false;

    // Did we detected any modulaiton at all
    bool detected_tag_modulation = false;

    // Reset the number of NRZ samples and use edge detection to detect them
    size_t nrzs = 0;

    // Bound the loop independently of nrzs.  Re-anchoring below resets nrzs, and
    // the loop condition is written in terms of it, so without this a re-anchor
    // makes the receive unbounded and the command never returns.
    uint32_t spins = 4 * HT2_MAX_NRSZ;

    g_ht2_per_n = 0;

    // Use the current modulation state as starting point
    uint8_t tag_modulation = lf_get_tag_modulation();

    // Raw demodulation/decoding by sampling edge periods

    while (nrzs < HT2_MAX_NRSZ) {

        if (spins-- == 0) {
            break;
        }

        // Get the timing of the next edge in number of wave periods
        size_t periods = lf_count_edge_periods(128);

        // Are we dealing with the first incoming edge
        if (waiting_for_first_edge) {

            // Just break out of loop after an initial time-out (tag is probably not available)
            if (periods == 0) {
                break;
            }

            if (tag_modulation == 0) {
                // hitag replies always start with 11111 == 1010101010, if we see 0
                // it means we missed the first period, e.g. if the signal never crossed 0 since reader signal
                // so let's add it:
                nrz_samples[nrzs++] = tag_modulation ^ 1;
                inserted_leading = true;
                // Register the number of periods that have passed
                // we missed the begin of response but we know it happened one period of 16 earlier
                resp_start += (periods - 16);
                resp_duration = resp_start;

            } else {
                // Register the number of periods that have passed
                resp_start += periods;
                resp_duration = resp_start;
            }

            // Indicate that we have dealt with the first edge
            waiting_for_first_edge = false;

            // Defer judging this edge until the next interval is known.
            //
            // The reader starts sampling t_wait_1_guard before the answer is due,
            // so the first edge it sees may be the idle line rather than the tag.
            // The two are trivially told apart by what follows: a real first half
            // bit runs about 16 carrier periods, while a false start is followed by
            // a gap of only a few.  Measured against a simulator, that false start
            // showed up as a 3..6 period interval and cost the frame a half bit -
            // answers arrived as 70..74 samples where 74 is right, and
            // ht2_packbits() rejected them.
            //
            // Deciding one interval late costs nothing and needs no state to be
            // rewound, which is what made re-anchoring lose samples.
            first_edge_pending = true;

            // The first edge is always a single NRZ bit, force periods on 16
            periods = 16;
            // We have received more than 0 periods, so we have detected a tag response
            detected_tag_modulation = true;

        } else {
            // The function lf_count_edge_periods() returns 0 when a time-out occurs
            if (periods == 0) {
                break;
            }
        }
        // Measured, so it is not retried blind: re-anchoring the frame when the
        // first measured gap is too short to be a half bit does clean the period
        // sequence perfectly - 16 16 15 17 15 17 instead of 16 6 18 15 17 - but it
        // costs samples.  The frame fell from 37 decoded bits to 35, under the 36
        // that ht2_packbits() needs, and failures went from 4 to 84.  The
        // diagnosis is right; discarding the edge is the wrong remedy.

        // Resolve the deferred first edge, now that we can see what followed it.
        if (first_edge_pending) {
            first_edge_pending = false;

            if (periods <= 10) {
                // A false start: the edge we anchored on was the idle line, and
                // this short gap is the distance to the real one.  Drop the sample
                // that edge produced and anchor here instead, keeping the
                // modulation state that goes with it.
                if (nrzs > 0) {
                    nrzs--;
                }
                tag_modulation ^= 1;
                resp_start += periods;
                resp_duration = resp_start;
                continue;
            }
        }

        if (g_ht2_per_n < ARRAYLEN(g_ht2_per)) {
            g_ht2_per[g_ht2_per_n++] = (periods > 255) ? 255 : (uint8_t)periods;
        }

        // Evaluate the number of periods before the next edge.
        //
        // A tag half bit is 16 carrier periods and a doubled one 32; measured
        // against a simulator the answer sits at 15..18 and 30..33, with an
        // occasional glitch of about 6 right at the start that this accepts as a
        // half bit and which then shifts every Manchester pair after it.
        //
        // Two ways of rejecting it were tried and both are worse.  Dropping the
        // glitch inverts the polarity of everything that follows, because the
        // signal really did change state - the reader ended up restarting the
        // exchange over and over, 97 START_AUTHs for 49 answers.  Carrying it into
        // the next interval keeps the polarity but lands on 24 periods, which is
        // ambiguous between one half bit and two, and the sample count fell from
        // 74 to 70.  Needs the glitch not to be produced, rather than classified.
        //
        // A third was tried and is worse still: reading a doubled interval in the
        // first ten half bits as a missed edge instead - two alternating samples
        // and no polarity flip - on the reasoning that the answer's SOF is five
        // '1' bits, so strictly alternating, so it cannot contain a doubled half
        // bit.  Writes went from 5 of 6 to 0 of 6.  The premise is sound but the
        // window is not: answers on this rig arrive as 16 15 17 15 17 15 17 30 33
        // 31 18 ..., three doubled intervals in a row while nrzs is still under
        // ten, so the tenth sample is already well past the SOF and the rule fires
        // on real payload.  A missed edge cannot be told from a doubled half bit
        // by position, only by an SOF boundary we do not actually know.
        if (periods > 24 && periods <= 64) {
            // Detected two sequential equal bits and a modulation switch
            // NRZ modulation: (11 => --|) or (11 __|)
            nrz_samples[nrzs++] = tag_modulation;

            if (nrzs < HT2_MAX_NRSZ) {
                nrz_samples[nrzs++] = tag_modulation;
            }

            resp_duration += periods;
            // Invert tag modulation state
            tag_modulation ^= 1;

        } else if (periods > 0 && periods <= 24) {
            // Detected one bit and a modulation switch
            // NRZ modulation: (1 => -|) or (0 _|)
            nrz_samples[nrzs++] = tag_modulation;

            resp_duration += periods;

            tag_modulation ^= 1;

        } else {
            // The function lf_count_edge_periods() returns > 64 periods, this is not a valid number periods
            break;
        }
    }

    // Make sure we always have an even number of samples. This fixes the problem
    // of ending the manchester decoding with a zero. See the example below where
    // the '|' character is end of modulation
    //  One at the end: ..._-|_____...
    // Zero at the end: ...-_|_____...
    // The last modulation change of a zero is not detected, but we should take
    // the half period in account, otherwise the demodulator will fail.
    // If a sample was synthesised at the head, every pair after it is shifted by
    // one and the final pair loses its second half.  manrawdecode() cannot
    // classify that pair, writes the impossible symbol 7, and packing stops a bit
    // early - a tag answering CE129911 decodes as CE129910.
    //
    // That missing half carries no information.  Manchester pairs are (1,0)='1'
    // and (0,1)='0', so the first half alone determines the bit and the second is
    // simply its complement.  Synthesising it completes the pair and recovers the
    // last bit, no closing edge required.
    if (inserted_leading && nrzs && ((nrzs + 2) < HT2_MAX_NRSZ)) {
        // Two samples, forming one legal pair, not one.
        //
        // The synthesised head shifts the pairing, and manrawdecode() picks its
        // own alignment on top of that, so a single filler can still leave the
        // closing symbol without a partner - the payload then lands one bit short
        // (31 of 32) and is thrown away.  A whole pair gives the decoder slack
        // whichever alignment it settles on.
        const uint8_t last = nrz_samples[nrzs - 1];
        nrz_samples[nrzs++] = (last != 0) ? 0 : 1;
        nrz_samples[nrzs++] = last;
    }

    if ((nrzs % 2) != 0) {

        if (nrzs >= HT2_MAX_NRSZ) {
            return false;
        }

        // Complete the pair with the complement of its first half, not with the
        // current line level.  Manchester pairs are (1,0)='1' and (0,1)='0', so
        // the second half is always the inverse of the first; appending the level
        // instead can produce (1,1) or (0,0), which manrawdecode() then flags as
        // an impossible symbol and the payload comes up a bit short.
        nrz_samples[nrzs] = (nrz_samples[nrzs - 1] != 0) ? 0 : 1;
        nrzs++;
    }

    // Whatever happened above, the closing pair has to be a legal one.  The last
    // half bit of a tag's answer has no transition after it - nothing follows, so
    // the line simply returns to idle - and the demodulator can be left holding a
    // duplicated sample.  The first half already determines the bit, so rewriting
    // the second as its complement recovers it rather than discarding the pair.
    if ((nrzs >= 2) && (nrz_samples[nrzs - 1] == nrz_samples[nrzs - 2])) {
        nrz_samples[nrzs - 1] = (nrz_samples[nrzs - 2] != 0) ? 0 : 1;
    }

    // A Hitag 2 answer opens with a SOF '1', which in half bit samples is (1,0),
    // so the very first sample must be a 1.  If it is not, an extra sample has
    // been prepended - the first edge compensation above does exactly that - and
    // manrawdecode() then has to guess the pairing.  It guesses by counting
    // (bits[i] == bits[i+1]) errors for both alignments, which on a short frame
    // can tie or come out backwards; picking alignment 1 drops both the first
    // sample and the tail, yielding 36 symbols with a spurious leading zero and a
    // payload one bit short.
    //
    // Dropping that leading sample makes alignment 0 the correct one, so the
    // guess cannot go wrong.
    if (nrzs && (nrz_samples[0] != 1)) {
        for (size_t k = 1; k < nrzs; k++) {
            nrz_samples[k - 1] = nrz_samples[k];
        }
        nrzs--;
    }

    *samples = nrzs;

    return detected_tag_modulation;
}

// A Hitag 2 answer opens with a SOF '1', whose first half bit sample is a 1.
// Anything else means a sample was prepended - the first edge compensation in
// ht2_receive() does exactly that - and manrawdecode() would then have to guess
// the pairing.  It guesses by counting (bits[i] == bits[i+1]) errors for both
// alignments, which on a short frame can tie or come out backwards; picking
// alignment 1 drops both the first sample and the tail, yielding 36 symbols with
// a spurious leading zero and a payload one bit short - a tag answering CE129911
// read back as 9C253222.  Dropping the leading sample makes alignment 0 correct
// by construction, so the guess cannot go wrong.
//
// Every Hitag 2 decode path needs this, so it lives here rather than being
// copied: ht2_tx_rx() lacked it, which is the brute force path behind
// `lf hitag chk`, `crack2` and `lookup`, where a mis-decode is a wrong verdict
// on a key rather than a visibly wrong read.
static void ht2_normalise_head(uint8_t *nrz_samples, size_t *nrzs) {
    if (*nrzs && (nrz_samples[0] != 1)) {
        for (size_t k = 1; k < *nrzs; k++) {
            nrz_samples[k - 1] = nrz_samples[k];
        }
        (*nrzs)--;
    }
}

bool ht2_packbits(uint8_t *nrz_samples, size_t nrzs, uint8_t *rx, size_t *rxlen) {

    if (nrzs < 5) {
        return false;
    }

    // A Hitag 2 answer is a SOF of ones followed by a 32 bit payload: 37 bits.
    //
    // The head is the anchor, not the length.  Sampling starts a known t_WAIT1
    // after the reader's command, and the normalisation above guarantees that
    // sample `start` is the first half bit of the SOF, so the SOF is simply the
    // datasheet's five bits at the front and anything past 37 is tail junk.
    //
    // Deriving the SOF as (length - 32) instead was wrong, and only looked right
    // because it was calibrated against this repo's own simulator, which answers
    // in exactly 37.  A genuine Paxton fob measured on this rig gives 76 raw
    // samples - 38 bits - with the surplus bit at the TAIL, so that rule skipped
    // six bits instead of five, dropped the first payload bit and took a spurious
    // one at the end: CE129911 read back as 9C253223, the same value shifted left
    // once.  The one case where the head really is short is 36 bits, where the
    // opening half bit was lost and only four SOF bits survive.
    //
    // Do not instead try several alignments and keep whichever packs cleanly:
    // more than one can pack a full 32 bits, and picking the wrong one hands back
    // a plausible but wrong UID.  Refusing to decode is far better than that.
    size_t start = 0;
    if (nrz_samples[0] != 1) {
        // a leading non-one is only ever the spurious sample, never part of a SOF
        start = 1;
    }

    if (nrzs <= start) {
        return false;
    }

    const size_t remaining = nrzs - start;

    // Which payload length is this?
    //
    // A tag answers either 32 bits of page data or, acknowledging a WRITE PAGE, a
    // 10 bit echo of the command.  This only ever accepted the 32 bit case, so the
    // reader threw away its own write acknowledgement - the simulator's trace
    // showed it echoing WRITE PAGE (4) correctly and the write failing anyway.
    //
    // A whole answer is SOF + payload, so the total picks the length out; the SOF
    // match below then still has to agree.
    size_t payload = 0;
    if ((remaining >= 36) && (remaining <= 39)) {
        payload = 32;
    } else if ((remaining >= 14) && (remaining <= 17)) {
        payload = 10;
    } else {
        return false;
    }

    // Do NOT widen this to 35 with a three bit SOF.
    //
    // It is tempting: the reader loses an edge in the tag's answer now and then,
    // two half bits merge and the frame arrives two bits short, and 35 looks like
    // a complete 32 bit payload behind a clipped header.  Measured, it lifts reads
    // from 3 of 6 to 6 of 6 and writes from 1 of 3 to 3 of 3.
    //
    // And it is wrong.  Three surviving header ones are not distinctive enough, so
    // frames mis-frame and decode to plausible but incorrect values: in that same
    // run the UID came back as BD F5 E8 46 - the password - and other blocks as
    // zeroes.  Silent corruption is far worse than a refused frame, which the
    // caller retries anyway.  The comment above about not keeping whichever
    // alignment packs cleanly is the same lesson; this is the second time.

    // Match the SOF rather than inferring its length from the frame length.
    //
    // The datasheet SOF is five ones, and a frame that lost its first half bit
    // carries four.  Deriving the length from the total gets that right when the
    // loss also shortens the frame - 36 bits, so four - and wrong when a spurious
    // bit at the tail makes up the difference.  Measured against a simulator: the
    // config answer arrived as 37 bits whose stream was the expected one shifted
    // left by one, so it held four SOF ones and a surplus bit at the end, and
    // assuming five failed the check at bit four on an answer that was otherwise
    // perfect.
    //
    // So try five and fall back to four.  This matches a known pattern, it does
    // not guess at data: whichever length is used, the SOF bits still have to be
    // ones and the payload still has to be a full 32 bits.
    // Prefer the length-implied SOF, and only fall back to the other.
    //
    // Trying five first regardless is ambiguous whenever the payload itself starts
    // with a one: four surviving SOF bits plus that one look like five, and the
    // frame decodes shifted left by a bit.  Measured against a simulator, exactly
    // the blocks beginning with a 1 came back wrong - BDF5E846 as 7BEBD08D,
    // B6447420 as 6C88E841, 96000010 as 2C000021 - while every block beginning
    // with a 0 was right.
    //
    // A whole answer is 5 + 32 = 37 bits, so the length says which to try first;
    // the pattern check then still has to agree.
    const size_t first = (remaining >= (payload + 5)) ? 5 : 4;
    size_t sof = 0;
    for (size_t n = 0; n < 2; n++) {

        const size_t cand = (n == 0) ? first : (9 - first);

        if (remaining < (cand + payload)) {
            continue;
        }

        bool ok = true;
        for (size_t k = 0; k < cand; k++) {
            if (nrz_samples[start + k] != 1) {
                ok = false;
                break;
            }
        }

        if (ok) {
            sof = cand;
            break;
        }
    }

    if (sof == 0) {
        return false;
    }

    size_t len = 0;

    // Clear the payload bytes before packing into them.
    //
    // The loop below ORs each bit in, so a buffer the caller reuses across frames
    // accumulates every frame that came before it.  ReaderHitag() does reuse one:
    // the UID answer CE129911 packed correctly, then the config answer 06F907C2
    // ORed on top of it and came back as CEFB9FD3, and every page after that read
    // as the same growing OR - which is why a dump printed one identical value
    // for all eight blocks.
    memset(rx, 0, (payload + 7) / 8);

    // exactly the payload, and no more: a surplus bit at the tail is junk
    for (size_t i = start + sof; (i < nrzs) && (len < payload); i++) {

        const uint8_t bit = nrz_samples[i];

        // manrawdecode() writes 7 for a pair it could not resolve
        if (bit > 1) {
            break;
        }

        rx[len >> 3] |= bit << (7 - (len % 8));
        len++;
    }

    // anything short of the full payload is a failed decode, not a short frame
    if (len != payload) {
        return false;
    }

    *rxlen = len;
    return true;
}int ht2_read_uid(uint8_t *uid, bool ledcontrol, bool send_answer, bool keep_field_up) {

    g_logging = false;

    // keep field up indicates there are more traffic to be done.
    if (keep_field_up == false) {
        clear_trace();
    }

    // hitag 2 state machine?
    hitag2_init();

    // init as reader
    lf_init(LF_ADC_READER, LF_ADC_WAV_REVERSED, true);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    uint8_t rx[HITAG_FRAME_LEN] = {0};
    size_t rxlen = 0;  // In number of bits

    uint8_t nrz_samples[HT2_MAX_NRSZ];

    uint8_t attempt_count = 3;

    int res = PM3_EFAILED;
    bool turn_on = true;

    while (attempt_count && BUTTON_PRESS() == false) {

        attempt_count--;

        WDT_HIT();

        uint32_t command_start = 0, command_duration = 0;
        uint32_t response_start = 0, response_duration = 0;

        // start AUTH command
        size_t txlen = 5;
        uint8_t tx[] = {HITAG2_START_AUTH};

        // Transmit as reader
        ht2_send(turn_on, &command_start, &command_duration, &response_start, tx, txlen, false);

        turn_on = false;

        // Reset the number of NRZ samples and use edge detection to detect them
        size_t nrzs = 0;

        // receive raw samples
        if (ht2_receive(&response_start, &response_duration, nrz_samples, &nrzs) == false) {
            continue;
        }

        // Store the transmit frame ( TX ), we do this now at this point, to avoid delay in processing
        // and to be able to overwrite the first samples with the trace (since they currently
        // still use the same memory space)
        LogTraceBits(tx, txlen, command_start, command_start + command_duration, true);

        // decode raw samples from Manchester Encoded to bits
        manrawdecode(nrz_samples, &nrzs, true, 0);

        // pack bits to bytes
        if (ht2_packbits(nrz_samples, nrzs, rx, &rxlen) == false) {
            continue;
        }

        // log Receive data
        LogTraceBits(rx, rxlen, response_start, response_start + response_duration, false);

        if (rxlen != 32)  {
            continue;
        }

        // Store received UID
        memcpy(tag.sectors[0], rx, 4);
        if (uid) {
            memcpy(uid, rx, 4);
        }
        res = PM3_SUCCESS;
        break;
    }

    if (keep_field_up == false) {
        lf_finalize(false);
        BigBuf_free_keep_EM();
    }

    if (send_answer) {
        reply_ng(CMD_LF_HITAG_READER, res, (uint8_t *)tag.sectors, 4);
    }

    return res;
}

// This function assumes you have called hitag2_read_uid before to turn on the field :)
// tx = expects bin arrays 0,1 i
// txlen = number of bits to send
// rx =  return bin arrys
// rxlen = number of bits returned
int ht2_tx_rx(uint8_t *tx, size_t txlen, uint8_t *rx, size_t *rxlen, bool ledcontrol, bool keep_field_up) {

    int res = PM3_EFAILED;
    size_t nrzs = 0;
    uint8_t samples[HT2_MAX_NRSZ] = {0};

    uint32_t command_start = 0, command_duration = 0;
    uint32_t response_start = 0, response_duration = 0;

    // Transmit as reader
    ht2_send(false, &command_start, &command_duration, &response_start, tx, txlen, true);

    // receive raw samples
    if (ht2_receive(&response_start, &response_duration, samples, &nrzs) == false) {
        goto out;
    }

    ht2_normalise_head(samples, &nrzs);

    // decode raw samples from Manchester Encoded to bits
    if (manrawdecode(samples, &nrzs, true, 0)) {
        goto out;
    }

    // pack bits to bytes
    if (rx && (ht2_packbits(samples, nrzs, rx, rxlen) == false)) {
        goto out;
    }

    res = PM3_SUCCESS;

out:
    if (keep_field_up == false) {
        lf_finalize(false);
    }
    return res;
}
