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
// Hitag shared functionality
//-----------------------------------------------------------------------------

#include "hitag_common.h"

#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "fpga_loader.h"
#include "fpga_apis.h"
#include "ticks_apis.h"
#include "dbprint.h"
#include "util.h"
#include "string.h"
#include "commonutil.h"
#include "hitag2/hitag2_crypto.h"
#include "lfadc.h"
#include "lfsampling.h"
#include "crc.h"
#include "protocols.h"
#include "appmain.h"    // tearoff_hook()

// Initialize FPGA and timer for Hitag operations
// A short settle after an FPGA mode change.  Deliberately a plain busy loop:
// hitag_setup_fpga() calls StopTicks() first, so WaitMS()/SpinDelay() have no
// timebase there and simply hang - that wedged the device hard enough to need a
// replug.  Roughly a few milliseconds at 48 MHz, which is all the FPGA needs.
// HITAG_RX_IDLE_GUARD now lives in hitag_common.h - SniffHitag2() needs it too.

static void hitag_settle(void) {
    for (volatile uint32_t i = 0; i < 200000; i++) {
        if ((i & 0x3FF) == 0) {
            WDT_HIT();
        }
    }
}

// Pick an edge detect threshold by measuring, rather than making the user guess.
//
// The usable window is narrow and reader dependent: against a Paxton reader
// 5..25 all worked, 30 was marginal and 40 received nothing, while the FPGA's
// own default of 127 received nothing at all.  Asking the user to find that by
// hand is not reasonable, so sample the edge rate at a spread of candidates and
// keep the most noise-rejecting one that still sees a healthy share of them.
//
// Must run with the FPGA already in edge detect and the capture timer started.
uint8_t hitag_autotune_threshold(void) {

    static const uint8_t cand[] = { 8, 12, 16, 20, 24, 28, 32 };
    uint32_t seen[ARRAYLEN(cand)] = {0};
    uint32_t best_seen = 0;

    for (uint32_t i = 0; i < ARRAYLEN(cand); i++) {

        FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, cand[i]);
        hitag_settle();

        uint32_t before = g_hitag_edges;

        // a few bounded receive passes is enough to gauge the edge rate
        for (uint32_t k = 0; k < 3; k++) {
            uint8_t rx[HITAG_FRAME_LEN] = {0};
            size_t rxlen = 0;
            uint32_t start_time = 0;
            int overflow = 0;
            hitag_tag_receive_frame_ex(rx, sizeof(rx), &rxlen, &start_time, false, &overflow, true);
            ResetLoEdgeCapture();
        }

        seen[i] = g_hitag_edges - before;
        if (seen[i] > best_seen) {
            best_seen = seen[i];
        }
    }

    // Nothing at all means no reader is present; leave a value that works once
    // one shows up rather than picking the most sensitive setting and chattering.
    if (best_seen == 0) {
        return 20;
    }

    uint8_t chosen = cand[0];
    for (uint32_t i = 0; i < ARRAYLEN(cand); i++) {
        if (seen[i] >= (best_seen / 2)) {
            chosen = cand[i];
        }
    }
    return chosen;
}

void hitag_setup_fpga(uint16_t conf, uint8_t threshold, bool ledcontrol) {
    StopTicks();

    // the EM-preserving variant: the plain FpgaDownloadAndGo() wipes all of
    // BigBuf, emulator memory included, whenever the LF bitstream is not
    // already cached, which would discard what `lf hitag eload` just wrote
    FpgaDownloadAndGo_keep_EM(FPGA_BITSTREAM_LF);

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    if (ledcontrol) LED_D_ON();

    // Bring the LF front end up the same way lf_init() and LFSetupFPGAForADC() do,
    // in the same order.  Two steps were missing here and both matter:
    //
    //   - the divisor has to be sent BEFORE the conf word, not after.  Setting the
    //     major mode last is what latches it, so programming the divisor afterwards
    //     left the sampling clock unconfigured.
    //   - FpgaSetupSsc() was never called at all, so the ADC sample stream the edge
    //     detector works from was never set up.
    //
    // The symptom was a detector free running at ~52 kHz - 633k edges in 12 s with
    // nothing framed, and no value of the threshold making any measurable difference.
    // Running any command that calls lf_init() (`lf read`, say) fixed it until the
    // next boot, which is what made it look like the device needed reflashing.
    // Bring the LF ADC front end up first, exactly as lf_init()/LFSetupFPGAForADC()
    // do, before switching the FPGA into edge detect.  Without this the peak
    // detector is never initialised and the edge detector free runs; running any
    // command that goes through lf_init() (`lf read`) fixed it until the next boot,
    // which is what made it look like the device needed reflashing.  reader_field
    // is false here: this is a tag simulator, it must not energise the coil.
    LFSetupFPGAForADC(LF_DIVISOR_125, false);
    hitag_settle();

    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125);  //125kHz
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | conf);
    if (threshold != 127) FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, threshold);

    // Connect the A/D to the peak-detected low-frequency path.
    SetAdcMuxFor(ADC_MUXSEL_LOPKD);

    // Set up the SSC so the ADC samples actually stream to the FPGA.
    FpgaSetupSsc(FPGA_MAJOR_MODE_LF_READER);

    // Give the front end a moment to settle before anything reads from it.
    hitag_settle();

    // Configure the timers via the HAL: a precision counter (T0 timing), an
    // input capture (tag frame edges) and a timestamp counter (trace timing).
    //
    // The input capture goes LAST, after the FPGA is configured.  StartLoEdgeCapture()
    // claims SSC_FRAME for TC1 via PIO_BSR, and the FpgaWriteConfWord()/FpgaSendCommand()
    // bit-bang that follows drives the same SSC lines, which undid that routing:
    // the detector then free ran at ~52 kHz (633k edges in 12 s) with nothing framed,
    // and the edge detect threshold had no measurable effect at any value.
    // SniffHitag2(), which does frame reader traffic, has always ordered it this way.
    StartPrecisionCounter();
    StartTimestamp();
    StartLoEdgeCapture();

    // Configure output and enable pin that is connected to the FPGA (for modulating)
    gpio_fpga_mod_only_setup();

    // Disable modulation at default, which means enable the field
    Gpio_SSC_DOUT_Low();
}

// Clean up and finalize Hitag operations
void hitag_cleanup(bool ledcontrol) {
    StopPrecisionCounter();
    StopLoEdgeCapture();
    StopTimestamp();
    set_tracing(false);
    lf_finalize(ledcontrol);
}

// Reader functions
static void hitag_reader_send_bit(int bit, bool ledcontrol) {
    // Time this bit from its own start.  Taking a reference and measuring the
    // difference leaves the free running counter alone, so nothing here depends
    // on a reset having landed, and the shared reference that the receive path
    // measures "time since the last edge" against is left where it was.
    const uint16_t t_ref = GetPrecisionCounterRaw();

    if (ledcontrol) LED_A_ON();

    // Binary puls length modulation (BPLM) is used to encode the data stream
    // This means that a transmission of a one takes longer than that of a zero
    Gpio_SSC_DOUT_High();

    // Wait for 4-10 times the carrier period
    while (GetPrecisionCounterDelta(t_ref) < T0 * HITAG_T_LOW) {};

    Gpio_SSC_DOUT_Low();

    if (bit == 0) {
        // Zero bit: |_-|
        while (GetPrecisionCounterDelta(t_ref) < T0 * HITAG_T_0) {};
    } else {
        // One bit: |_--|
        while (GetPrecisionCounterDelta(t_ref) < T0 * HITAG_T_1) {};
    }

    if (ledcontrol) LED_A_OFF();
}

void hitag_reader_send_frame(const uint8_t *frame, size_t frame_len, bool ledcontrol, bool send_sof) {
    // Send SOF (Start of Frame) for Hitag µ if requested
    if (send_sof) {
        hitag_reader_send_bit(0, ledcontrol);

        // Time the code violation from its own start, see hitag_reader_send_bit()
        const uint16_t t_sof = GetPrecisionCounterRaw();

        if (ledcontrol) LED_A_ON();

        // SOF is HIGH for HITAG_T_LOW
        Gpio_SSC_DOUT_High();
        while (GetPrecisionCounterDelta(t_sof) < T0 * HITAG_T_LOW) {};

        // Then LOW for HITAG_T_CODE_VIOLATION
        Gpio_SSC_DOUT_Low();
        while (GetPrecisionCounterDelta(t_sof) < T0 * HITAG_T_CODE_VIOLATION) {};

        if (ledcontrol) LED_A_OFF();
    }

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        hitag_reader_send_bit(TEST_BIT_MSB(frame, i), ledcontrol);
    }

    // Send EOF
    ResetPrecisionCounter();

    Gpio_SSC_DOUT_High();

    // Wait for 4-10 times the carrier period
    while (GetPrecisionCounter() < T0 * HITAG_T_LOW) {};

    Gpio_SSC_DOUT_Low();
}

void hitag_reader_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *resptime, bool ledcontrol,
                                hitag_mod_t modulation, int sof_bits) {
    // Reset values for receiving frames
    memset(rx, 0x00, sizeofrx);
    *rxlen = 0;

    int lastbit = 1;
    bool bSkip = true;
    uint32_t errorCount = 0;
    bool bStarted = false;
    lo_edge_t next_edge = LO_EDGE_FALLING;
    int double_speed = (modulation == AC4K || modulation == MC8K) ? 2 : 1;

    uint32_t rb_i = 0;
    uint8_t edges[160] = {0};

    // Skip SOF bits
    bool sof_received = false;

    // Receive tag frame, watch for at most T0*HITAG_T_PROG_MAX periods.
    //
    // Bounded, for the same reason the tag side receive is.  The precision
    // counter is reset on every edge below, so the T_PROG_MAX bound only expires
    // while the line is quiet: when the edge detector chatters - which it does
    // with no clean carrier to work with - edges keep arriving, the counter keeps
    // being reset, and this loop never returns.  Nothing in it polls the button
    // or USB, so the Proxmark stops answering entirely and only a replug brings
    // it back.  Two devices were lost that way while measuring.
    uint32_t guard = HITAG_RX_IDLE_GUARD;
    while (GetPrecisionCounter() < (T0 * HITAG_T_PROG_MAX)) {

        if (--guard == 0) {
            break;
        }
        if ((guard & 0x3FF) == 0) {
            WDT_HIT();
        }

        // Check if edge in tag modulation is detected
        if (GetLoEdgeCaptureStatus() == next_edge) {
            next_edge = next_edge == LO_EDGE_RISING ? LO_EDGE_FALLING : LO_EDGE_RISING;

            // only use INPUT_CAPTURE_EVT_RB falling edge for now
            if (next_edge == LO_EDGE_FALLING) {
                continue;
            }

            // Retrieve the new timing values
            uint32_t rb = GetLoEdgeCaptureFalling() / T0;

            // For debug, save the edges for decoding manual
            if (rb_i < ARRAYLEN(edges)) {
                edges[rb_i++] = rb;
            }

            // Reset timer every frame, we have to capture the last edge for timing
            ResetPrecisionCounter();

            if (ledcontrol) LED_B_INV();

            // Capture tag frame (manchester decoding using only falling edges)
            if (bStarted == false) {
                if (rb >= HITAG_T_WAIT_RESP) {
                    bStarted = true;

                    // Capture tag response timestamp
                    *resptime = TIMESTAMP;

                    // We always receive a 'one' first, which has the falling edge after a half period |-_|
                    rx[0] = 0x80;
                    *rxlen = 1;
                } else {
                    errorCount++;
                }
            } else {
                // Handle different modulation types
                if (modulation == AC2K || modulation == AC4K) {
                    // Anticollision Coding
                    if (rb >= HITAG_T_TAG_CAPTURE_FOUR_HALF / double_speed) {
                        // Anticollision Coding example |--__|--__| (00)
                        lastbit = 0;
                        // CLEAR_BIT_MSB(rx, *rxlen);
                        (*rxlen)++;
                    } else if (rb >= HITAG_T_TAG_CAPTURE_THREE_HALF / double_speed) {
                        // Anticollision Coding example |-_-_|--__| (10) or |--__|-_-_| (01)
                        lastbit = !lastbit;
                        if (lastbit) {
                            SET_BIT_MSB(rx, *rxlen);
                        }
                        (*rxlen)++;

                        bSkip = !!lastbit;
                    } else if (rb >= HITAG_T_TAG_CAPTURE_TWO_HALF / double_speed) {
                        // Anticollision Coding example |-_-_| (1)
                        if (bSkip == false) {
                            lastbit = 1;
                            SET_BIT_MSB(rx, *rxlen);
                            (*rxlen)++;
                        }

                        bSkip = !bSkip;
                    } else {
                        // Ignore weird value, is to small to mean anything
                        errorCount++;
                    }
                } else {
                    // Manchester coding (MC4K, MC8K)
                    if (rb >= HITAG_T_TAG_CAPTURE_FOUR_HALF / double_speed) {
                        // Manchester coding example |-_|_-|-_| (101)
                        // CLEAR_BIT_MSB(rx, *rxlen);
                        (*rxlen)++;

                        SET_BIT_MSB(rx, *rxlen);
                        (*rxlen)++;
                    } else if (rb >= HITAG_T_TAG_CAPTURE_THREE_HALF / double_speed) {
                        // Manchester coding example |_-|...|_-|-_| (0...01)
                        // CLEAR_BIT_MSB(rx, *rxlen);
                        (*rxlen)++;

                        // We have to skip this half period at start and add the 'one' the second time
                        if (bSkip == false) {
                            SET_BIT_MSB(rx, *rxlen);
                            (*rxlen)++;
                        }

                        lastbit = !lastbit;
                        bSkip = !bSkip;
                    } else if (rb >= HITAG_T_TAG_CAPTURE_TWO_HALF / double_speed) {
                        // Manchester coding example |_-|_-| (00) or |-_|-_| (11)
                        // bit is same as last bit
                        if (lastbit) {
                            SET_BIT_MSB(rx, *rxlen);
                        }
                        (*rxlen)++;
                    } else {
                        // Ignore weird value, is to small to mean anything
                        errorCount++;
                    }
                }

                // Handle SOF bits
                if (sof_received == false && *rxlen >= sof_bits) {
                    // Check if SOF is valid (all bits should be 1)
                    if ((rx[0] >> (8 - sof_bits)) != ((1 << sof_bits) - 1)) {
                        if (sof_bits == 4) {
                            sof_bits = 3;
                            // Hitag µ is LSB first 0b110
                            if ((rx[0] & 0xE0) != 0xC0) {
                                DBG Dbprintf("Warning, SOF is invalid rx[0]: 0x%02X", rx[0]);
                            }
                        } else {
                            DBG DbpString("Warning, not all bits of SOF are 1");
                        }
                    }

                    *rxlen -= sof_bits;
                    uint8_t tmp = rx[0];
                    rx[0] = 0x00;
                    for (size_t i = 0; i < *rxlen; i++) {
                        if (TEST_BIT_MSB(&tmp, sof_bits + i)) {
                            SET_BIT_MSB(rx, i);
                        }
                    }
                    // DBG Dbprintf("after sof_bits rxlen: %d rx[0]: 0x%02X", *rxlen, rx[0]);
                    sof_received = true;
                }
            }
        }

        // if we saw over 100 weird values break it probably isn't hitag...
        if (errorCount > 100 || (*rxlen) / 8 >= sizeofrx) {
            break;
        }

        // We can break this loop if we received the last bit from a frame
        // max periods between 2 falling edge
        // RTF AC64 |--__|--__| (00) 64 * T0
        // RTF MC32 |_-|-_|_-| (010) 48 * T0
        if (GetLoEdgeCaptureCount() > (T0 * 80)) {
            if (bStarted) {
                break;
            }
        }
    }

    DBG {
        Dbprintf("bStarted:%d bSkip:%d lastbit:%d sof_received:%d", bStarted, bSkip, lastbit, sof_received);
        Dbprintf("RX %i:%02X.. resptime:%i", *rxlen, rx[0], *resptime);
        Dbprintf("Edges count: %d, hex: ", rb_i);
        Dbhexdump(rb_i, edges, false);
    }
}

int hitag_reader_transfer(const uint8_t *tx, size_t txlen, uint8_t *rx, size_t sizeofrx, size_t *rxlen, int t_wait,
                          bool ledcontrol, hitag_mod_t modulation, uint8_t sof_bits, uint8_t send_sof) {
    uint32_t start_time = 0;

    DBG Dbprintf("tx %d bits:", txlen);
    DBG Dbhexdump((txlen + 7) / 8, tx, false);

    // Disable input capture to avoid triggers during our own modulation.
    StopLoEdgeCapture();

    // Wait for HITAG_T_WAIT_SC carrier periods after the last tag bit before transmitting,
    // Since the clock counts since the last falling edge, a 'one' means that the
    // falling edge occurred halfway the period. with respect to this falling edge,
    // we need to wait (T_Wait2 + half_tag_period) when the last was a 'one'.
    // All timer values are in terms of T0 units
    while (GetPrecisionCounter() < T0 * t_wait) {};

    start_time = TIMESTAMP;

    // Transmit the reader frame
    hitag_reader_send_frame(tx, txlen, ledcontrol, send_sof);

    // tearoff
    if (g_tearoff_enabled && tearoff_hook() == PM3_ETEAROFF) {
        return PM3_ETEAROFF;
    }

    LogTraceBits(tx, txlen, start_time, TIMESTAMP, true);

    // Enable and reset input capture for capturing the tag response.
    EnableLoEdgeCapture();

    hitag_reader_receive_frame(rx, sizeofrx, rxlen, &start_time, ledcontrol, modulation, sof_bits);

    DBG Dbprintf("rx %d bits:", *rxlen);
    DBG Dbhexdump((int)(*rxlen + 7) / 8, rx, false);

    // Check if frame was captured and store it
    if (*rxlen > 0) {
        DBG {
            uint8_t response_bit[sizeofrx * 8];

            for (size_t i = 0; i < *rxlen; i++) {
                response_bit[i] = (rx[i / 8] >> (7 - (i % 8))) & 1;
            }

            Dbprintf("ht?: rxlen...... %zu", *rxlen);
            Dbprintf("ht?: sizeofrx... %zu", sizeofrx);
            DbpString("ht?: response_bit:");
            Dbhexdump((int) *rxlen, response_bit, false);
        }

        LogTraceBits(rx, *rxlen, start_time, TIMESTAMP, false);
    }

    return PM3_SUCCESS;
}

// Tag functions - depends on modulation type
// Wait n carrier periods by counting SSC_CLK edges.  The FPGA drives ssp_clk from
// cross_lo, the carrier zero crossing, so this tracks the reader's clock instead of
// our own timer.  A real tag derives its bit timing from the field for the same
// reason: over a 37 bit answer even a small carrier offset accumulates into enough
// drift to corrupt the later bits.  Needs SSC_CLK configured as an input, see
// gpio_fpga_mod_feedback_setup().
static void hitag_wait_carrier(uint16_t periods) {
    while (periods--) {
        while (Gpio_SSC_CLK_Read() == false) { WDT_HIT(); }
        while (Gpio_SSC_CLK_Read() == true)  { WDT_HIT(); }
    }
}

// Manchester at 4 kbit/s, clocked off the carrier rather than the ARM timer.
//
// The sense matters: HT2 datasheet 3.3.1 says "The first bit of the transmitted
// data always starts with the Modulator ON (loaded) state", so a '1' begins
// loaded.  Loaded is DOUT *high* here - lo_edge_detect.v has
//     wire tag_modulation = ssp_dout & !lf_field;
//     assign pwr_oe2 = tag_modulation;  assign pwr_oe4 = tag_modulation;
// so in tag mode (lf_field 0) a high DOUT switches the load transistors on.
//
// Do not reach for the SHORT_COIL()/OPEN_COIL() macros in util.h here: they map
// SHORT_COIL to DOUT low, which is the opposite of what this FPGA mode does, and
// following their naming inverts the whole answer.
void hitag_tag_send_bit_mc4k_sync(int bit, bool ledcontrol) {
    if (ledcontrol) LED_A_ON();

    if (bit) {
        // loaded, then unloaded
        Gpio_SSC_DOUT_High();
        hitag_wait_carrier(16);
        Gpio_SSC_DOUT_Low();
        hitag_wait_carrier(16);
    } else {
        // unloaded, then loaded
        Gpio_SSC_DOUT_Low();
        hitag_wait_carrier(16);
        Gpio_SSC_DOUT_High();
        hitag_wait_carrier(16);
    }

    if (ledcontrol) LED_A_OFF();
}

// Carrier-synchronised frame send for the Hitag 2 simulator.
//
// One write per carrier period, latched right after the SSC_CLK edge, so the
// transitions land on carrier boundaries instead of wherever a polling loop
// happens to finish.  Levels are computed inline: a prebuilt sample buffer was
// tried, copying SimulateTagLowFrequencyEx() more literally, and it destabilised
// the device without improving the modulation.
//
// Manchester, 32 T0 per bit.  A '1' is loaded for the first half then unloaded,
// a '0' is the reverse; HT2 datasheet 3.3.1 requires the first bit to begin
// loaded.  Loaded is DOUT high: lo_edge_detect.v ties pwr_oe2/pwr_oe4 to
// ssp_dout, so a high DOUT switches the load transistors on.  Do not go by the
// SHORT_COIL/OPEN_COIL names in util.h, they read backwards for this FPGA mode.
//
// Every wait is bounded.  ssp_clk is the carrier zero crossing and stops dead
// when the reader's field goes away; an unbounded spin here wedges the device
// with no way back, since this loop cannot poll data_available() for `hw break`.
#define HITAG_CLK_WAIT_GUARD  20000


// Which SSC_DOUT level actually loads the coil.  lo_edge_detect.v ties
// pwr_oe2/pwr_oe4 straight to ssp_dout, so a high DOUT should mean loaded, but
// that is a reading of the verilog rather than a measurement - hence the switch.
static bool s_invert_mod = false;

// How many of the 16 carrier periods in a loaded half bit actually switch the
// coil load on.  16 is the real thing, a full-depth load; anything less trades
// depth for a smaller disturbance of our own receive path, which goes deaf for
// the length of the answer once its envelope follower has been slammed.
static uint8_t s_mod_duty = HITAG_T_TAG_HALF_PERIOD;

// TEMP: does the answer burst actually drive the coil?  Continuous toggling
// swings the reader's ADC rail to rail, so if a real answer does not, the send
// path is not doing what the diagnostic loop does.
uint32_t g_tx_samples, g_tx_bails, g_tx_frames;

// Edges the FPGA edge detector has handed us since the last reset.  Cheap to
// keep (one increment on a path that already runs per edge) and it settles the
// question the simulator kept raising: zero here means no signal is reaching us
// at all, so a run with no frames says nothing about the simulation itself.
uint32_t g_hitag_edges;

// TEMP INSTRUMENT: raw edge intervals (T0) of the most recent receive, kept so a
// caller can dump them *after* the exchange has finished.  Printing from inside
// the receive loop changes the timing it is meant to measure, so nothing here
// prints; it is a plain store on a path that already runs once per edge.
uint16_t g_hitag_rx_iv[HITAG_RX_IV_MAX];
uint16_t g_hitag_rx_it[HITAG_RX_IV_MAX];
uint32_t g_hitag_rx_iv_count;




void hitag_edges_reset(void) {
    g_hitag_edges = 0;
}



void hitag_tag_set_mod_polarity(bool invert) {
    s_invert_mod = invert;
}

void hitag_tag_set_mod_duty(uint8_t duty) {
    s_mod_duty = (duty == 0 || duty > HITAG_T_TAG_HALF_PERIOD) ? HITAG_T_TAG_HALF_PERIOD : duty;
}

// Hitag 2 public (read only) modes, HT2 datasheet rev 2.1 sections 4.2.3 and 4.2.4.
//
// Once the transponder has gone past t_WAIT START_AUTH without being addressed it
// stops behaving like a Hitag 2 and just talks: it "cyclically transmits page 4
// to page 7 in plain mode to the read/write device without a start sequence as
// long as the transponder is in the field".  So there is no SOF, no framing and
// no answer timing to hit - the caller loops over this and the only thing that
// matters is that the bit period is right and the code is right.
//
//   Public Mode A   Manchester  64 T0  2 kbit/s  pages 4,5    (emulates uEM H400x)
//   Public Mode B   Biphase     32 T0  4 kbit/s  pages 4..7   (ISO 11784/11785)
//   Public Mode C   Biphase     64 T0  2 kbit/s  pages 4..7   (emulates PCF793X)
//
// Manchester follows the same convention as the command mode answer above: a '1'
// loads the first half of the bit, a '0' the second.
//
// Biphase here is the differential code: the level always flips at a bit
// boundary, and a '0' flips again in the middle of the bit.  That is the ISO
// 11784/11785 convention, which is what Public Mode B claims compliance with, but
// the datasheet only draws it and the drawing does not survive text extraction -
// so if a reader decodes B or C inverted, this is the line to flip.
void hitag_tag_send_public(const uint8_t *frame, size_t frame_len, uint8_t period, bool biphase, bool ledcontrol) {

    if ((frame_len == 0) || (period == 0)) {
        return;
    }

    const uint8_t half = period / 2;
    const size_t total = frame_len * period;
    const uint8_t duty = (uint8_t)(((uint16_t)s_mod_duty * half) / HITAG_T_TAG_HALF_PERIOD);

    g_tx_frames++;

    if (ledcontrol) LED_A_ON();

    // Carries across bits, so a differential code stays differential from one
    // call to the next - the pages are sent back to back with no gap.
    static bool s_bp_level = false;

    const uint16_t t_frame = GetPrecisionCounterRaw();

    for (size_t sample = 0; sample < total; sample++) {

        const size_t idx = sample / period;
        const size_t phase = sample % period;
        const uint16_t deadline = (uint16_t)((sample + 1) * T0);

        const int bit = TEST_BIT_MSB(frame, idx);

        bool loaded;

        if (biphase) {
            // One flip at the boundary, a second mid bit for a '0'.
            if (phase == 0) {
                s_bp_level = !s_bp_level;
            } else if ((phase == half) && (bit == 0)) {
                s_bp_level = !s_bp_level;
            }
            loaded = s_bp_level;
        } else {
            loaded = bit ? (phase < half) : (phase >= half);
        }

        // Same shallow load knob the command mode answer uses, but scaled.
        //
        // s_mod_duty is expressed against the command mode answer's 16 T0 half
        // bit, and defaults to exactly that - full duty, clamp never fires.  The
        // 2 kbit/s public modes have a 32 T0 half bit, so applying it unscaled
        // loaded only the first half of every half bit and left the modulation
        // at half duty by accident.
        if (loaded && ((phase % half) >= duty)) {
            loaded = false;
        }

        // Same carrier-plus-deadline pacing as hitag_tag_send_frame_mc4k_sync():
        // wait on ssp_clk while it is healthy, fall through on the timer if it
        // drops out, so our own load modulation cannot stretch the bit rate.
        while (Gpio_SSC_CLK_Read() == false) {
            if (GetPrecisionCounterDelta(t_frame) >= deadline) {
                g_tx_bails++;
                break;
            }
        }

        g_tx_samples++;

        if (loaded != s_invert_mod) {
            Gpio_SSC_DOUT_High();
        } else {
            Gpio_SSC_DOUT_Low();
        }

        while (Gpio_SSC_CLK_Read() == true) {
            if (GetPrecisionCounterDelta(t_frame) >= deadline) {
                break;
            }
        }
    }

    // Deliberately no Gpio_SSC_DOUT_Low() here.  The public modes send the pages
    // "cyclically ... without a start sequence", so one pass runs straight into
    // the next; dropping the load between passes put a gap at the wrap and cost
    // the bit there.  Measured: the reader recovered the 64 bit pattern exactly
    // except for one undecodable Manchester pair per cycle, always at the wrap,
    // which was enough to stop lf em 410x demod parsing it.  The caller clears
    // DOUT once the whole loop ends.

    if (ledcontrol) LED_A_OFF();
}

void hitag_tag_send_frame_mc4k_sync(const uint8_t *frame, size_t frame_len, int sof_bits, bool ledcontrol) {

    const size_t nbits = (size_t)sof_bits + frame_len;

    const size_t total = nbits * HITAG_T_TAG_FULL_PERIOD;

    g_tx_frames++;

    if (ledcontrol) LED_A_ON();

    Gpio_SSC_DOUT_Low();

    // Time the frame against the free running counter as well as the carrier.
    //
    // Waiting only on ssp_clk feeds our own modulation back into our own bit
    // timing: loading the coil is what suppresses the carrier the zero crossing
    // detector is watching, so a sample whose edge is missed waits for the next
    // one and the frame stretches.  Measured against a Paxton reader, every
    // sample went out - 251008 for 212 frames, exactly 1184 each, no bails - yet
    // the answer took 1537 T0 instead of 1200, so 28% of samples cost an extra
    // carrier period and the Manchester rate fell from 4 kbit/s to 3.1.  A real
    // reader will not decode that, which is why nothing came back but polling.
    //
    // Each sample now also carries a deadline, one carrier period after the last,
    // measured from the start of the frame.  While the carrier is healthy its
    // edge arrives first and nothing changes; when it drops out we carry on from
    // the timer instead of waiting, so the frame can never run long.
    const uint16_t t_frame = GetPrecisionCounterRaw();

    for (size_t sample = 0; sample < total; sample++) {

        const size_t idx = sample / HITAG_T_TAG_FULL_PERIOD;
        const size_t phase = sample % HITAG_T_TAG_FULL_PERIOD;
        const uint16_t deadline = (uint16_t)((sample + 1) * T0);

        const int bit = (idx < (size_t)sof_bits)
                        ? 1
                        : TEST_BIT_MSB(frame, idx - (size_t)sof_bits);

        bool loaded = bit ? (phase < HITAG_T_TAG_HALF_PERIOD)
                          : (phase >= HITAG_T_TAG_HALF_PERIOD);

        // Shallower load: switch on for only the first s_mod_duty periods of the
        // loaded half bit.  The envelope the reader sees is a low pass of this,
        // so the Manchester transition is still there, just less deep.
        if (loaded && ((phase % HITAG_T_TAG_HALF_PERIOD) >= s_mod_duty)) {
            loaded = false;
        }

        bool lost_clock = false;

        while (Gpio_SSC_CLK_Read() == false) {
            if (GetPrecisionCounterDelta(t_frame) >= deadline) {
                lost_clock = true;
                break;
            }
        }
        if (lost_clock) {
            // The carrier did not come back in time.  Keep the frame on schedule
            // rather than abandoning it: a stretched answer is worse than one
            // sample placed by the timer.
            g_tx_bails++;
        }

        g_tx_samples++;

        if (loaded != s_invert_mod) {
            Gpio_SSC_DOUT_High();
        } else {
            Gpio_SSC_DOUT_Low();
        }

        while (Gpio_SSC_CLK_Read() == true) {
            if (GetPrecisionCounterDelta(t_frame) >= deadline) {
                break;
            }
        }
    }

    // TEMP EXPERIMENT: the trailing half-period hold is disabled.
    //
    // It was added so our own decoder had a closing edge for the last half bit.
    // A reader may instead see it as a surplus bit at the tail, which makes a
    // frame that lost its leading half bit come out at 37 bits with a true SOF of
    // 4 - and that is undecidable from the frame alone when the payload starts
    // with a 1.
    Gpio_SSC_DOUT_Low();

    if (ledcontrol) LED_A_OFF();
}

static void hitag_tag_send_bit(int bit, hitag_mod_t modulation, bool ledcontrol) {
    // Reset clock for the next bit
    ResetPrecisionCounter();

    if (ledcontrol) LED_A_ON();

    switch (modulation) {
        case AC2K: {
            if (bit == 0) {
                // AC Coding --__
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 32) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 64) {};
            } else {
                // AC coding -_-_
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 16) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 32) {};

                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 48) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 64) {};
            }
            break;
        }
        case AC4K: {
            if (bit == 0) {
                // AC Coding --__
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * HITAG_T_TAG_HALF_PERIOD) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * HITAG_T_TAG_FULL_PERIOD) {};
            } else {
                // AC coding -_-_
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 8) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 16) {};

                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 24) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 32) {};
            }
            break;
        }
        case MC4K: {
            if (bit == 0) {
                // Manchester: Unloaded, then loaded |__--|
                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 16) {};

                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 32) {};
            } else {
                // Manchester: Loaded, then unloaded |--__|
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 16) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 32) {};
            }
            break;
        }
        case MC8K: {
            if (bit == 0) {
                // Manchester: Unloaded, then loaded |__--|
                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 8) {};

                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 16) {};
            } else {
                // Manchester: Loaded, then unloaded |--__|
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 8) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 16) {};
            }
            break;
        }
    }

    if (ledcontrol) LED_A_OFF();
}

void hitag_tag_receive_frame_ex(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *start_time, bool ledcontrol, int *overflow, bool sof_is_bit) {
    uint8_t edges[160] = {0};
    uint32_t rb_i = 0;

    g_hitag_rx_iv_count = 0;

    // How many polls of this loop went by between one edge and the next.  A
    // merged interval with roughly twice the usual poll count means the loop kept
    // running and the edge detector simply never fired; the same poll count as a
    // single bit means we stalled and missed it.  One increment per iteration, so
    // it does not change what it measures.
    uint32_t it = 0;

    // Receive frame, watch for at most T0*EOF periods.
    //
    // StartLoEdgeCapture() clocks TC1 from MCK/32, not from the carrier, so the
    // counter free runs; what holds it down is the external trigger, which
    // resets it on every falling edge of SSC_FRAME.  When the edge detector has
    // no clean carrier to work with it fires continuously, the counter never
    // reaches the EOF limit, and without a bound this loop never returns - the
    // caller then never gets back to its data_available()/BUTTON_PRESS() check
    // and the device wedges with no way back short of a replug.  Returning early
    // with nothing received costs nothing, the simulator just listens again.
    // Has the opening gap of a frame been taken yet?  Only the very first edge
    // may be recovered from a rising event, see the comment further down.
    bool frame_open = false;

    uint32_t guard = HITAG_RX_IDLE_GUARD;
    while (GetLoEdgeCaptureCount() < T0 * HITAG_T_EOF) {

        it++;

        if (--guard == 0) {
            break;
        }
        if ((guard & 0x3FF) == 0) {
            WDT_HIT();
        }

        // Act on every falling edge, without demanding a rising edge in between.
        //
        // GetLoEdgeCaptureStatus() reads TC_SR once, which clears LDRAS and LDRBS
        // together and reports rising in preference, so when both edges land in
        // one poll the falling event is destroyed.  Tracking an expected edge and
        // skipping anything that did not match turned that single lost edge into
        // a permanent desync, discarding every later falling edge of the frame.
        lo_edge_t ev = GetLoEdgeCaptureStatus();

        // Recover the falling edge that opens a frame.
        //
        // GetLoEdgeCaptureStatus() reads TC_SR once, which clears LDRAS and
        // LDRBS together and reports rising in preference.  Inside a frame this
        // loop polls about four times per T0, so the two edges of a gap are seen
        // separately - but the frame's FIRST gap arrives while we are between
        // calls, waiting out the idle, and by the first poll both its falling and
        // its rising have landed.  Rising wins and the falling event is destroyed.
        //
        // Measured on this rig: the first event of every reader frame is a rising
        // edge carrying RA = 10 T0, which is the reader's t_low - proof that the
        // falling edge really happened one t_low earlier.  The next falling edge
        // is the SECOND gap, and its interval - the first bit's period - is then
        // swallowed by the idle carried in *overflow and read as the frame
        // opener.  The first bit was therefore never measured at all, and the
        // opener below fabricated it as '1'.  That is invisible for START_AUTH
        // (11000), for a password starting 0xB and for WRITE PAGE (0xA2), and it
        // stored 0x91223344 when the reader wrote 0x11223344.
        //
        // TC_RB still holds the destroyed edge's capture, so taking the rising
        // event as that falling edge recovers it exactly.  Only before the frame
        // has opened: once bits are arriving the polls are fast enough to see
        // both edges, and converting them there would double every gap.
        if ((ev == LO_EDGE_RISING) && (frame_open == false)) {
            ev = LO_EDGE_FALLING;
        }

        if (ev == LO_EDGE_FALLING) {

            // Retrieve the new timing values
            uint32_t rb = GetLoEdgeCaptureFalling() / T0 + *overflow;
            *overflow = 0;

            // Past this point the polls are fast enough to see both edges of a
            // gap, so no further rising event may be taken for a falling one.
            frame_open = true;

            g_hitag_edges++;

            if (rb_i < ARRAYLEN(edges)) {
                edges[rb_i++] = rb;
            }

            if (g_hitag_rx_iv_count < HITAG_RX_IV_MAX) {
                g_hitag_rx_it[g_hitag_rx_iv_count] = (it > 0xFFFF) ? 0xFFFF : (uint16_t)it;
                g_hitag_rx_iv[g_hitag_rx_iv_count++] = (rb > 0xFFFF) ? 0xFFFF : (uint16_t)rb;
            }
            it = 0;

            if (ledcontrol) LED_B_INV();

            // Capture reader cmd start timestamp
            if (*start_time == 0) {
                *start_time = TIMESTAMP - HITAG_T_LOW;
            }

            // Capture reader frame
            if (rb >= HITAG_T_STOP) {

                // Only an interval at the very start opens a frame.  One that
                // turns up mid frame is a dropped edge, not a boundary: two bit
                // periods merge into a single gap over HITAG_T_STOP.  Bailing out
                // there truncated the reader's 32 bit password to 6 bits, having
                // received textbook intervals up to that point (22 19 20 28 29 21).
                // Skip it and keep going; the frame still closes on the EOF
                // timeout, which is what actually delimits frames here.
                if (*rxlen != 0) {

                    // Recover the bits the merged gap swallowed.
                    //
                    // A dropped edge joins two or three bit periods into one gap.
                    // Skipping it, as this used to, throws those bits away - which
                    // is exactly why a 64 bit AUTH arrives as 61..63 and crypto
                    // never authenticates.  Measured intervals in a failing frame
                    // are textbook otherwise, 17..19 for '0' and 25..27 for '1',
                    // with a single oversized gap among them:
                    //
                    //     ... 17  71  25 27 ...   71 = 27+27+17, three bits
                    //     ... 17  49  20 19 ...   49 = two bits
                    //
                    // So decompose the gap into the run of nominal bit periods
                    // that best fits its length.  Where the fit is all-ones or
                    // all-zeroes the result is exact; a mixed run has an order
                    // this cannot know, and is emitted ones-first as a guess.  A
                    // wrong guess fails authentication exactly as the dropped
                    // bits already did, so this can only improve on discarding.
                    // Only inside a frame that already carries real content.
                    //
                    // Without this the rule fabricates bits out of noise: a stray
                    // edge opens a frame, the long gap that follows is "recovered"
                    // into two or three invented bits, and what should have been
                    // discarded becomes a 4 bit frame.  Measured against a Paxton,
                    // that cost the whole exchange - 69 fabricated 4 bit frames,
                    // not one password or read command answered, where the same
                    // build without the rule ran 206 passwords and 824 reads.
                    //
                    // A dropped edge only matters in the long frames it actually
                    // damages: the reader's shortest real command is 5 bits and
                    // the loss shows up around bit 40 of a 64 bit AUTH, so
                    // requiring a byte of frame first protects START_AUTH while
                    // leaving every frame the rule exists for untouched.
                    if (*rxlen < 8) {
                        continue;
                    }

                    uint32_t best_k = 0, best_ones = 0, best_err = 0xFFFFFFFF;
                    for (uint32_t k = 2; k <= 3; k++) {
                        for (uint32_t ones = 0; ones <= k; ones++) {
                            uint32_t sum = ones * HITAG_T_1_NOMINAL +
                                           (k - ones) * HITAG_T_0_NOMINAL;
                            uint32_t err = (rb > sum) ? (rb - sum) : (sum - rb);
                            if (err < best_err) {
                                best_err = err;
                                best_k = k;
                                best_ones = ones;
                            }
                        }
                    }

                    // Only act on a decomposition that actually fits; a gap that
                    // matches nothing is noise, and inventing bits from it would
                    // corrupt a frame that would otherwise merely be short.
                    if (best_err <= HITAG_T_SPLIT_TOL) {
                        for (uint32_t b = 0; b < best_k; b++) {
                            if ((*rxlen / 8) >= sizeofrx) {
                                break;
                            }
                            if (b < best_ones) {
                                SET_BIT_MSB(rx, *rxlen);
                            }
                            (*rxlen)++;
                        }
                    }
                    continue;
                }

                // The opening gap carries no bit, in any of the three protocols.
                //
                // A reader frame is N bit gaps followed by an EOF gap, so an N
                // bit frame is N+1 falling edges and N intervals between them:
                // the first interval is the first bit's period, and the gap that
                // opens the frame only starts the clock.  This used to count it
                // as a '1' for Hitag 2, which was a workaround for the lost
                // opening edge recovered above - with the edge back, doing so
                // would shift the whole frame by one bit.
                (void)sof_is_bit;
                *rxlen = 0;
            } else if (rb >= HITAG_T_1_MIN) {
                // '1' bit
                SET_BIT_MSB(rx, *rxlen);
                (*rxlen)++;
            } else if (rb >= HITAG_T_0_MIN) {
                // '0' bit
                // CLEAR_BIT_MSB(rx, *rxlen);
                (*rxlen)++;
            } else {
                // Ignore weird value, is too small to mean anything
            }
        }
    }

    if (ledcontrol) LED_B_OFF();

    DBG if (rb_i) {
        Dbprintf("RX %i bits.. start_time:%i edges:", *rxlen, *start_time);
        Dbhexdump(rb_i, edges, false);
    }

}

// Hitag S and u framing: the opening gap is a delimiter, not a bit
void hitag_tag_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *start_time, bool ledcontrol, int *overflow) {
    hitag_tag_receive_frame_ex(rx, sizeofrx, rxlen, start_time, ledcontrol, overflow, false);
}

void hitag_tag_send_frame_ex(const uint8_t *frame, size_t frame_len, int sof_bits, hitag_mod_t modulation, bool ledcontrol, bool lead_in) {
    // The beginning of the frame is hidden in some high level; pause until our bits will have an effect.
    // Hitag 2 does not want this: it starts modulating straight into the first SOF
    // bit from an unloaded line, and the lead-in would swallow that bit's rising
    // transition as well as prepending a burst that is not part of the Manchester.
    ResetPrecisionCounter();

    if (lead_in == false) {
        Gpio_SSC_DOUT_Low();
    } else {
        Gpio_SSC_DOUT_High();
    }

    if (lead_in)
    switch (modulation) {
        case AC4K:
        case MC8K: {
            while (GetPrecisionCounter() < T0 * 40) {}; // FADV
            break;
        }
        case AC2K:
        case MC4K: {
            while (GetPrecisionCounter() < T0 * 20) {}; // STD + ADV
            break;
        }
    }

    // SOF - send start of frame
    for (size_t i = 0; i < sof_bits; i++) {
        if (sof_bits == 4 && i == 3) {
            // Hitag µ SOF is 110
            hitag_tag_send_bit(0, modulation, ledcontrol);
            break;
        } else
            hitag_tag_send_bit(1, modulation, ledcontrol);
    }

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        hitag_tag_send_bit(TEST_BIT_MSB(frame, i), modulation, ledcontrol);
    }

    Gpio_SSC_DOUT_Low();
}

// Hitag S and u keep the lead-in
void hitag_tag_send_frame(const uint8_t *frame, size_t frame_len, int sof_bits, hitag_mod_t modulation, bool ledcontrol) {
    hitag_tag_send_frame_ex(frame, frame_len, sof_bits, modulation, ledcontrol, true);
}
