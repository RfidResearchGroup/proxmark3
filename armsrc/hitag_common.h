#ifndef HITAG_COMMON_H
#define HITAG_COMMON_H

#include "hitag.h"

// Sam7s has several timers, we will use the source TIMER_CLOCK3 (aka AT91C_TC_CLKS_TIMER_DIV3_CLOCK)
// TIMER_CLOCK3 = MCK/32, MCK is running at 48 MHz, Timer is running at 48MHz/32 = 1500 KHz
// Hitag units (T0) have duration of 8 microseconds (us), which is 1/125000 per second (carrier)
// T0 = TIMER_CLOCK3 / 125000 = 12

#define T0 12

#define HITAG_FRAME_LEN 20

// TC0 and TC1 are 16-bit counters and will overflow after 5461 * T0
// Ensure not to set these timings above 5461 (~43ms) when comparing without considering overflow, as they will never reach that value.

#define HITAG_T_LOW 8    /* T_LOW should be 4..10 */
#define HITAG_T_0 20     /* T[0] should be 18..22 */
#define HITAG_T_1 28     /* T[1] should be 26..32 */
#define HITAG_T_0_MIN 15 /* T[0] should be 18..22 */
#define HITAG_T_1_MIN 25 /* T[1] should be 26..32 */
// A histogram taken during simulation put '1' intervals at 23..27 and suggested
// 22 here, but that sample was polluted by the simulator's own artifacts:
// against a genuine fob 22 fragmented the reader frames that 25 decodes
// cleanly.  Left at 25 until a histogram from a sniff-only run says otherwise.
#define HITAG_T_STOP 36  /* T_EOF should be > 36 */

/* Nominal reader bit periods, in T0, measured off a Paxton: '0' lands 17..19 and
 * '1' lands 25..27.  Used to decompose a gap that swallowed several bits when an
 * edge was dropped, and the tolerance is how far the best fit may miss. */
#define HITAG_T_0_NOMINAL 18
#define HITAG_T_1_NOMINAL 26
#define HITAG_T_SPLIT_TOL 4
#define HITAG_T_CODE_VIOLATION 36 /* Hitag µ TFcv should be 34..38 */
#define HITAG_T_EOF 80         /* T_EOF should be > 36 */

#define HITAG_T_WAIT_RESP 200  /* T_wresp should be 204..212 */
#define HITAG_T_WAIT_SC 200    /* T_wsc should be 90..5000 */
// hitagU requires at least 312.5 cycles; if it is less than or equal to 300, hitagU may not work properly on pm5.
#define HITAG_T_WAIT_FIRST 350 /* T_wfc should be 280..565 (T_ttf) */
#define HITAG_T_PROG_MAX 750   /* T_prog should be 716..726 */

#define HITAG_T_TAG_ONE_HALF_PERIOD 10
#define HITAG_T_TAG_TWO_HALF_PERIOD 25
#define HITAG_T_TAG_THREE_HALF_PERIOD 41
#define HITAG_T_TAG_FOUR_HALF_PERIOD 57

// Bound on the receive spin, see hitag_tag_receive_frame_ex().  The longest
// frame worth receiving is 64 bits of BPLM, about 2050 T0 or 16 ms, so the bound
// has to sit above that or real frames get cut short.  It also has to stay small
// enough that a vanished field still returns control promptly: at roughly ten
// cycles an iteration this is some tens of milliseconds, so `hw break` still
// answers quickly.  WDT_HIT() is deliberately NOT called every iteration - doing
// that made each idle pass take seconds and left the simulator deaf.
#define HITAG_RX_IDLE_GUARD   200000

#define HITAG_T_TAG_HALF_PERIOD 16
#define HITAG_T_TAG_FULL_PERIOD 32

#define HITAG_T_TAG_CAPTURE_ONE_HALF 13
#define HITAG_T_TAG_CAPTURE_TWO_HALF 25
#define HITAG_T_TAG_CAPTURE_THREE_HALF 41
#define HITAG_T_TAG_CAPTURE_FOUR_HALF 57

// Trace timestamp in T0 units, provided by the timers HAL (GetTimestamp).
#define TIMESTAMP GetTimestamp()

// Common hitag functions
void hitag_setup_fpga(uint16_t conf, uint8_t threshold, bool ledcontrol);
void hitag_cleanup(bool ledcontrol);
void hitag_reader_send_frame(const uint8_t *frame, size_t frame_len, bool ledcontrol, bool send_sof);
void hitag_reader_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *resptime, bool ledcontrol, hitag_mod_t modulation,
                                int sof_bits);
int hitag_reader_transfer(const uint8_t *tx, size_t txlen, uint8_t *rx, size_t sizeofrx, size_t *rxlen, int t_wait,
                          bool ledcontrol, hitag_mod_t modulation, uint8_t sof_bits, uint8_t send_sof);
void hitag_tag_receive_frame_ex(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *start_time,
                               bool ledcontrol, int *overflow, bool sof_is_bit);
void hitag_tag_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *start_time, bool ledcontrol, int *overflow);
void hitag_tag_send_bit_mc4k_sync(int bit, bool ledcontrol);
void hitag_tag_set_mod_polarity(bool invert);
void hitag_tag_set_mod_duty(uint8_t duty);
uint8_t hitag_autotune_threshold(void);
extern uint32_t g_hitag_edges;
extern uint32_t g_tx_samples, g_tx_bails, g_tx_frames;

// TEMP INSTRUMENT: raw edge intervals (T0) of the most recent receive.
#define HITAG_RX_IV_MAX 8
extern uint16_t g_hitag_rx_iv[HITAG_RX_IV_MAX];
extern uint16_t g_hitag_rx_it[HITAG_RX_IV_MAX];
extern uint32_t g_hitag_rx_iv_count;
void hitag_edges_reset(void);
void hitag_tag_send_frame_mc4k_sync(const uint8_t *frame, size_t frame_len, int sof_bits, bool ledcontrol);

// Hitag 2 public (read only) modes: one pass of a raw, unframed bit stream.
//
// `period` is the bit length in carrier periods - 32 for a 4 kbit/s mode, 64 for
// 2 kbit/s - and `biphase` picks the code.  There is no SOF and no framing: the
// public modes send the user pages back to back with no start sequence, so the
// caller simply calls this in a loop.
void hitag_tag_send_public(const uint8_t *frame, size_t frame_len, uint8_t period, bool biphase, bool ledcontrol);
void hitag_tag_send_frame_ex(const uint8_t *frame, size_t frame_len, int sof_bits,
                             hitag_mod_t modulation, bool ledcontrol, bool lead_in);
void hitag_tag_send_frame(const uint8_t *frame, size_t frame_len, int sof_bits, hitag_mod_t modulation, bool ledcontrol);

#endif
