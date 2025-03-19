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
#define HITAG_T_STOP 36  /* T_EOF should be > 36 */
#define HITAG_T_CODE_VIOLATION 36 /* Hitag µ TFcv should be 34..38 */
#define HITAG_T_EOF 80         /* T_EOF should be > 36 */

#define HITAG_T_WAIT_RESP 200  /* T_wresp should be 204..212 */
#define HITAG_T_WAIT_SC 200    /* T_wsc should be 90..5000 */
#define HITAG_T_WAIT_FIRST 300 /* T_wfc should be 280..565 (T_ttf) */
#define HITAG_T_PROG_MAX 750   /* T_prog should be 716..726 */

#define HITAG_T_TAG_ONE_HALF_PERIOD 10
#define HITAG_T_TAG_TWO_HALF_PERIOD 25
#define HITAG_T_TAG_THREE_HALF_PERIOD 41
#define HITAG_T_TAG_FOUR_HALF_PERIOD 57

#define HITAG_T_TAG_HALF_PERIOD 16
#define HITAG_T_TAG_FULL_PERIOD 32

#define HITAG_T_TAG_CAPTURE_ONE_HALF 13
#define HITAG_T_TAG_CAPTURE_TWO_HALF 25
#define HITAG_T_TAG_CAPTURE_THREE_HALF 41
#define HITAG_T_TAG_CAPTURE_FOUR_HALF 57

extern uint16_t timestamp_high;
#define TIMESTAMP ( (AT91C_BASE_TC2->TC_SR & AT91C_TC_COVFS) ? timestamp_high += 1 : 0, ((timestamp_high << 16) + AT91C_BASE_TC2->TC_CV) / T0)

// Common hitag functions
void hitag_setup_fpga(uint16_t conf, uint8_t threshold, bool ledcontrol);
void hitag_cleanup(bool ledcontrol);
void hitag_reader_send_frame(const uint8_t *frame, size_t frame_len, bool ledcontrol, bool send_sof);
void hitag_reader_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *resptime, bool ledcontrol, MOD modulation,
                                int sof_bits);
void hitag_tag_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *start_time, bool ledcontrol, int *overflow);
void hitag_tag_send_frame(const uint8_t *frame, size_t frame_len, int sof_bits, MOD modulation, bool ledcontrol);

#endif
