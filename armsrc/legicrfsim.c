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

static uint8_t* legic_mem;      /* card memory, used for sim */
static legic_card_select_t card;/* metadata of currently selected card */
static crc_t legic_crc;

//-----------------------------------------------------------------------------
// Frame timing and pseudorandom number generator
//
// The Prng is forwarded every 99.1us (TAG_BIT_PERIOD), except when the reader is
// transmitting. In that case the prng has to be forwarded every bit transmitted:
//  - 31.3us for a 0 (RWD_TIME_0)
//  - 99.1us for a 1 (RWD_TIME_1)
//
// The data dependent timing makes writing comprehensible code significantly
// harder. The current aproach forwards the prng data based if there is data on
// air and time based, using GetCountSspClk(), during computational and wait
// periodes. SSP Clock is clocked by the FPGA at 212 kHz (subcarrier frequency).
//
// To not have the necessity to calculate/guess exection time dependend timeouts
// tx_frame and rx_frame use a shared timestamp to coordinate tx and rx timeslots.
//-----------------------------------------------------------------------------

static uint32_t last_frame_end; /* ts of last bit of previews rx or tx frame */

#define TAG_FRAME_WAIT       70 /* 330us from READER frame end to TAG frame start */
#define TAG_BIT_PERIOD       21 /* 99.1us */

#define RWD_TIME_PAUSE        4 /* 18.9us */
#define RWD_TIME_1           21 /* RWD_TIME_PAUSE 18.9us off + 80.2us on = 99.1us */
#define RWD_TIME_0           13 /* RWD_TIME_PAUSE 18.9us off + 42.4us on = 61.3us */
#define RWD_CMD_TIMEOUT      40 /* 40 * 99.1us (arbitrary value) */

//-----------------------------------------------------------------------------
// Legic Simulator
//-----------------------------------------------------------------------------

static int32_t init_card(uint8_t cardtype, legic_card_select_t *p_card) {
  p_card->tagtype = cardtype;

  switch(p_card->tagtype) {
    case 0:
      p_card->cmdsize = 6;
      p_card->addrsize = 5;
      p_card->cardsize = 22;
      break;
    case 1:
      p_card->cmdsize = 9;
      p_card->addrsize = 8;
      p_card->cardsize = 256;
      break;
    case 2:
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

static void init_tag() {
  // configure FPGA
  FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
  FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR
                  | FPGA_HF_SIMULATOR_MODULATE_212K);
  SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

  // configure SSC with defaults
  FpgaSetupSsc();

  // first pull output to low to prevent glitches then re-claim GPIO_SSC_DOUT
  LOW(GPIO_SSC_DOUT);
  AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
  AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;

  // reserve a cardmem, meaning we can use the tracelog function in bigbuff easier.
  legic_mem = BigBuf_get_EM_addr();

  // init crc calculator
  crc_init(&legic_crc, 4, 0x19 >> 1, 0x05, 0);

  // start 212kHz timer (running from SSP Clock)
  StartCountSspClk();
}

//-----------------------------------------------------------------------------
// Command Line Interface
//
// Only this function is public / called from appmain.c
//-----------------------------------------------------------------------------

void LegicRfSimulate(uint8_t cardtype) {
  // configure ARM and FPGA
  init_tag();

  // verify command line input
  if(init_card(cardtype, &card) != 0) {
    DbpString("Unknown tagtype.");
    goto OUT;
  }

  LED_A_ON();
  DbpString("Starting Legic emulator, press button to end");
  while(!BUTTON_PRESS()) {
    WDT_HIT();

    // init coordination timestamp
    last_frame_end = GetCountSspClk();

    // reset prng
    legic_prng_init(0);
  }

OUT:
  DbpString("Stopped");
  switch_off();
  StopTicks();
}
