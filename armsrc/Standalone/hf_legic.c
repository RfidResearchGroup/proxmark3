//-----------------------------------------------------------------------------
// Stefanie Hofmann, 2020
// Uli Heilmeier, 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for Legic Prime read/sim
//-----------------------------------------------------------------------------
#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"

#include "legicrf.h"
#include "legicrfsim.h"

void ModInfo(void) {
  DbpString("  HF Legic Prime standalone  ");
}

// Searching for Legic card until found and read.
// Simulating recorded Legic Prime card.
// C = Searching
// A, B, C = Reading
// A, D = Simulating

void RunMod(){
  StandAloneMode();
  FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
  Dbprintf(">>  HF Legic Prime Read/Simulate Started  <<");

  int read_success;
  for(;;){
    WDT_HIT();

    //exit from hf_legic,  send usbcommand
    if(data_available()) break;

    //Was our button held down or pressed?
    int button_pressed = BUTTON_HELD(280);
    if(button_pressed != BUTTON_HOLD) continue;

    LED_A_OFF();
    LED_B_OFF();
    LED_C_ON();
    LED_D_OFF();

    WAIT_BUTTON_RELEASED();

    //record
    DbpString("[=] start recording");

    //search for legic card until reading successfull or button pressed
    do{
      LED_C_ON();
      SpinDelay(1000);
      // We don't care if we read a MIM256, MIM512 or MIM1024
      // we just read 1024 bytes
      LegicRfReader(0, 1024, 0x55);
      read_success = check_success();
      }while(read_success == 0 && !BUTTON_PRESS());

    //simulate if read successfully
    if(read_success == 1){
      LED_A_OFF();
      LED_B_OFF();
      LED_C_OFF();
      LED_D_ON();
      // The read data is migrated to a MIM1024 card
      LegicRfSimulate(2);
    }else{
      LEDsoff();
      WAIT_BUTTON_RELEASED();
    }
  }
}
