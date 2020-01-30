//-----------------------------------------------------------------------------
// Christian Herrmann, 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for HID collector aka IceHID by Iceman
//-----------------------------------------------------------------------------
#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "lfops.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "printf.h"
#include "spiffs.h"
#include "ticks.h"

/*
 * `lf_hidcollect` sniffs after LF HID credentials, and stores them in internal
 * flash. It requires RDV4 hardware (for flash and battery).
 *
 * On entering stand-alone mode, this module will start reading/record HID credentials.
 * Every found / collected credential will be written/appended to the logfile in flash 
 * as a text string. 
 *
 * LEDs:
 * - LED A: reading / record
 * - LED B: writing to flash
 * - LED C: unmounting/sync'ing flash (normally < 100ms)
 *
 * To retrieve log file from flash:
 *
 * 1. mem spiffs dump o lf_hidcollect.log f lf_hidcollect.log
 *    Copies log file from flash to your PC.
 *
 * 2. exit the Proxmark3 client
 *
 * 3. more lf_hidcollect.log
 *
 * This module emits debug strings during normal operation -- so try it out in
 * the lab connected to PM3 client before taking it into the field.
 *
 * To delete the log file from flash: 
 * 
 * 1. mem spiffs remove lf_hidcollect.log
 */

#define LF_HIDCOLLECT_LOGFILE "lf_hidcollect.log"

void DownloadLogInstructions() {
    Dbprintf("");
    Dbprintf("[=] To get the logfile from flash and display it:");
    Dbprintf("[=] " _YELLOW_("1.") "mem spiffs dump o "LF_HIDCOLLECT_LOGFILE" f "LF_HIDCOLLECT_LOGFILE);
    Dbprintf("[=] " _YELLOW_("2.") "exit proxmark3 client");
    Dbprintf("[=] " _YELLOW_("3.") "cat "LF_HIDCOLLECT_LOGFILE);    
}

void ModInfo(void) {
    DbpString("  LF HID collector mode -  a.k.a IceHID (Iceman)");
}

void RunMod() {

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    StandAloneMode();
    Dbprintf("[=] LF HID collector a.k.a IceHID started");
  
    rdv40_spiffs_lazy_mount();
    
    bool log_exists = exists_in_spiffs(LF_HIDCOLLECT_LOGFILE);
    
    // the main loop for your standalone mode
    for (;;) {
        WDT_HIT();

        // exit from IceHID, send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(280);
        if (button_pressed == BUTTON_HOLD)
            break;

        LED_A_ON();    
        // findone, high, low,
        uint32_t hi = 0, lo = 0;
        CmdHIDdemodFSK(1, &hi, &lo, 0);

        LED_A_OFF();
        
        //didn't collect any, loop
        if (hi == 0 && lo == 0)
            continue;
        
        uint8_t entry[20];
        memset(entry, 0, sizeof(entry));
        sprintf((char *)entry, "%lx%08lx\n", hi, lo);

        LED_B_ON();
        if (!log_exists) {
            rdv40_spiffs_write(LF_HIDCOLLECT_LOGFILE, entry, sizeof(entry), RDV40_SPIFFS_SAFETY_SAFE);
            log_exists = true;
        } else {
            rdv40_spiffs_append(LF_HIDCOLLECT_LOGFILE, entry, sizeof(entry), RDV40_SPIFFS_SAFETY_SAFE);
        }
        LED_B_OFF();

        SpinErr(LED_A, 250, 2);
    }

    LED_C_ON();
    rdv40_spiffs_lazy_unmount();
    LED_C_OFF();

    SpinErr(LED_A, 200, 5);
    SpinDelay(100);
    
    LEDsoff();
    SpinDelay(300);  
    DownloadLogInstructions();
    
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
}
