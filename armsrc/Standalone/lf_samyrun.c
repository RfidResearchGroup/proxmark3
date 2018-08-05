//-----------------------------------------------------------------------------
// Samy Kamkar, 2012
// Christian Herrmann, 2017
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for LF aka SamyRun by Samy Kamkar 
//-----------------------------------------------------------------------------
#include "lf_samyrun.h"

// samy's sniff and repeat routine for LF
void RunMod() {
	StandAloneMode();
	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

	uint32_t high[OPTS], low[OPTS];
	int selected = 0;
	int playing = 0;
	int cardRead = 0;

	// Turn on selected LED
	LED(selected + 1, 0);

	for (;;) {		
		WDT_HIT();
		
		// exit from SamyRun,   send a usbcommand.
		if (usb_poll_validate_length()) break;

		// Was our button held down or pressed?
		int button_pressed = BUTTON_HELD(1000);
		//SpinDelay(300);

		// Button was held for a second, begin recording
		if (button_pressed > 0 && cardRead == 0) {
			LEDsoff();
			LED(selected + 1, 0);
			LED(LED_RED2, 0);

			// record
			DbpString("[+] starting recording");

			// wait for button to be released
			while (BUTTON_PRESS())
				WDT_HIT();

			/* need this delay to prevent catching some weird data */
			SpinDelay(500);

			CmdHIDdemodFSK(1, &high[selected], &low[selected], 0);
			Dbprintf("[+] recorded %x %x %08x", selected, high[selected], low[selected]);

			LEDsoff();
			LED(selected + 1, 0);
			// Finished recording
			// If we were previously playing, set playing off
			// so next button push begins playing what we recorded
			playing = 0;			
			cardRead = 1;	
		}
		else if (button_pressed > 0 && cardRead == 1) {
			LEDsoff();
			LED(selected + 1, 0);
			LED(LED_ORANGE, 0);

			// record
			Dbprintf("[+] cloning %x %x %08x", selected, high[selected], low[selected]);

			// wait for button to be released
			while (BUTTON_PRESS())
				WDT_HIT();

			/* need this delay to prevent catching some weird data */
			SpinDelay(500);

			CopyHIDtoT55x7(0, high[selected], low[selected], 0);
			Dbprintf("[+] cloned %x %x %08x", selected, high[selected], low[selected]);

			LEDsoff();
			LED(selected + 1, 0);
			// Finished recording

			// If we were previously playing, set playing off
			// so next button push begins playing what we recorded
			playing = 0;			
			cardRead = 0;			
		}

		// Change where to record (or begin playing)
		else if (button_pressed) {
			// Next option if we were previously playing
			if (playing)
				selected = (selected + 1) % OPTS;
			playing = !playing;

			LEDsoff();
			LED(selected + 1, 0);

			// Begin transmitting
			if (playing) {
				LED(LED_GREEN, 0);
				DbpString("[+] playing");
				// wait for button to be released
				while (BUTTON_PRESS())
					WDT_HIT();
				
				Dbprintf("[+] %x %x %08x", selected, high[selected], low[selected]);
				CmdHIDsimTAG(high[selected], low[selected], false);		
				DbpString("[+] done playing");
				
				if (BUTTON_HELD(1000) > 0) {
					DbpString("[+] exiting");
					LEDsoff();
					return;
				}

				/* We pressed a button so ignore it here with a delay */
				SpinDelay(300);

				// when done, we're done playing, move to next option
				selected = (selected + 1) % OPTS;
				playing = !playing;
				LEDsoff();
				LED(selected + 1, 0);
			}
			else {
				while (BUTTON_PRESS())
					WDT_HIT();
			}
		}
	}
}