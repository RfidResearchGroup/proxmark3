//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency HID commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include "proxmark3.h"
#include "ui.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmdlfhid.h"
#include "util.h"
#include "cmdmain.h"
#include "sleep.h"

static int CmdHelp(const char *Cmd);

int usage_lf_hid_wiegand(void){
  	PrintAndLog("Usage: lf hid wiegand [h] [OEM] [FC] [CN]");
	PrintAndLog("This command converts facility code/card number to Wiegand code");
	PrintAndLog("Options:");
	PrintAndLog("       h             - This help");
	PrintAndLog("       OEM           - OEM number");
	PrintAndLog("       FC            - facility code");
	PrintAndLog("       CN            - card number");
	PrintAndLog("Examples:");
	PrintAndLog("      lf hid wiegand 0 101 2001");
	return 0;
}
int usage_lf_hid_brute(void){
	PrintAndLog("Enables bruteforce of HID readers with specified facility code.");
	PrintAndLog("Different formatlength is supported");
	PrintAndLog("This is a incremental attack against reader.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf hid brute <format length> <facility code>");
	PrintAndLog("Options :");
	PrintAndLog("  <format length>	- 26|33|34|35|37|40|44|84");
	PrintAndLog("  <facility code>	- 8-bit value HID facility code");
	PrintAndLog("");
	PrintAndLog("Sample  : lf hid brute 26 224");
	return 0;
}
/*
int CmdHIDDemod(const char *Cmd)
{
  if (GraphTraceLen < 4800) {
    PrintAndLog("too short; need at least 4800 samples");
    return 0;
  }

  GraphTraceLen = 4800;
  for (int i = 0; i < GraphTraceLen; ++i) {
    if (GraphBuffer[i] < 0) {
      GraphBuffer[i] = 0;
    } else {
      GraphBuffer[i] = 1;
    }
  }
  RepaintGraphWindow();
  return 0;
}
*/
int CmdHIDDemodFSK(const char *Cmd) {
	int findone = ( Cmd[0] == '1' ) ? 1 : 0;
	UsbCommand c = {CMD_HID_DEMOD_FSK, {findone, 0 , 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdHIDSim(const char *Cmd) {
	unsigned int hi = 0, lo = 0;
	int n = 0, i = 0;

	while (sscanf(&Cmd[i++], "%1x", &n ) == 1) {
		hi = (hi << 4) | (lo >> 28);
		lo = (lo << 4) | (n & 0xf);
	}

	PrintAndLog("Emulating tag with ID %x%16x", hi, lo);
	PrintAndLog("Press pm3-button to abort simulation");

	UsbCommand c = {CMD_HID_SIM_TAG, {hi, lo, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdHIDClone(const char *Cmd) {
	unsigned int hi2 = 0, hi = 0, lo = 0;
	int n = 0, i = 0;
	UsbCommand c;

	if (strchr(Cmd,'l') != 0) {
		while (sscanf(&Cmd[i++], "%1x", &n ) == 1) {
			hi2 = (hi2 << 4) | (hi >> 28);
			hi = (hi << 4) | (lo >> 28);
			lo = (lo << 4) | (n & 0xf);
		}

		PrintAndLog("Cloning tag with long ID %x%08x%08x", hi2, hi, lo);

		c.d.asBytes[0] = 1;
	} else {
		while (sscanf(&Cmd[i++], "%1x", &n ) == 1) {
			hi = (hi << 4) | (lo >> 28);
			lo = (lo << 4) | (n & 0xf);
		}

		PrintAndLog("Cloning tag with ID %x%08x", hi, lo);

		hi2 = 0;
		c.d.asBytes[0] = 0;
	}

	c.cmd = CMD_HID_CLONE_TAG;
	c.arg[0] = hi2;
	c.arg[1] = hi;
	c.arg[2] = lo;

	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static void getParity26(uint32_t *hi, uint32_t *lo){
	uint32_t result = 0;
	int i;
	// even parity
	for (i = 24;i >= 13;i--)
		result ^= (*lo >> i) & 1;
	// even parity 26th bit
	*lo |= result << 25;

	// odd parity 
	result = 0;
	for (i = 12;i >= 1;i--)
		result ^= (*lo >> i) & 1;
	*lo |= !result;
}
static void getParity33(uint32_t *hi, uint32_t *lo){

}
static void getParity34(uint32_t *hi, uint32_t *lo){
	uint32_t result = 0;
	int i;

	// even parity 
	for (i = 7;i >= 0;i--)
		result ^= (*hi >> i) & i;
	for (i = 31;i >= 24;i--)
		result ^= (*lo >> i) & 1;

	*hi |= result << 2; 

	// odd parity bit
	result = 0;
	for (i = 23;i >= 1;i--)
		result ^= (*lo >> i) & 1;

	*lo |= !result;
}
static void getParity35(uint32_t *hi, uint32_t *lo){	
}
static void getParity37S(uint32_t *hi,uint32_t *lo){
	uint32_t result = 0;
	int i;

	// even parity
	for (i = 4; i >= 0; i--)
		result ^= (*hi >> i) & 1;
	
	for (i = 31; i >= 20; i--)
		result ^= (*lo >> i) & 1;

	*hi |= result;

	// odd parity
	result = 0;
	for (i = 19; i >= 1; i--)
		result ^= (*lo >> i) & 1;

	*lo |= result;
}
static void getParity37H(uint32_t *hi, uint32_t *lo){
	uint32_t result = 0;
	int i;

	// even parity
	for (i = 4;i >= 0;i--)
		result ^= (*hi >> i) & 1;
	for (i = 31;i >= 20;i--)
		result ^= (*lo >> i) & 1;
	*hi |= result << 4;

	// odd parity
	result = 0;
	for (i = 19;i >= 1;i--)
		result ^= (*lo >> i) & 1;
	*lo |= result;
}

static void calc26(uint16_t fc, uint32_t cardno, uint32_t *hi, uint32_t *lo){
   *lo = ((cardno & 0xFFFF) << 1) | ((fc & 0xFF) << 17) | (1 << 26);
   *hi = (1 << 5);
}
static void calc33(uint16_t fc, uint32_t cardno, uint32_t *hi, uint32_t *lo){

}
static void calc34(uint16_t fc, uint32_t cardno, uint32_t *hi, uint32_t *lo){
  // put card number first bit 1 .. 20 //
  *lo = ((cardno & 0X000F7FFF) << 1) | ((fc & 0XFFFF) << 17);
  // set bit format for less than 37 bit format
  *hi = (1 << 5) | (fc >> 15);
}
static void calc35(uint16_t fc, uint32_t cardno, uint32_t *hi, uint32_t *lo){
	*lo = ((cardno & 0xFFFFF) << 1) | fc << 21; 
	*hi = (1 << 5) | ((fc >> 11) & 1);  
}
static void calc37S(uint16_t fc, uint32_t cardno, uint32_t *hi, uint32_t *lo){
	// FC 2 - 17   - 16 bit  
	// cardno 18 - 36  - 19 bit
	// Even P1   1 - 19
	// Odd  P37  19 - 36

	fc = fc & 0xFFFF;
	*lo = ((fc << 20) | (cardno & 0x7FFFF) << 1);
	*hi = (fc >> 12);
}
static void calc37H(uint64_t cardno, uint32_t *hi, uint32_t *lo){
	// SC NONE
	// cardno 1-35 34 bits 
	// Even Parity  0th bit  1-18
	// Odd  Parity 36th bit 19-35
	cardno = (cardno & 0x00000003FFFFFFFF);
	*lo = (cardno << 1);
	*hi = (cardno >> 31);
}
static void calc40(uint64_t cardno, uint32_t *hi, uint32_t *lo){
	cardno = (cardno & 0xFFFFFFFFFF);
	*lo = ((cardno & 0xFFFFFFFF) << 1 ); 
	*hi = (cardno >> 31);  
}

static void calcWiegand(uint8_t fmtlen, uint16_t fc, uint64_t cardno, uint32_t *hi, uint32_t *lo){

	uint32_t cn = (cardno & 0xFFFFFFFF);
	switch ( fmtlen ) {
		case 26 : {			
			calc26(fc, cn, hi, lo);
			getParity26(hi, lo);		
			break;
		}
		case 33 : { 
 			calc33(fc, cn, hi, lo);
			getParity33(hi, lo);	
			break;
		}
		case 34 : {
 			calc34(fc, cn, hi, lo);
			getParity34(hi, lo);		
			break;
		}
		case 35 : {
			calc35(fc, cn, hi, lo);
			getParity35(hi, lo);
			break;
		}
		case 37 : {
			calc37S(fc, cn, hi, lo);
			getParity37S(hi, lo);
			break;
		}
		case 38 : { 
			calc37H(cn, hi, lo);
			getParity37H(hi, lo);
			break;
		}
		case 40 : calc40(cardno, hi, lo);	break;
		case 44 : { break; }
		case 84 : { break; }
	}
}	

int CmdHIDWiegand(const char *Cmd) {
	uint32_t oem;
	uint32_t fc, lo = 0, hi = 0;
	uint64_t cardnum = 0;
	
	uint8_t ctmp = param_getchar(Cmd, 0);
	if ( strlen(Cmd) == 0 || strlen(Cmd) < 3 || ctmp == 'H' || ctmp == 'h' ) return usage_lf_hid_wiegand();

	oem = param_get8(Cmd, 0);
	fc = param_get32ex(Cmd, 1, 0, 10);
	cardnum = param_get64ex(Cmd, 2, 0, 10);

	uint8_t ftmlen[] = {26,33,34,35,37,38,40};
	for (uint8_t i = 0; i < sizeof(ftmlen); i++){
		calcWiegand( ftmlen[i], fc, cardnum, &hi, &lo);
		PrintAndLog("HID %d bit | OEM: %d FC: %d CN: %llu | Wiegand code: %08X%08X", ftmlen[i], oem, fc, cardnum, hi, lo);
	}
	return 0;
}

int CmdHIDBrute(const char *Cmd){
	
	bool error = TRUE;
	uint8_t fc = 0, fmtlen = 0;
	uint32_t hi = 0, lo = 0;

	UsbCommand c = {CMD_HID_SIM_TAG, {0, 0, 0}};  
	
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 2 || strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_hid_brute();

	fmtlen = param_get8(Cmd, 0);
	uint8_t ftms[] = {26,33,34,35,37};
	for ( uint8_t i = 0; i < sizeof(ftms); i++){
		if ( ftms[i] == fmtlen ) {
			error = FALSE;
		}
	}

	if ( error ) return usage_lf_hid_brute();
	
  	fc =  param_get8(Cmd, 1);
	if ( fc == 0) return usage_lf_hid_brute();
	
	PrintAndLog("Brute-forcing HID reader");
	PrintAndLog("Press pm3-button to abort simulation or run another command");

	for ( uint16_t cn = 1; cn < 0xFFFF; ++cn){
		if (ukbhit()) {
			PrintAndLog("aborted via keyboard!");
			c.cmd = CMD_PING;
			c.arg[0] = 0x00;
			c.arg[1] = 0x00;
			c.arg[2] = 0x00;
			clearCommandBuffer();
			SendCommand(&c);
			return 1;
		}

		calcWiegand( fmtlen, fc, cn, &hi, &lo);

		c.arg[0] = hi;
		c.arg[1] = lo;		
		clearCommandBuffer();
		SendCommand(&c);
		
		PrintAndLog("Trying FC: %u; CN: %u", fc, cn);
		// pause
		sleep(1);
	}
	return 0;
}

static command_t CommandTable[] = {
	{"help",    CmdHelp,        1, "This help"},
// 	{"demod",   CmdHIDDemod,    1, "Demodulate HID Prox Card II (not optimal)"},
	{"fskdemod",CmdHIDDemodFSK, 0, "['1'] Realtime HID FSK demodulator (option '1' for one tag only)"},
	{"sim",     CmdHIDSim,      0, "<ID> -- HID tag simulator"},
	{"clone",   CmdHIDClone,    0, "<ID> ['l'] -- Clone HID to T55x7 (tag must be in antenna)(option 'l' for 84bit ID)"},
	{"wiegand", CmdHIDWiegand,  0, "<OEM> <facility code> <card number> -- convert facility code/card number to Wiegand code"},
	{"brute",   CmdHIDBrute, 0, "<format length> <facility code> -- brute force card number"},
	{NULL, NULL, 0, NULL}
};

int CmdLFHID(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
