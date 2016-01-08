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

static int CmdHelp(const char *Cmd);

int usage_hid_wiegand(){
  	PrintAndLog("Usage: lf hid wiegand [h] [formatlenght] [oem] [FacilityCode] [cardnumber]");
	PrintAndLog("This command converts FC/Cardnum to wiegand code");
	PrintAndLog("Options:");
	PrintAndLog("       h			- This help");
	PrintAndLog("       formatlen	- Format length,  26|34|35|37|44|84");
	PrintAndLog("       oem			- Oem number");
	PrintAndLog("       facilitynum	- Facility number");
	PrintAndLog("       cardnum		- Card number");
	PrintAndLog("Examples:");
	PrintAndLog("      lf hid wiegand 26 0 304 2001");
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
int CmdHIDDemodFSK(const char *Cmd)
{
	int findone = ( Cmd[0] == '1' ) ? 1 : 0;
	UsbCommand c = {CMD_HID_DEMOD_FSK, {findone, 0 , 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdHIDSim(const char *Cmd)
{
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

int CmdHIDClone(const char *Cmd)
{
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
	*hi = *hi;
}
static void getParity37S(uint32_t *hi,uint32_t *lo){
	uint32_t result = 0;
	uint8_t i;

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
static void calc37S(uint16_t sc, uint32_t cn, uint32_t *hi, uint32_t *lo){
	// SC 2 - 17   - 16 bit  
	// CN 18 - 36  - 19 bit
	// Even P1   1 - 19
	// Odd  P37  19 - 36

	sc = sc & 0xFFFF;
	*lo = ( (sc << 20) | (cn & 0x7FFFF) << 1);
	*hi = (sc >> 12);
}
static void calc37H(uint64_t cn, uint32_t *hi, uint32_t *lo){
	// SC NONE
	// CN 1-35 34 bits 
	// Even Parity  0th bit  1-18
	// Odd  Parity 36th bit 19-35
	cn = (cn & 0x00000003FFFFFFFF);
	*lo = (cn << 1);
	*hi = (cn >> 31);
}
static void calc40(uint64_t cn, uint32_t *hi, uint32_t *lo){
	cn = (cn & 0xFFFFFFFFFF);
	*lo = (uint32_t)((cn & 0xFFFFFFFF) << 1 ); 
	*hi = (uint32_t) (cn >> 31);  
}

int CmdHIDWiegand(const char *Cmd)
{
	uint32_t oem;
	uint32_t fmtlen = 0;
	uint32_t fc, lo = 0, hi = 0;
	uint64_t cn = 0;
	uint32_t cardnum = 0;
	
	//uint32_t temp, p
	uint8_t ctmp = param_getchar(Cmd, 0);
	if ( strlen(Cmd) < 0 || strlen(Cmd) < 4 || ctmp == 'H' || ctmp == 'h' ) return usage_hid_wiegand();

	fmtlen = param_get8(Cmd, 0);	
	oem = param_get8(Cmd, 1);
	fc = param_get32ex(Cmd, 2, 0, 10);
	cn = param_get64ex(Cmd, 3, 0, 10);

	switch ( fmtlen ) {
		case 26 : {
			cardnum = (cn & 0xFFFFFFFF);
			calc26(fc, cardnum, &hi, &lo);
			getParity26(&hi, &lo);		
			break;
		}
		case 34 : {
			cardnum = (cn & 0xFFFFFFFF);
 			calc34(fc, cardnum, &hi, &lo);
			getParity34(&hi, &lo);		
			break;
		}
		case 35 : {
			cardnum = (cn & 0xFFFFFFFF);
			calc35(fc, cardnum, &hi, &lo);
			getParity35(&hi, &lo);
			break;
		}
		case 37 : {
			cardnum = (cn & 0xFFFFFFFF);
			calc37S(fc, cardnum, &hi, &lo);
			getParity37S(&hi, &lo);
			break;
		}
		case 38 : { 
			cardnum = (cn & 0xFFFFFFFF);
			calc37H(cardnum, &hi, &lo);
			getParity37H(&hi, &lo);
			break;
		}
		case 40 : {
			calc40(cn, &hi, &lo);
			PrintAndLog("%x  %x", hi, lo);
			break;
		}
		case 44 : { break; }
		case 84 : { break; }
	}
	PrintAndLog("HID %d bit | FC: %d CN: %d | Wiegand Code: %08X%08X", fmtlen, fc, cn, hi, lo);
	return 0;
}

static command_t CommandTable[] = {
	{"help",      CmdHelp,        1, "This help"},
	//{"demod",     CmdHIDDemod,    1, "Demodulate HID Prox Card II (not optimal)"},
	{"fskdemod",  CmdHIDDemodFSK, 0, "['1'] Realtime HID FSK demodulator (option '1' for one tag only)"},
	{"sim",       CmdHIDSim,      0, "<ID> -- HID tag simulator"},
	{"clone",     CmdHIDClone,    0, "<ID> ['l'] -- Clone HID to T55x7 (tag must be in antenna)(option 'l' for 84bit ID)"},
	{"wiegand",  CmdHIDWiegand,  1, "<oem> <fmtlen> <fc> <cardnum> -- convert facilitycode, cardnumber to Wiegand code"},
	{NULL, NULL, 0, NULL}
};

int CmdLFHID(const char *Cmd) {
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
