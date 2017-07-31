//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Farpoint G Prox II / Pyramid tag commands
// Biphase, rf/ , 96 bits  (unknown key calc + some bits)
//-----------------------------------------------------------------------------
#include "cmdlfguard.h"

static int CmdHelp(const char *Cmd);

int usage_lf_guard_clone(void){
	PrintAndLog("clone a Guardall tag to a T55x7 tag.");
	PrintAndLog("The facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated. ");
	PrintAndLog("Currently work only on 26bit");
	PrintAndLog("");
	PrintAndLog("Usage: lf guard clone <format> <Facility-Code> <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("         <format> :  format length 26|32|36|40");	
	PrintAndLog("  <Facility-Code> :  8-bit value facility code");
	PrintAndLog("  <Card Number>   : 16-bit value card number");
	PrintAndLog("");
	PrintAndLog("Sample  : lf guard clone 26 123 11223");
	return 0;
}

int usage_lf_guard_sim(void) {
	PrintAndLog("Enables simulation of Guardall card with specified card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("The facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
	PrintAndLog("Currently work only on 26bit");
	PrintAndLog("");
	PrintAndLog("Usage:  lf guard sim <format> <Facility-Code> <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("         <format> :  format length 26|32|36|40");	
	PrintAndLog("  <Facility-Code> :  8-bit value facility code");
	PrintAndLog("  <Card Number>   : 16-bit value card number");
	PrintAndLog("");
	PrintAndLog("Sample  : lf guard sim 26 123 11223");
	return 0;
}

// Works for 26bits.
int GetGuardBits(uint8_t fmtlen, uint32_t fc, uint32_t cn, uint8_t *guardBits) {
  
	uint8_t xorKey = 0x66;
	uint8_t i;
	uint8_t pre[96];
	uint8_t rawbytes[12];
	memset(pre, 0x00, sizeof(pre));
	memset(rawbytes, 0x00, sizeof(rawbytes));	

	// add format length (decimal)
	switch (fmtlen) {
		case 32: {
			rawbytes[1] = (32 << 2);
			
			break;
		}
		case 36: {
			// FC = ((ByteStream[3] & 0x7F)<<7) | (ByteStream[4]>>1);
			// Card = ((ByteStream[4]&1)<<19) | (ByteStream[5]<<11) | (ByteStream[6]<<3) | (ByteStream[7]>>5);
			rawbytes[1] = (36 << 2);
			// Get 26 wiegand from FacilityCode, CardNumber	
			uint8_t wiegand[34];
			memset(wiegand, 0x00, sizeof(wiegand));
			num_to_bytebits(fc, 8, wiegand);
			num_to_bytebits(cn, 26, wiegand+8);

			// add wiegand parity bits (dest, source, len)
			wiegand_add_parity(pre, wiegand, 34);			
			break;
		}
		case 40: {
			rawbytes[1] = (40 << 2);
			break;
		}
		case 26:
		default: {
			rawbytes[1] = (26 << 2);
			// Get 26 wiegand from FacilityCode, CardNumber	
			uint8_t wiegand[24];
			memset(wiegand, 0x00, sizeof(wiegand));
			num_to_bytebits(fc, 8, wiegand);
			num_to_bytebits(cn, 16, wiegand+8);

			// add wiegand parity bits (dest, source, len)
			wiegand_add_parity(pre, wiegand, 24);
			break;
		}
	}
	// 2bit checksum, unknown today, 
	// these two bits are the last ones of rawbyte[1], hence the LSHIFT above.

	
	// xor key
	rawbytes[0] = xorKey;
	
	rawbytes[2] = 1;
	rawbytes[3] = 0;
	
	// add wiegand to rawbytes
	for (i = 0; i < 4; ++i)
		rawbytes[i+4] = bytebits_to_byte( pre + (i*8), 8);
	
	if (g_debugMode) printf(" WIE | %s\n", sprint_hex(rawbytes, sizeof(rawbytes)));	
	
	
	// XOR (only works on wiegand stuff)
	for (i = 1; i < 12; ++i)
		rawbytes[i] ^= xorKey ;
	
	if (g_debugMode) printf(" XOR | %s \n", sprint_hex(rawbytes, sizeof(rawbytes)));

	// convert rawbytes to bits in pre
	for (i = 0; i < 12; ++i)
		num_to_bytebitsLSBF( rawbytes[i], 8, pre + (i*8));

	if (g_debugMode) printf("\n Raw | %s \n", sprint_hex(rawbytes, sizeof(rawbytes)));
	if (g_debugMode) printf(" Raw | %s\n", sprint_bin(pre, 64) );
	
	// add spacer bit 0 every 4 bits, starting with index 0,
	// 12 bytes, 24 nibbles.  24+1 extra bites. 3bytes.  ie 9bytes | 1byte xorkey, 8bytes rawdata (64bits, should be enough for a 40bit wiegand)
	addParity(pre, guardBits+6, 64, 5, 3);

	// preamble
	guardBits[0] = 1;
	guardBits[1] = 1;
	guardBits[2] = 1;
	guardBits[3] = 1;
	guardBits[4] = 1;
	guardBits[5] = 0;
	
	if (g_debugMode) printf(" FIN | %s\n", sprint_bin(guardBits, 96) );
	return 1;
}

// by marshmellow
// demod gProxIIDemod 
// error returns as -x 
// success returns start position in BitStream
// BitStream must contain previously askrawdemod and biphasedemoded data
int detectGProxII(uint8_t BitStream[], size_t *size) {
	size_t startIdx=0;
	uint8_t preamble[] = {1,1,1,1,1,0};

	if (!preambleSearch(BitStream, preamble, sizeof(preamble), size, &startIdx)) 
		return -3; //preamble not found

	if (*size != 96) return -2; //should have found 96 bits
	
	//check first 6 spacer bits to verify format
	if (!BitStream[startIdx+5] && !BitStream[startIdx+10] && !BitStream[startIdx+15] && !BitStream[startIdx+20] && !BitStream[startIdx+25] && !BitStream[startIdx+30]){
		//confirmed proper separator bits found
		//return start position
		return (int) startIdx;
	}
	return -5; //spacer bits not found - not a valid gproxII
}

//by marshmellow
//attempts to demodulate and identify a G_Prox_II verex/chubb card
//WARNING: if it fails during some points it will destroy the DemodBuffer data
// but will leave the GraphBuffer intact.
//if successful it will push askraw data back to demod buffer ready for emulation
int CmdGuardDemod(const char *Cmd) {
	if (!ASKbiphaseDemod(Cmd, false)){
		if (g_debugMode) PrintAndLog("DEBUG: Error - gProxII ASKbiphaseDemod failed 1st try");
		return 0;
	}
	size_t size = DemodBufferLen;
	//call lfdemod.c demod for gProxII
	int ans = detectGProxII(DemodBuffer, &size);
	if (ans < 0){
		if (g_debugMode) PrintAndLog("DEBUG: Error - gProxII demod");
		return 0;
	}
	//got a good demod of 96 bits
	uint8_t ByteStream[8] = {0x00};
	uint8_t xorKey = 0;
	size_t startIdx = ans + 6; //start after 6 bit preamble

	uint8_t bits_no_spacer[90];
	//so as to not mess with raw DemodBuffer copy to a new sample array
	memcpy(bits_no_spacer, DemodBuffer + startIdx, 90);
	// remove the 18 (90/5=18) parity bits (down to 72 bits (96-6-18=72))
	size_t bitLen = removeParity(bits_no_spacer, 0, 5, 3, 90); //source, startloc, paritylen, ptype, length_to_run
	if (bitLen != 72) {
		if (g_debugMode) 
			PrintAndLog("DEBUG: Error - gProxII spacer removal did not produce 72 bits: %u, start: %u", bitLen, startIdx);
		return 0;
	}
	// get key and then get all 8 bytes of payload decoded
	xorKey = (uint8_t)bytebits_to_byteLSBF(bits_no_spacer, 8);
	for (size_t idx = 0; idx < 8; idx++) {
		ByteStream[idx] = ((uint8_t)bytebits_to_byteLSBF(bits_no_spacer+8 + (idx*8),8)) ^ xorKey;
		if (g_debugMode) PrintAndLog("DEBUG: gProxII byte %u after xor: %02x", (unsigned int)idx, ByteStream[idx]);
	}
	
	//ByteStream contains 8 Bytes (64 bits) of decrypted raw tag data
	uint8_t fmtLen = ByteStream[0]>>2;
	uint32_t FC = 0;
	uint32_t Card = 0;
	//get raw 96 bits to print
	uint32_t raw1 = bytebits_to_byte(DemodBuffer+ans,32);
	uint32_t raw2 = bytebits_to_byte(DemodBuffer+ans+32, 32);
	uint32_t raw3 = bytebits_to_byte(DemodBuffer+ans+64, 32);
	bool unknown = false;
	switch(fmtLen) {
		case 36:
			FC = ((ByteStream[3] & 0x7F)<<7) | (ByteStream[4]>>1);
			Card = ((ByteStream[4]&1)<<19) | (ByteStream[5]<<11) | (ByteStream[6]<<3) | (ByteStream[7]>>5);
			break;
		case 26: 
			FC = ((ByteStream[3] & 0x7F)<<1) | (ByteStream[4]>>7);
			Card = ((ByteStream[4]&0x7F)<<9) | (ByteStream[5]<<1) | (ByteStream[6]>>7);
			break;
		default :
			unknown = true;
			break;
	}
	if ( !unknown)
		PrintAndLog("G-Prox-II Found: Format Len: %ubit - FC: %u - Card: %u, Raw: %08x%08x%08x", fmtLen, FC, Card, raw1, raw2, raw3);
	else
		PrintAndLog("Unknown G-Prox-II Fmt Found: Format Len: %u, Raw: %08x%08x%08x", fmtLen, raw1, raw2, raw3);

	setDemodBuf(DemodBuffer, 96, ans);
	setClockGrid(g_DemodClock, g_DemodStartIdx + (ans*g_DemodClock));
	return 1;
}

int CmdGuardRead(const char *Cmd) {
	lf_read(true, 10000);
	return CmdGuardDemod(Cmd);
}

int CmdGuardClone(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_guard_clone();

	uint32_t facilitycode = 0, cardnumber = 0, fc = 0, cn = 0, fmtlen = 0;
	uint8_t i;
	uint8_t bs[96];
	memset(bs, 0x00, sizeof(bs));
	
	//GuardProxII - compat mode, ASK/Biphase,  data rate 64, 3 data blocks
	uint32_t blocks[5] = {T55x7_MODULATION_BIPHASE | T55x7_BITRATE_RF_64 | 3 << T55x7_MAXBLOCK_SHIFT, 0, 0, 0, 0};
	
	if (param_getchar(Cmd, 3) == 'Q' || param_getchar(Cmd, 3) == 'q')
		blocks[0] = T5555_MODULATION_FSK2 | T5555_SET_BITRATE(50) | 3 << T5555_MAXBLOCK_SHIFT;

	if (sscanf(Cmd, "%u %u %u", &fmtlen, &fc, &cn ) != 3) return usage_lf_guard_clone();

	fmtlen &= 0x7f;
	facilitycode = (fc & 0x000000FF);
	cardnumber = (cn & 0x0000FFFF);
	
	if ( !GetGuardBits(fmtlen, facilitycode, cardnumber, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	blocks[1] = bytebits_to_byte(bs,32);
	blocks[2] = bytebits_to_byte(bs+32,32);
	blocks[3] = bytebits_to_byte(bs+64,32);

	PrintAndLog("Preparing to clone Guardall to T55x7 with Facility Code: %u, Card Number: %u", facilitycode, cardnumber);
	PrintAndLog("Blk | Data ");
	PrintAndLog("----+------------");
	for ( i = 0; i<4; ++i )
		PrintAndLog(" %02d | 0x%08x", i, blocks[i]);

	UsbCommand resp;
	UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

	for ( i = 0; i<4; ++i ) {
		c.arg[0] = blocks[i];
		c.arg[1] = i;
		clearCommandBuffer();
		SendCommand(&c);
		if (!WaitForResponseTimeout(CMD_ACK, &resp, T55XX_WRITE_TIMEOUT)){
			PrintAndLog("Error occurred, device did not respond during write operation.");
			return -1;
		}
	}
    return 0;
}

int CmdGuardSim(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_guard_sim();

	uint32_t facilitycode = 0, cardnumber = 0, fc = 0, cn = 0, fmtlen = 0;
	uint8_t clock = 64, encoding = 2, separator = 0, invert = 0;
	
	uint8_t bs[96];
	memset(bs, 0x00, sizeof(bs));
	
	if (sscanf(Cmd, "%u %u %u", &fmtlen, &fc, &cn ) != 3) return usage_lf_guard_sim();

	fmtlen &= 0x7F;
	facilitycode = (fc & 0x000000FF);
	cardnumber = (cn & 0x0000FFFF);
	
	if ( !GetGuardBits(fmtlen, facilitycode, cardnumber, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	PrintAndLog("Simulating Guardall - Facility Code: %u, CardNumber: %u", facilitycode, cardnumber );

	// Guard uses:  clk: 64, invert: 0, encoding: 2 (ASK Biphase)
	uint64_t arg1, arg2;
	arg1 = (clock << 8) | encoding;
	arg2 = (invert << 8) | separator;

	uint8_t rawbytes[12];
	size_t size = sizeof(rawbytes);
	for (uint8_t i=0; i < size; ++i){
		rawbytes[i] =  bytebits_to_byte( bs + (i*8), 8);
	}

	UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};
	memcpy(c.d.asBytes, rawbytes, size );
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
    {"help",	CmdHelp,		1, "This help"},
	{"demod",	CmdGuardDemod,	1, "Demodulate a G Prox II tag from the GraphBuffer"},
	{"read",	CmdGuardRead,	0, "Attempt to read and extract tag data from the antenna"},
	{"clone",	CmdGuardClone,	0, "<Facility-Code> <Card Number>  clone Guardall tag"},
	{"sim",		CmdGuardSim,	0, "<Facility-Code> <Card Number>  simulate Guardall tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFGuard(const char *Cmd) {
	clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
