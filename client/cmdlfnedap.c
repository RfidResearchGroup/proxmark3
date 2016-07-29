//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency NEDAP tag commands
//-----------------------------------------------------------------------------
#include <string.h>
#include <inttypes.h>
#include "cmdlfnedap.h"
static int CmdHelp(const char *Cmd);

int usage_lf_nedap_clone(void){
	PrintAndLog("clone a NEDAP tag to a T55x7 tag.");
	PrintAndLog("");
	PrintAndLog("Usage: lf nedap clone [h] <Card-Number>");
	PrintAndLog("Options:");
	PrintAndLog("      h             : This help");
	PrintAndLog("      <Card Number> : 24-bit value card number");
//	PrintAndLog("      Q5            : optional - clone to Q5 (T5555) instead of T55x7 chip");
	PrintAndLog("");
	PrintAndLog("Sample: lf nedap clone 112233");
	return 0;
}

int usage_lf_nedap_sim(void) {
	PrintAndLog("Enables simulation of NEDAP card with specified card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf nedap sim [h] <Card-Number>");
	PrintAndLog("Options:");
	PrintAndLog("      h               : This help");
	PrintAndLog("      <Card Number>   : 24-bit value card number");
	PrintAndLog("");
	PrintAndLog("Sample: lf nedap sim 112233");
	return 0;
}

int GetNedapBits(uint32_t cn, uint8_t *nedapBits) {

	uint8_t pre[128];
	memset(pre, 0x00, sizeof(pre));

	// preamble  1111 1111 10 = 0XF8
	num_to_bytebits(0xF8, 10, pre);

	// fixed tagtype code?  0010 1101 = 0x2D
	num_to_bytebits(0x2D, 8, pre+10);
	
	// 46 encrypted bits - UNKNOWN ALGO
	//    -- 16 bits checksum. Should be 4x4 checksum,  based on UID and 2 constant values.
	//    -- 30 bits undocumented?  
	num_to_bytebits(cn, 46, pre+18);

	//----from this part, the UID in clear text, with a 1bit ZERO as separator between bytes.
	pre[64] = 0;

	// cardnumber (uid)
	num_to_bytebits(cn, 24, pre+64);

	pre[73] = 0;
	pre[82] = 0;
	pre[91] = 0;
	pre[100] = 0;
	pre[109] = 0;
	pre[118] = 0;
	
	// add paritybits	(bitsource, dest, sourcelen, paritylen, parityType (odd, even,)
	addParity(pre+64, pre+64, 128, 8, 1);

//1111111110001011010000010110100011001001000010110101001101011001000110011010010000000000100001110001001000000001000101011100111
	return 1;
}
/*
 - UID: 001630
 - i: 4071
 - Checksum2 BE21
*/
//GetParity( uint8_t *bits, uint8_t type, int length)

//NEDAP demod - ASK/Biphase (or Diphase),  RF/64 with preamble of 1111111110  (always a 128 bit data stream)
//print NEDAP Prox ID, encoding, encrypted ID, 

int CmdLFNedapDemod(const char *Cmd) {
	//raw ask demod no start bit finding just get binary from wave
	if (!ASKbiphaseDemod("0 64 0 0", FALSE)) {
		if (g_debugMode) PrintAndLog("Error NEDAP: ASKbiphaseDemod failed");
		return 0;
	}
	size_t size = DemodBufferLen;
	int idx = NedapDemod(DemodBuffer, &size);
	if (idx < 0){
		if (g_debugMode){
			// if (idx == -5)
				// PrintAndLog("DEBUG: Error - not enough samples");
			// else if (idx == -1)
				// PrintAndLog("DEBUG: Error - only noise found");
			// else if (idx == -2)
				// PrintAndLog("DEBUG: Error - problem during ASK/Biphase demod");
			if (idx == -3)
				PrintAndLog("DEBUG: Error - Size not correct: %d", size);
			else if (idx == -4)
				PrintAndLog("DEBUG: Error - NEDAP preamble not found");
			else
				PrintAndLog("DEBUG: Error - idx: %d",idx);
		}
		return 0;
	}

/* Index map                                                      E                                                                              E
 preamble    enc tag type         encrypted uid                   P d    33    d    90    d    04    d    71    d    40    d    45    d    E7    P
 1111111110 00101101000001011010001100100100001011010100110101100 1 0 00110011 0 10010000 0 00000100 0 01110001 0 01000000 0 01000101 0 11100111 1
                                                                         uid2       uid1       uid0         I          I          R           R    
 1111111110 00101101000001011010001100100100001011010100110101100 1 
 
 0 00110011 
 0 10010000 
 0 00000100
 0 01110001
 0 01000000
 0 01000101
 0 11100111
 1
 
	 Tag ID is 049033 
	 I = Identical on all tags
	 R = Random ?
	 UID2, UID1, UID0 == card number

*/
	//get raw ID before removing parities
	uint32_t raw[4] = {0,0,0,0};
	raw[0] = bytebits_to_byte(DemodBuffer+idx+96,32);
	raw[1] = bytebits_to_byte(DemodBuffer+idx+64,32);
	raw[2] = bytebits_to_byte(DemodBuffer+idx+32,32);
	raw[3] = bytebits_to_byte(DemodBuffer+idx,32);
	setDemodBuf(DemodBuffer,128,idx);

	uint8_t firstParity = GetParity( DemodBuffer, EVEN, 63);
	if ( firstParity != DemodBuffer[63]  ) {
		PrintAndLog("1st 64bit parity check failed:  %d|%d ", DemodBuffer[63], firstParity);
		return 0;
	}

	uint8_t secondParity = GetParity( DemodBuffer+64, EVEN, 63);
	if ( secondParity != DemodBuffer[127]  ) {
		PrintAndLog("2st 64bit parity check failed:  %d|%d ", DemodBuffer[127], secondParity);
		return 0;
	}

	// ok valid card found!
	uint32_t uid = 0;
	uid =  bytebits_to_byte(DemodBuffer+65, 8);
	uid |= bytebits_to_byte(DemodBuffer+74, 8) << 8;
	uid |= bytebits_to_byte(DemodBuffer+83, 8) << 16;

	uint16_t two = 0;
	two =  bytebits_to_byte(DemodBuffer+92, 8); 
	two |= bytebits_to_byte(DemodBuffer+101, 8) << 8;
	
	uint16_t chksum2 = 0;
	chksum2 =  bytebits_to_byte(DemodBuffer+110, 8);
	chksum2 |= bytebits_to_byte(DemodBuffer+119, 8) << 8;

	PrintAndLog("NEDAP ID Found - Raw: %08x%08x%08x%08x", raw[3], raw[2], raw[1], raw[0]);
	PrintAndLog(" - UID: %06X", uid);
	PrintAndLog(" - i: %04X", two);
	PrintAndLog(" - Checksum2 %04X", chksum2);

	if (g_debugMode){
		PrintAndLog("DEBUG: idx: %d, Len: %d, Printing Demod Buffer:", idx, 128);
		printDemodBuff();
		PrintAndLog("BIN:\n%s", sprint_bin_break( DemodBuffer, 128, 64) );
	}

	return 1;
}
/*
configuration
lf t55xx wr b 0 d 00170082

1) uid 049033
lf t55 wr b 1 d FF8B4168
lf t55 wr b 2 d C90B5359
lf t55 wr b 3 d 19A40087
lf t55 wr b 4 d 120115CF

2) uid 001630
lf t55 wr b 1 d FF8B6B20
lf t55 wr b 2 d F19B84A3
lf t55 wr b 3 d 18058007
lf t55 wr b 4 d 1200857C

3) uid 39feff
lf t55xx wr b 1 d ffbfa73e
lf t55xx wr b 2 d 4c0003ff
lf t55xx wr b 3 d ffbfa73e
lf t55xx wr b 4 d 4c0003ff

*/

int CmdLFNedapRead(const char *Cmd) {
	CmdLFRead("s");
	getSamples("30000",false);
	return CmdLFNedapDemod("");
}
/*
int CmdLFNedapClone(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_nedap_clone();

	uint32_t cardnumber=0, cn = 0;
	uint32_t blocks[5];
	uint8_t i;
	uint8_t bs[128];
	memset(bs, 0x00, sizeof(bs));

	if (sscanf(Cmd, "%u", &cn ) != 1) return usage_lf_nedap_clone();

	cardnumber = (cn & 0x00FFFFFF);
	
	if ( !GetNedapBits(cardnumber, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	((ASK/biphase   data rawdemod ab 0 64 1 0
	//NEDAP - compat mode, ASK/Biphase, data rate 64, 4 data blocks
	blocks[0] = T55x7_MODULATION_BIPHASE | T55x7_BITRATE_RF_64 | 4<<T55x7_MAXBLOCK_SHIFT;

	if (param_getchar(Cmd, 3) == 'Q' || param_getchar(Cmd, 3) == 'q')
		//t5555 (Q5) BITRATE = (RF-2)/2 (iceman)
		blocks[0] = T5555_MODULATION_BIPHASE | T5555_INVERT_OUTPUT | 64<<T5555_BITRATE_SHIFT | 4<<T5555_MAXBLOCK_SHIFT;

	blocks[1] = bytebits_to_byte(bs,32);
	blocks[2] = bytebits_to_byte(bs+32,32);
	blocks[3] = bytebits_to_byte(bs+64,32);
	blocks[4] = bytebits_to_byte(bs+96,32);

	PrintAndLog("Preparing to clone NEDAP to T55x7 with card number: %u", cardnumber);
	PrintAndLog("Blk | Data ");
	PrintAndLog("----+------------");
	for ( i = 0; i<5; ++i )
		PrintAndLog(" %02d | %08" PRIx32, i, blocks[i]);

	UsbCommand resp;
	UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

	for ( i = 0; i<5; ++i ) {
		c.arg[0] = blocks[i];
		c.arg[1] = i;
		clearCommandBuffer();
		SendCommand(&c);
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)){
			PrintAndLog("Error occurred, device did not respond during write operation.");
			return -1;
		}
	}
    return 0;
}
*/

int CmdLFNedapSim(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_nedap_sim();

	uint32_t cardnumber = 0, cn = 0;
	
	uint8_t bs[128];
	size_t size = sizeof(bs);
	memset(bs, 0x00, size);
	
	// NEDAP,  Bihase = 2, clock 64, inverted, 
	uint8_t encoding = 2, separator = 0, clk=64, invert=1;
	uint16_t arg1, arg2;
	arg1 = clk << 8 | encoding;
	arg2 = invert << 8 | separator;

	if (sscanf(Cmd, "%u", &cn ) != 1) return usage_lf_nedap_sim();
	cardnumber = (cn & 0x00FFFFFF);
	
	if ( !GetNedapBits(cardnumber, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	PrintAndLog("Simulating Nedap - CardNumber: %u", cardnumber );
	
	UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};
	memcpy(c.d.asBytes, bs, size);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdLFNedapChk(const char *Cmd){
    
	uint8_t data[256] = { 0x30, 0x16, 0x00, 0x71, 0x40, 0x21, 0xBE};
	int len = 0;
	param_gethex_ex(Cmd, 0, data, &len);
	
	len = ( len == 0 ) ? 5 : len>>1;
	
	PrintAndLog("Input: [%d] %s", len, sprint_hex(data, len));
	
	//uint8_t last = GetParity(data, EVEN, 62);
	//PrintAndLog("TEST PARITY::  %d | %d ", DemodBuffer[62], last);

    uint8_t cl = 0x1D, ch = 0x1D, carry = 0;
    uint8_t al, bl, temp;
    
	for (int i = 0; i < len; ++i){
		al = data[i];
        for (int j = 8; j > 0; --j) {
			
            bl = al ^ ch;
			//printf("BL %02x | CH %02x \n", al, ch);
			
            carry = (cl & 0x80) ? 1 : 0;
            cl <<= 1;
            
            temp = (ch & 0x80) ? 1 : 0;
            ch = (ch << 1) | carry;
            carry = temp;
            
            carry = (al & 0x80) ? 1 : 0;
            al <<= 1;
            
            carry = (bl & 0x80) ? 1 : 0;
            bl <<= 1;
            
            if (carry) {
                cl ^= 0x21;
                ch ^= 0x10;
            }
        }
    }
	
	PrintAndLog("Nedap checksum: [ 0x21, 0xBE ] %x", ((ch << 8) | cl) );
	return 0;
}


static command_t CommandTable[] = {
    {"help",	CmdHelp,		1, "This help"},
	{"read",	CmdLFNedapRead, 0, "Attempt to read and extract tag data"},
//	{"clone",	CmdLFNedapClone,0, "<Card Number>  clone nedap tag"},
	{"sim",		CmdLFNedapSim,  0, "<Card Number>  simulate nedap tag"},
	{"chk",		CmdLFNedapChk,	1, "Calculate Nedap Checksum <uid bytes>"},
    {NULL, NULL, 0, NULL}
};

int CmdLFNedap(const char *Cmd) {
	clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
