#include "cmdlfio.h"

static int CmdHelp(const char *Cmd);

int usage_lf_io_fskdemod(void) {
	PrintAndLog("Enables IOProx compatible reader mode printing details of scanned tags.");
	PrintAndLog("By default, values are printed and logged until the button is pressed or another USB command is issued.");
	PrintAndLog("If the [1] option is provided, reader mode is exited after reading a single card.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf io fskdemod [h] [1]");
	PrintAndLog("Options :");
	PrintAndLog("      h :  This help");
	PrintAndLog("      1 : (optional) stop after reading a single card");
	PrintAndLog("");
	PrintAndLog("Samples");
	PrintAndLog("        lf io fskdemod");
	PrintAndLog("        lf io fskdemod 1");
	return 0;
}

int usage_lf_io_sim(void) {
	PrintAndLog("Enables simulation of IOProx card with specified facility-code and card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf io sim [h] <version> <facility-code> <card-number>");
	PrintAndLog("Options :");
	PrintAndLog("                h :  This help");	
	PrintAndLog("        <version> :  8bit version");
	PrintAndLog("  <facility-code> :  8bit value facility code");
	PrintAndLog("    <card number> :  16bit value card number");
	PrintAndLog("");
	PrintAndLog("Samples");
	PrintAndLog("       lf io sim 26 101 1337");
	return 0;
}

int usage_lf_io_clone(void) {
	PrintAndLog("Enables cloning of IOProx card with specified facility-code and card number onto T55x7.");
	PrintAndLog("The T55x7 must be on the antenna when issuing this command.  T55x7 blocks are calculated and printed in the process.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf awid clone [h] <version> <facility-code> <card-number> [Q5]");
	PrintAndLog("Options :");
	PrintAndLog("                h :  This help");	
	PrintAndLog("        <version> :  8bit version");
	PrintAndLog("  <facility-code> :  8bit value facility code");
	PrintAndLog("    <card number> :  16bit value card number");
	PrintAndLog("               Q5 :  optional - clone to Q5 (T5555) instead of T55x7 chip");
	PrintAndLog("");
	PrintAndLog("Samples");
	PrintAndLog("       lf io clone 26 101 1337");
	return 0;
}

int CmdIODemodFSK(const char *Cmd) {
	if (Cmd[0] == 'h' || Cmd[0] == 'H') return usage_lf_io_fskdemod();
	int findone = (Cmd[0]=='1') ? 1 : 0;
	UsbCommand c = {CMD_IO_DEMOD_FSK};
	c.arg[0] = findone;
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}
/*
int CmdIOProxDemod(const char *Cmd){
  if (GraphTraceLen < 4800) {
    PrintAndLog("too short; need at least 4800 samples");
    return 0;
  }
  GraphTraceLen = 4800;
  for (int i = 0; i < GraphTraceLen; ++i) {
    GraphBuffer[i] = (GraphBuffer[i] < 0) ? 0 : 1;
  }
  RepaintGraphWindow();
  return 0;
}  
*/

//Index map
//0           10          20          30          40          50          60
//|           |           |           |           |           |           |
//01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
//-----------------------------------------------------------------------------
//00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1 ???????? 11
//XSF(version)facility:codeone+codetwo (raw)
int getIOProxBits(uint8_t version, uint8_t fc, uint16_t cn, uint8_t *bits) {
#define SEPARATOR 1	
	uint8_t pos=0;
	// the return bits, preamble 0000 0000 0
	uint8_t pre[64];
	memset(pre, 0, sizeof(pre));

	// skip 9 zeros as preamble
	pos = 9;
	
	// another fixed byte 11110000 = 0xF0
	num_to_bytebits(0xF0, 8, pre+pos);
	pos += 8;
	pre[pos] = SEPARATOR;
	pos++;	
	
	// add facilitycode
	num_to_bytebits(fc, 8, pre+pos);
	pos += 8;
	pre[pos] = SEPARATOR;
	pos++;
	
	// add version
	num_to_bytebits(version, 8, pre+pos);
	pos += 8;
	pre[pos] = SEPARATOR;
	pos++;
	
	// cardnumber high byte
	num_to_bytebits( ((cn & 0xFF00)>>8), 8, pre+pos);
	pos += 8;
	pre[pos] = SEPARATOR;
	pos++;
	
	// cardnumber low byte
	num_to_bytebits( (cn & 0xFF), 8, pre+pos);
	pos += 8;
	pre[pos] = SEPARATOR;
	pos++;

	// calculate and add CRC
	uint16_t crc = 0;
	for (uint8_t i=1; i<6; ++i)
		crc += bytebits_to_byte(pre+9*i, 8);
	
	crc &= 0xFF;
	crc = 0xff - crc;
	num_to_bytebits(crc, 8, pre+pos);
	pos += 8;
		
	// Final two ONES
	pre[pos] = SEPARATOR;
	pre[++pos] = SEPARATOR;

	memcpy(bits, pre, sizeof(pre));
	return 1;
}

int CmdIOSim(const char *Cmd) {
	uint16_t cn = 0;
	uint8_t version = 0, fc = 0;
	uint8_t bits[64];
	uint8_t *bs = bits;
	size_t size = sizeof(bits);
	memset(bs, 0x00, size);

	uint64_t arg1 = ( 10 << 8 ) + 8; // fcHigh = 10, fcLow = 8
	uint64_t arg2 = (64 << 8)| + 1; // clk RF/64 invert=1
  
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_io_sim();
	
  	version = param_get8(Cmd, 0);
	fc = param_get8(Cmd, 1);
	cn = param_get32ex(Cmd, 2, 0, 10);

	if ( !version | !fc || !cn) return usage_lf_io_sim();
	
	if ((cn & 0xFFFF) != cn) {
		cn &= 0xFFFF;
		PrintAndLog("Card Number Truncated to 16-bits (IOProx): %u", cn);
	}
	
	PrintAndLog("Emulating IOProx Version: %u FC: %u; CN: %u\n", version, fc, cn);
	PrintAndLog("Press pm3-button to abort simulation or run another command");
	
	if ( !getIOProxBits(version, fc, cn, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}
	// IOProx uses: fcHigh: 10, fcLow: 8, clk: 64, invert: 1
	// arg1 --- fcHigh<<8 + fcLow
	// arg2 --- Inversion and clk setting
	// 64   --- Bitstream length: 64-bits == 8 bytes
	UsbCommand c = {CMD_FSK_SIM_TAG, {arg1, arg2, size}};  
	memcpy(c.d.asBytes, bs, size);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdIOClone(const char *Cmd) {
	
	uint32_t blocks[3] = {T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_64 | 2<<T55x7_MAXBLOCK_SHIFT, 0, 0};
	uint16_t cn = 0;
	uint8_t version = 0, fc = 0;
	uint8_t bits[64];
	uint8_t *bs=bits;
	memset(bs,0,sizeof(bits));
	
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_io_clone();

  	version = param_get8(Cmd, 0);
	fc = param_get8(Cmd, 1);
	cn = param_get32ex(Cmd, 2, 0, 10);

	if ( !version | !fc || !cn) return usage_lf_io_clone();
	
	if ((cn & 0xFFFF) != cn) {
		cn &= 0xFFFF;
		PrintAndLog("Card Number Truncated to 16-bits (IOProx): %u", cn);
	}
	
//	if (param_getchar(Cmd, 4) == 'Q' || param_getchar(Cmd, 4) == 'q')
		//t5555 (Q5) BITRATE = (RF-2)/2 (iceman)
//		blocks[0] = T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | 50<<T5555_BITRATE_SHIFT | 3<<T5555_MAXBLOCK_SHIFT;

	if ( !getIOProxBits(version, fc, cn, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	blocks[1] = bytebits_to_byte(bs,32);
	blocks[2] = bytebits_to_byte(bs+32,32);

	PrintAndLog("Preparing to clone IOProx to T55x7 with Version: %u FC: %u, CN: %u", version, fc, cn);
	PrintAndLog("Blk | Data ");
	PrintAndLog("----+------------");
	PrintAndLog(" 00 | 0x%08x", blocks[0]);
	PrintAndLog(" 01 | 0x%08x", blocks[1]);
	PrintAndLog(" 02 | 0x%08x", blocks[2]);
	//UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};
	UsbCommand c = {CMD_IO_CLONE_TAG, {blocks[1],blocks[2],0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
	{"help",	CmdHelp,		1, "This help"},
	//{"demod",	CmdIOProxDemod,	1, "Demodulate Stream"},
	{"fskdemod",CmdIODemodFSK,	0, "['1'] Realtime IO FSK demodulator (option '1' for one tag only)"},
	{"sim",		CmdIOSim,		0, "<version> <facility-code> <card number> -- IOProx tag simulator"},
	{"clone",	CmdIOClone,		0, "<version> <facility-code> <card number> <Q5> -- Clone IOProx to T55x7"},
	{NULL, NULL, 0, NULL}
};

int CmdLFIO(const char *Cmd){
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0; 
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
