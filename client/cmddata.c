//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data and Graph commands
//-----------------------------------------------------------------------------

#include <stdio.h>    // also included in util.h
#include <string.h>   // also included in util.h
#include <limits.h>   // for CmdNorm INT_MIN && INT_MAX
#include "data.h"     // also included in util.h
#include "cmddata.h"
#include "util.h"
#include "cmdmain.h"
#include "proxmark3.h"
#include "ui.h"       // for show graph controls
#include "graph.h"    // for graph data
#include "cmdparser.h"// already included in cmdmain.h
#include "usb_cmd.h"  // already included in cmdmain.h and proxmark3.h
#include "lfdemod.h"  // for demod code
#include "crc.h"      // for pyramid checksum maxim
#include "crc16.h"    // for FDXB demod checksum
#include "loclass/cipherutils.h" // for decimating samples in getsamples

uint8_t DemodBuffer[MAX_DEMOD_BUF_LEN];
uint8_t g_debugMode=0;
size_t DemodBufferLen=0;
static int CmdHelp(const char *Cmd);

int usage_data_printdemodbuf(void){
	PrintAndLog("Usage: data printdemodbuffer x o <offset> l <length>");
	PrintAndLog("Options:");
	PrintAndLog("       h          This help");
	PrintAndLog("       x          output in hex (omit for binary output)");
	PrintAndLog("       o <offset> enter offset in # of bits");
	PrintAndLog("       l <length> enter length to print in # of bits or hex characters respectively");
	return 0;	
}
int usage_data_askem410xdemod(void){
	PrintAndLog("Usage:  data askem410xdemod [clock] <0|1> [maxError]");
	PrintAndLog("     [set clock as integer] optional, if not set, autodetect.");
	PrintAndLog("     <invert>, 1 for invert output");
	PrintAndLog("     [set maximum allowed errors], default = 100.");
	PrintAndLog("");
	PrintAndLog("    sample: data askem410xdemod        = demod an EM410x Tag ID from GraphBuffer");
	PrintAndLog("          : data askem410xdemod 32     = demod an EM410x Tag ID from GraphBuffer using a clock of RF/32");
	PrintAndLog("          : data askem410xdemod 32 1   = demod an EM410x Tag ID from GraphBuffer using a clock of RF/32 and inverting data");
	PrintAndLog("          : data askem410xdemod 1      = demod an EM410x Tag ID from GraphBuffer while inverting data");
	PrintAndLog("          : data askem410xdemod 64 1 0 = demod an EM410x Tag ID from GraphBuffer using a clock of RF/64 and inverting data and allowing 0 demod errors");
	return 0;
}
int usage_data_manrawdecode(void){
	PrintAndLog("Usage:  data manrawdecode [invert] [maxErr]");
	PrintAndLog("     Takes 10 and 01 and converts to 0 and 1 respectively");
	PrintAndLog("     --must have binary sequence in demodbuffer (run data askrawdemod first)");
	PrintAndLog("  [invert]  invert output");		
	PrintAndLog("  [maxErr]  set number of errors allowed (default = 20)");		
	PrintAndLog("");
	PrintAndLog("    sample: data manrawdecode   = decode manchester bitstream from the demodbuffer");
	return 0;
}
int usage_data_biphaserawdecode(void){
	PrintAndLog("Usage:  data biphaserawdecode [offset] [invert] [maxErr]");
	PrintAndLog("     Converts 10 or 01 to 1 and 11 or 00 to 0");
	PrintAndLog("     --must have binary sequence in demodbuffer (run data askrawdemod first)");
	PrintAndLog("     --invert for Conditional Dephase Encoding (CDP) AKA Differential Manchester");
	PrintAndLog("");
	PrintAndLog("     [offset <0|1>], set to 0 not to adjust start position or to 1 to adjust decode start position");
	PrintAndLog("     [invert <0|1>], set to 1 to invert output");
	PrintAndLog("     [maxErr int],   set max errors tolerated - default=20");
	PrintAndLog("");
	PrintAndLog("    sample: data biphaserawdecode     = decode biphase bitstream from the demodbuffer");
	PrintAndLog("    sample: data biphaserawdecode 1 1 = decode biphase bitstream from the demodbuffer, set offset, and invert output");
	return 0;
}
int usage_data_rawdemod(void){
	PrintAndLog("Usage:  data rawdemod [modulation] <help>|<options>");
	PrintAndLog("   [modulation] as 2 char, 'ab' for ask/biphase, 'am' for ask/manchester, 'ar' for ask/raw, 'fs' for fsk, ...");		
	PrintAndLog("         'nr' for nrz/direct, 'p1' for psk1, 'p2' for psk2");
	PrintAndLog("   <help> as 'h', prints the help for the specific modulation");	
	PrintAndLog("   <options> see specific modulation help for optional parameters");				
	PrintAndLog("");
	PrintAndLog("    sample: data rawdemod fs h         = print help specific to fsk demod");
	PrintAndLog("          : data rawdemod fs           = demod GraphBuffer using: fsk - autodetect");
	PrintAndLog("          : data rawdemod ab           = demod GraphBuffer using: ask/biphase - autodetect");
	PrintAndLog("          : data rawdemod am           = demod GraphBuffer using: ask/manchester - autodetect");
	PrintAndLog("          : data rawdemod ar           = demod GraphBuffer using: ask/raw - autodetect");
	PrintAndLog("          : data rawdemod nr           = demod GraphBuffer using: nrz/direct - autodetect");
	PrintAndLog("          : data rawdemod p1           = demod GraphBuffer using: psk1 - autodetect");
	PrintAndLog("          : data rawdemod p2           = demod GraphBuffer using: psk2 - autodetect");
	return 0;
}
int usage_data_rawdemod_am(void){
	PrintAndLog("Usage:  data rawdemod am <s> [clock] <invert> [maxError] [maxLen] [amplify]");
	PrintAndLog("     ['s'] optional, check for Sequence Terminator");
	PrintAndLog("     [set clock as integer] optional, if not set, autodetect");
	PrintAndLog("     <invert>, 1 to invert output");
	PrintAndLog("     [set maximum allowed errors], default = 100");
	PrintAndLog("     [set maximum Samples to read], default = 32768 (512 bits at rf/64)");
	PrintAndLog("     <amplify>, 'a' to attempt demod with ask amplification, default = no amp");
	PrintAndLog("");
	PrintAndLog("    sample: data rawdemod am        = demod an ask/manchester tag from GraphBuffer");
	PrintAndLog("          : data rawdemod am 32     = demod an ask/manchester tag from GraphBuffer using a clock of RF/32");
	PrintAndLog("          : data rawdemod am 32 1   = demod an ask/manchester tag from GraphBuffer using a clock of RF/32 and inverting data");
	PrintAndLog("          : data rawdemod am 1      = demod an ask/manchester tag from GraphBuffer while inverting data");
	PrintAndLog("          : data rawdemod am 64 1 0 = demod an ask/manchester tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
	return 0;
}
int usage_data_rawdemod_ab(void){
	PrintAndLog("Usage:  data rawdemod ab [offset] [clock] <invert> [maxError] [maxLen] <amplify>");
	PrintAndLog("     [offset], offset to begin biphase, default=0");
	PrintAndLog("     [set clock as integer] optional, if not set, autodetect");
	PrintAndLog("     <invert>, 1 to invert output");
	PrintAndLog("     [set maximum allowed errors], default = 100");
	PrintAndLog("     [set maximum Samples to read], default = 32768 (512 bits at rf/64)");
	PrintAndLog("     <amplify>, 'a' to attempt demod with ask amplification, default = no amp");
	PrintAndLog("     NOTE: <invert>  can be entered as second or third argument");
	PrintAndLog("     NOTE: <amplify> can be entered as first, second or last argument");
	PrintAndLog("     NOTE: any other arg must have previous args set to work");
	PrintAndLog("");
	PrintAndLog("     NOTE: --invert for Conditional Dephase Encoding (CDP) AKA Differential Manchester");
	PrintAndLog("");
	PrintAndLog("    sample: data rawdemod ab              = demod an ask/biph tag from GraphBuffer");
	PrintAndLog("          : data rawdemod ab 0 a          = demod an ask/biph tag from GraphBuffer, amplified");
	PrintAndLog("          : data rawdemod ab 1 32         = demod an ask/biph tag from GraphBuffer using an offset of 1 and a clock of RF/32");
	PrintAndLog("          : data rawdemod ab 0 32 1       = demod an ask/biph tag from GraphBuffer using a clock of RF/32 and inverting data");
	PrintAndLog("          : data rawdemod ab 0 1          = demod an ask/biph tag from GraphBuffer while inverting data");
	PrintAndLog("          : data rawdemod ab 0 64 1 0     = demod an ask/biph tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
	PrintAndLog("          : data rawdemod ab 0 64 1 0 0 a = demod an ask/biph tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors, and amp");
	return 0;
}
int usage_data_rawdemod_ar(void){
	PrintAndLog("Usage:  data rawdemod ar [clock] <invert> [maxError] [maxLen] [amplify]");
	PrintAndLog("     [set clock as integer] optional, if not set, autodetect");
	PrintAndLog("     <invert>, 1 to invert output");
	PrintAndLog("     [set maximum allowed errors], default = 100");
	PrintAndLog("     [set maximum Samples to read], default = 32768 (1024 bits at rf/64)");
	PrintAndLog("     <amplify>, 'a' to attempt demod with ask amplification, default = no amp");
	PrintAndLog("");
	PrintAndLog("    sample: data rawdemod ar            = demod an ask tag from GraphBuffer");
	PrintAndLog("          : data rawdemod ar a          = demod an ask tag from GraphBuffer, amplified");
	PrintAndLog("          : data rawdemod ar 32         = demod an ask tag from GraphBuffer using a clock of RF/32");
	PrintAndLog("          : data rawdemod ar 32 1       = demod an ask tag from GraphBuffer using a clock of RF/32 and inverting data");
	PrintAndLog("          : data rawdemod ar 1          = demod an ask tag from GraphBuffer while inverting data");
	PrintAndLog("          : data rawdemod ar 64 1 0     = demod an ask tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
	PrintAndLog("          : data rawdemod ar 64 1 0 0 a = demod an ask tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors, and amp");
	return 0;
}
int usage_data_rawdemod_fs(void){
	PrintAndLog("Usage:  data rawdemod fs [clock] <invert> [fchigh] [fclow]");
	PrintAndLog("     [set clock as integer] optional, omit for autodetect.");
	PrintAndLog("     <invert>, 1 for invert output, can be used even if the clock is omitted");
	PrintAndLog("     [fchigh], larger field clock length, omit for autodetect");
	PrintAndLog("     [fclow], small field clock length, omit for autodetect");
	PrintAndLog("");
	PrintAndLog("    sample: data rawdemod fs           = demod an fsk tag from GraphBuffer using autodetect");
	PrintAndLog("          : data rawdemod fs 32        = demod an fsk tag from GraphBuffer using a clock of RF/32, autodetect fc");
	PrintAndLog("          : data rawdemod fs 1         = demod an fsk tag from GraphBuffer using autodetect, invert output");   
	PrintAndLog("          : data rawdemod fs 32 1      = demod an fsk tag from GraphBuffer using a clock of RF/32, invert output, autodetect fc");
	PrintAndLog("          : data rawdemod fs 64 0 8 5  = demod an fsk1 RF/64 tag from GraphBuffer");
	PrintAndLog("          : data rawdemod fs 50 0 10 8 = demod an fsk2 RF/50 tag from GraphBuffer");
	PrintAndLog("          : data rawdemod fs 50 1 10 8 = demod an fsk2a RF/50 tag from GraphBuffer");
	return 0;
}
int usage_data_rawdemod_nr(void){
	PrintAndLog("Usage:  data rawdemod nr [clock] <0|1> [maxError]");
	PrintAndLog("     [set clock as integer] optional, if not set, autodetect.");
	PrintAndLog("     <invert>, 1 for invert output");
	PrintAndLog("     [set maximum allowed errors], default = 100.");
	PrintAndLog("");
	PrintAndLog("    sample: data rawdemod nr        = demod a nrz/direct tag from GraphBuffer");
	PrintAndLog("          : data rawdemod nr 32     = demod a nrz/direct tag from GraphBuffer using a clock of RF/32");
	PrintAndLog("          : data rawdemod nr 32 1   = demod a nrz/direct tag from GraphBuffer using a clock of RF/32 and inverting data");
	PrintAndLog("          : data rawdemod nr 1      = demod a nrz/direct tag from GraphBuffer while inverting data");
	PrintAndLog("          : data rawdemod nr 64 1 0 = demod a nrz/direct tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
	return 0;
}
int usage_data_rawdemod_p1(void){
	PrintAndLog("Usage:  data rawdemod p1 [clock] <0|1> [maxError]");
	PrintAndLog("     [set clock as integer] optional, if not set, autodetect.");
	PrintAndLog("     <invert>, 1 for invert output");
	PrintAndLog("     [set maximum allowed errors], default = 100.");
	PrintAndLog("");
	PrintAndLog("    sample: data rawdemod p1        = demod a psk1 tag from GraphBuffer");
	PrintAndLog("          : data rawdemod p1 32     = demod a psk1 tag from GraphBuffer using a clock of RF/32");
	PrintAndLog("          : data rawdemod p1 32 1   = demod a psk1 tag from GraphBuffer using a clock of RF/32 and inverting data");
	PrintAndLog("          : data rawdemod p1 1      = demod a psk1 tag from GraphBuffer while inverting data");
	PrintAndLog("          : data rawdemod p1 64 1 0 = demod a psk1 tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
	return 0;
}
int usage_data_rawdemod_p2(void){
	PrintAndLog("Usage:  data rawdemod p2 [clock] <0|1> [maxError]");
	PrintAndLog("     [set clock as integer] optional, if not set, autodetect.");
	PrintAndLog("     <invert>, 1 for invert output");
	PrintAndLog("     [set maximum allowed errors], default = 100.");
	PrintAndLog("");
	PrintAndLog("    sample: data rawdemod p2         = demod a psk2 tag from GraphBuffer, autodetect clock");
	PrintAndLog("          : data rawdemod p2 32      = demod a psk2 tag from GraphBuffer using a clock of RF/32");
	PrintAndLog("          : data rawdemod p2 32 1    = demod a psk2 tag from GraphBuffer using a clock of RF/32 and inverting output");
	PrintAndLog("          : data rawdemod p2 1       = demod a psk2 tag from GraphBuffer, autodetect clock and invert output");
	PrintAndLog("          : data rawdemod p2 64 1 0  = demod a psk2 tag from GraphBuffer using a clock of RF/64, inverting output and allowing 0 demod errors");
	return 0;
}
int usage_data_autocorr(void) {
	PrintAndLog("Usage: data autocorr [window] [g]");
	PrintAndLog("Options:");
	PrintAndLog("       h              This help");
	PrintAndLog("       [window]       window length for correlation - default = 4000");
	PrintAndLog("       g              save back to GraphBuffer (overwrite)");
	return 0;
}
int usage_data_undecimate(void){
	PrintAndLog("Usage: data undec [factor]");
	PrintAndLog("This function performs un-decimation, by repeating each sample N times");
	PrintAndLog("Options:        ");
	PrintAndLog("       h            This help");
	PrintAndLog("       factor       The number of times to repeat each sample.[default:2]");
	PrintAndLog("Example: 'data undec 3'");
	return 0;
}
int usage_data_detectclock(void){
	PrintAndLog("Usage:  data detectclock [modulation] <clock>");
	PrintAndLog("     [modulation as char], specify the modulation type you want to detect the clock of");
	PrintAndLog("     <clock>             , specify the clock (optional - to get best start position only)");
	PrintAndLog("       'a' = ask, 'f' = fsk, 'n' = nrz/direct, 'p' = psk");
	PrintAndLog("");
	PrintAndLog("    sample: data detectclock a    = detect the clock of an ask modulated wave in the GraphBuffer");
	PrintAndLog("            data detectclock f    = detect the clock of an fsk modulated wave in the GraphBuffer");
	PrintAndLog("            data detectclock p    = detect the clock of an psk modulated wave in the GraphBuffer");
	PrintAndLog("            data detectclock n    = detect the clock of an nrz/direct modulated wave in the GraphBuffer");
	return 0;
}
int usage_data_hex2bin(void){
	PrintAndLog("Usage: data hex2bin <hex_digits>");
	PrintAndLog("       This function will ignore all non-hexadecimal characters (but stop reading on whitespace)");
	return 0;
}
int usage_data_bin2hex(void){
	PrintAndLog("Usage: data bin2hex <binary_digits>");
	PrintAndLog("       This function will ignore all characters not 1 or 0 (but stop reading on whitespace)");
	return 0;
}

//set the demod buffer with given array of binary (one bit per byte)
//by marshmellow
void setDemodBuf(uint8_t *buff, size_t size, size_t startIdx)
{
	if (buff == NULL) 
		return;

	if ( size >= MAX_DEMOD_BUF_LEN)
		size = MAX_DEMOD_BUF_LEN;

	size_t i = 0;
	for (; i < size; i++){
		DemodBuffer[i]=buff[startIdx++];
	}
	DemodBufferLen = size;
}

int CmdSetDebugMode(const char *Cmd)
{
	int demod=0;
	sscanf(Cmd, "%i", &demod);
	g_debugMode=(uint8_t)demod;
	return 1;
}

//by marshmellow
void printDemodBuff(void)
{
	int bitLen = DemodBufferLen;
	if (bitLen<1) {
		PrintAndLog("no bits found in demod buffer");
		return;
	}
	if (bitLen>512) bitLen=512; //max output to 512 bits if we have more - should be plenty

	char *bin = sprint_bin_break(DemodBuffer, bitLen,16);
	PrintAndLog("%s",bin);

	return;
}

int CmdPrintDemodBuff(const char *Cmd)
{
	char hex[512]={0x00};
	bool hexMode = false;
	bool errors = false;
	uint32_t offset = 0; //could be size_t but no param_get16...
	uint32_t length = 512;
	char cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00)
	{
		switch(param_getchar(Cmd, cmdp))
		{
		case 'h':
		case 'H':
			return usage_data_printdemodbuf();
		case 'x':
		case 'X':
			hexMode = true;
			cmdp++;
			break;
		case 'o':
		case 'O':
			offset = param_get32ex(Cmd, cmdp+1, 0, 10);
			if (!offset) errors = true;
			cmdp += 2;
			break;
		case 'l':
		case 'L':
			length = param_get32ex(Cmd, cmdp+1, 512, 10);
			if (!length) errors = true;
			cmdp += 2;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
		if(errors) break;
	}
	//Validations
	if(errors) return usage_data_printdemodbuf();
	length = (length > (DemodBufferLen-offset)) ? DemodBufferLen-offset : length; 
	int numBits = (length) & 0x00FFC; //make sure we don't exceed our string

	if (hexMode){
		char *buf = (char *) (DemodBuffer + offset);
		numBits = (numBits > sizeof(hex)) ? sizeof(hex) : numBits;
		numBits = binarraytohex(hex, buf, numBits);
		if (numBits==0) return 0;
		PrintAndLog("DemodBuffer: %s",hex);		
	} else {
		PrintAndLog("DemodBuffer:\n%s", sprint_bin_break(DemodBuffer+offset,numBits,16));
	}
	return 1;
}

//by marshmellow
//this function strictly converts >1 to 1 and <1 to 0 for each sample in the graphbuffer
int CmdGetBitStream(const char *Cmd)
{
	int i;
	CmdHpf(Cmd);
	for (i = 0; i < GraphTraceLen; i++) {
		if (GraphBuffer[i] >= 1) {
			GraphBuffer[i] = 1;
		} else {
			GraphBuffer[i] = 0;
		}
	}
	RepaintGraphWindow();
	return 0;
}

//by marshmellow
//print 64 bit EM410x ID in multiple formats
void printEM410x(uint32_t hi, uint64_t id)
{
	if (id || hi){
		uint64_t iii=1;
		uint64_t id2lo=0;
		uint32_t ii=0;
		uint32_t i=0;
		for (ii=5; ii>0;ii--){
			for (i=0;i<8;i++){
				id2lo=(id2lo<<1LL) | ((id & (iii << (i+((ii-1)*8)))) >> (i+((ii-1)*8)));
			}
		}
		if (hi){
			//output 88 bit em id
			PrintAndLog("\nEM TAG ID      : %06X%016llX", hi, id);
		} else{
			//output 40 bit em id
			PrintAndLog("\nEM TAG ID      : %010llX", id);
			PrintAndLog("Unique TAG ID  : %010llX",  id2lo);
			PrintAndLog("\nPossible de-scramble patterns");
			PrintAndLog("HoneyWell IdentKey {");
			PrintAndLog("DEZ 8          : %08lld",id & 0xFFFFFF);
			PrintAndLog("DEZ 10         : %010lld",id & 0xFFFFFFFF);
			PrintAndLog("DEZ 5.5        : %05lld.%05lld",(id>>16LL) & 0xFFFF,(id & 0xFFFF));
			PrintAndLog("DEZ 3.5A       : %03lld.%05lld",(id>>32ll),(id & 0xFFFF));
			PrintAndLog("DEZ 3.5B       : %03lld.%05lld",(id & 0xFF000000) >> 24,(id & 0xFFFF));
			PrintAndLog("DEZ 3.5C       : %03lld.%05lld",(id & 0xFF0000) >> 16,(id & 0xFFFF));
			PrintAndLog("DEZ 14/IK2     : %014lld",id);
			PrintAndLog("DEZ 15/IK3     : %015lld",id2lo);
			PrintAndLog("DEZ 20/ZK      : %02lld%02lld%02lld%02lld%02lld%02lld%02lld%02lld%02lld%02lld",
			    (id2lo & 0xf000000000) >> 36,
			    (id2lo & 0x0f00000000) >> 32,
			    (id2lo & 0x00f0000000) >> 28,
			    (id2lo & 0x000f000000) >> 24,
			    (id2lo & 0x0000f00000) >> 20,
			    (id2lo & 0x00000f0000) >> 16,
			    (id2lo & 0x000000f000) >> 12,
			    (id2lo & 0x0000000f00) >> 8,
			    (id2lo & 0x00000000f0) >> 4,
			    (id2lo & 0x000000000f)
			);
			uint64_t paxton = (((id>>32) << 24) | (id & 0xffffff))  + 0x143e00;
			PrintAndLog("}\nOther          : %05lld_%03lld_%08lld",(id&0xFFFF),((id>>16LL) & 0xFF),(id & 0xFFFFFF));  
			PrintAndLog("Pattern Paxton : %lld [0x%llX]", paxton, paxton);

			uint32_t p1id = (id & 0xFFFFFF);
			uint8_t arr[32] = {0x00};
			int i =0; 
			int j = 23;
			for (; i < 24; ++i, --j	){
				arr[i] = (p1id >> i) & 1;
			}

			uint32_t p1  = 0;

			p1 |= arr[23] << 21;
			p1 |= arr[22] << 23;
			p1 |= arr[21] << 20;
			p1 |= arr[20] << 22;
				
			p1 |= arr[19] << 18;
			p1 |= arr[18] << 16;
			p1 |= arr[17] << 19;
			p1 |= arr[16] << 17;
				
			p1 |= arr[15] << 13;
			p1 |= arr[14] << 15;
			p1 |= arr[13] << 12;
			p1 |= arr[12] << 14;

			p1 |= arr[11] << 6;
			p1 |= arr[10] << 2;
			p1 |= arr[9]  << 7;
			p1 |= arr[8]  << 1;

			p1 |= arr[7]  << 0;
			p1 |= arr[6]  << 8;
			p1 |= arr[5]  << 11;
			p1 |= arr[4]  << 3;

			p1 |= arr[3]  << 10;
			p1 |= arr[2]  << 4;
			p1 |= arr[1]  << 5;
			p1 |= arr[0]  << 9;
			PrintAndLog("Pattern 1      : %d [0x%X]", p1, p1);

			uint16_t sebury1 = id & 0xFFFF;
			uint8_t  sebury2 = (id >> 16) & 0x7F;
			uint32_t sebury3 = id & 0x7FFFFF;
			PrintAndLog("Pattern Sebury : %d %d %d  [0x%X 0x%X 0x%X]", sebury1, sebury2, sebury3, sebury1, sebury2, sebury3);
		}
	}
	return;
}

int AskEm410xDecode(bool verbose, uint32_t *hi, uint64_t *lo )
{
	size_t idx = 0;
	size_t BitLen = DemodBufferLen;
	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	memcpy(BitStream, DemodBuffer, BitLen); 
	if (Em410xDecode(BitStream, &BitLen, &idx, hi, lo)){
		//set GraphBuffer for clone or sim command
		setDemodBuf(BitStream, BitLen, idx);
		if (g_debugMode){
			PrintAndLog("DEBUG: idx: %d, Len: %d, Printing Demod Buffer:", idx, BitLen);
			printDemodBuff();
		}
		if (verbose){
			PrintAndLog("EM410x pattern found: ");
			printEM410x(*hi, *lo);
		}
		return 1;
	}
	return 0;
}

int AskEm410xDemod(const char *Cmd, uint32_t *hi, uint64_t *lo, bool verbose)
{
	bool st = TRUE;
	if (!ASKDemod_ext(Cmd, FALSE, FALSE, 1, &st)) return 0;
	return AskEm410xDecode(verbose, hi, lo);
}

//by marshmellow
//takes 3 arguments - clock, invert and maxErr as integers
//attempts to demodulate ask while decoding manchester
//prints binary found and saves in graphbuffer for further commands
int CmdAskEM410xDemod(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 10 || cmdp == 'h' || cmdp == 'H')		
		return usage_data_askem410xdemod();

	uint64_t lo = 0;
	uint32_t hi = 0;
	return AskEm410xDemod(Cmd, &hi, &lo, true);
}

//by marshmellow
//Cmd Args: Clock, invert, maxErr, maxLen as integers and amplify as char == 'a'
//   (amp may not be needed anymore)
//verbose will print results and demoding messages
//emSearch will auto search for EM410x format in bitstream
//askType switches decode: ask/raw = 0, ask/manchester = 1 
int ASKDemod_ext(const char *Cmd, bool verbose, bool emSearch, uint8_t askType, bool *stCheck) {
	int invert=0;
	int clk=0;
	int maxErr=100;
	int maxLen=0;
	uint8_t askAmp = 0;
	char amp = param_getchar(Cmd, 0);
	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	sscanf(Cmd, "%i %i %i %i %c", &clk, &invert, &maxErr, &maxLen, &amp);
	if (!maxLen) maxLen = BIGBUF_SIZE;
	if (invert != 0 && invert != 1) {
		PrintAndLog("Invalid argument: %s", Cmd);
		return 0;
	}
	if (clk==1){
		invert=1;
		clk=0;
	}
	if (amp == 'a' || amp == 'A') askAmp=1; 
	size_t BitLen = getFromGraphBuf(BitStream);
	if (g_debugMode) PrintAndLog("DEBUG: Bitlen from grphbuff: %d",BitLen);
	if (BitLen<255) return 0;
	if (maxLen<BitLen && maxLen != 0) BitLen = maxLen;
	int foundclk = 0;
	bool st = false;
	if (*stCheck) st = DetectST(BitStream, &BitLen, &foundclk);
	if (st) {
		*stCheck = st;
		clk = (clk == 0) ? foundclk : clk;
		if (verbose || g_debugMode) PrintAndLog("\nFound Sequence Terminator");
	}
	int errCnt = askdemod(BitStream, &BitLen, &clk, &invert, maxErr, askAmp, askType);
	if (errCnt<0 || BitLen<16){  //if fatal error (or -1)
		if (g_debugMode) PrintAndLog("DEBUG: no data found %d, errors:%d, bitlen:%d, clock:%d",errCnt,invert,BitLen,clk);
		return 0;
	}
	if (errCnt>maxErr){
		if (g_debugMode) PrintAndLog("DEBUG: Too many errors found, errors:%d, bits:%d, clock:%d",errCnt, BitLen, clk);
		return 0;
	}
	if (verbose || g_debugMode) PrintAndLog("\nUsing Clock:%d, Invert:%d, Bits Found:%d",clk,invert,BitLen);

	//output
	setDemodBuf(BitStream,BitLen,0);
	if (verbose || g_debugMode){
		if (errCnt>0) PrintAndLog("# Errors during Demoding (shown as 7 in bit stream): %d",errCnt);
		if (askType) PrintAndLog("ASK/Manchester - Clock: %d - Decoded bitstream:",clk);
		else PrintAndLog("ASK/Raw - Clock: %d - Decoded bitstream:",clk);
		// Now output the bitstream to the scrollback by line of 16 bits
		printDemodBuff();
		
	}
	uint64_t lo = 0;
	uint32_t hi = 0;
	if (emSearch){
		AskEm410xDecode(true, &hi, &lo);
	}
	return 1;
}
int ASKDemod(const char *Cmd, bool verbose, bool emSearch, uint8_t askType) {
	bool st = false;
	return ASKDemod_ext(Cmd, verbose, emSearch, askType, &st);
}

//by marshmellow
//takes 5 arguments - clock, invert, maxErr, maxLen as integers and amplify as char == 'a'
//attempts to demodulate ask while decoding manchester
//prints binary found and saves in graphbuffer for further commands
int Cmdaskmandemod(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 25 || cmdp == 'h' || cmdp == 'H')
		return usage_data_rawdemod_am();

	bool st = TRUE;
	if (Cmd[0]=='s') 
		return ASKDemod_ext(Cmd++, TRUE, TRUE, 1, &st);
	else if (Cmd[1] == 's')
		return ASKDemod_ext(Cmd+=2, TRUE, TRUE, 1, &st);
	else
	return ASKDemod(Cmd, TRUE, TRUE, 1);
}

//by marshmellow
//manchester decode
//stricktly take 10 and 01 and convert to 0 and 1
int Cmdmandecoderaw(const char *Cmd)
{
	int i =0;
	int errCnt=0;
	size_t size=0;
	int invert=0;
	int maxErr = 20;
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 5 || cmdp == 'h' || cmdp == 'H')
		return usage_data_manrawdecode();

	if (DemodBufferLen==0) return 0;
	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	int high=0,low=0;
	for (;i<DemodBufferLen;++i){
		if (DemodBuffer[i]>high) high=DemodBuffer[i];
		else if(DemodBuffer[i]<low) low=DemodBuffer[i];
		BitStream[i]=DemodBuffer[i];
	}
	if (high>7 || low <0 ){
		PrintAndLog("Error: please raw demod the wave first then manchester raw decode");
		return 0;
	}

	sscanf(Cmd, "%i %i", &invert, &maxErr);
	size=i;
	errCnt=manrawdecode(BitStream, &size, invert);
	if (errCnt>=maxErr){
		PrintAndLog("Too many errors: %d",errCnt);
		return 0;
	}
	PrintAndLog("Manchester Decoded - # errors:%d - data:",errCnt);
	PrintAndLog("%s", sprint_bin_break(BitStream, size, 16));
	if (errCnt==0){
		uint64_t id = 0;
		uint32_t hi = 0;
		size_t idx=0;
		if (Em410xDecode(BitStream, &size, &idx, &hi, &id)){
			//need to adjust to set bitstream back to manchester encoded data
			//setDemodBuf(BitStream, size, idx);

			printEM410x(hi, id);
		}
	}
	return 1;
}

//by marshmellow
//biphase decode
//take 01 or 10 = 0 and 11 or 00 = 1
//takes 2 arguments "offset" default = 0 if 1 it will shift the decode by one bit
// and "invert" default = 0 if 1 it will invert output
//  the argument offset allows us to manually shift if the output is incorrect - [EDIT: now auto detects]
int CmdBiphaseDecodeRaw(const char *Cmd)
{
	size_t size=0;
	int offset=0, invert=0, maxErr=20, errCnt=0;
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 3 || cmdp == 'h' || cmdp == 'H')
		return usage_data_biphaserawdecode();

	sscanf(Cmd, "%i %i %i", &offset, &invert, &maxErr);
	if (DemodBufferLen==0){
		PrintAndLog("DemodBuffer Empty - run 'data rawdemod ar' first");
		return 0;
	}
	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	memcpy(BitStream, DemodBuffer, DemodBufferLen); 
	size = DemodBufferLen;
	errCnt=BiphaseRawDecode(BitStream, &size, offset, invert);
	if (errCnt<0){
		PrintAndLog("Error during decode:%d", errCnt);
		return 0;
	}
	if (errCnt>maxErr){
		PrintAndLog("Too many errors attempting to decode: %d",errCnt);
		return 0;
	}

	if (errCnt>0){
		PrintAndLog("# Errors found during Demod (shown as 7 in bit stream): %d",errCnt);
	}
	PrintAndLog("Biphase Decoded using offset: %d - # invert:%d - data:",offset,invert);
	PrintAndLog("%s", sprint_bin_break(BitStream, size, 16));
	
	if (offset) setDemodBuf(DemodBuffer,DemodBufferLen-offset, offset);  //remove first bit from raw demod
	return 1;
}

//by marshmellow
// - ASK Demod then Biphase decode GraphBuffer samples
int ASKbiphaseDemod(const char *Cmd, bool verbose)
{
	//ask raw demod GraphBuffer first
	int offset=0, clk=0, invert=0, maxErr=0;
	sscanf(Cmd, "%i %i %i %i", &offset, &clk, &invert, &maxErr);
	
	uint8_t BitStream[MAX_DEMOD_BUF_LEN];
	size_t size = getFromGraphBuf(BitStream);	
	if (size == 0 ) {
		if (g_debugMode) PrintAndLog("DEBUG: no data in graphbuf");  
			return 0;  
	}
	//invert here inverts the ask raw demoded bits which has no effect on the demod, but we need the pointer
	int errCnt = askdemod(BitStream, &size, &clk, &invert, maxErr, 0, 0);  
	if ( errCnt < 0 || errCnt > maxErr ) {   
		if (g_debugMode) PrintAndLog("DEBUG: no data or error found %d, clock: %d", errCnt, clk);  
			return 0;  
	} 

	//attempt to Biphase decode BitStream
	errCnt = BiphaseRawDecode(BitStream, &size, offset, invert);
	if (errCnt < 0){
		if (g_debugMode || verbose) PrintAndLog("Error BiphaseRawDecode: %d", errCnt);
		return 0;
	} 
	if (errCnt > maxErr) {
		if (g_debugMode || verbose) PrintAndLog("Error BiphaseRawDecode too many errors: %d", errCnt);
		return 0;
	}
	//success set DemodBuffer and return
	setDemodBuf(BitStream, size, 0);
	if (g_debugMode || verbose){
		PrintAndLog("Biphase Decoded using offset: %d - clock: %d - # errors:%d - data:",offset,clk,errCnt);
		printDemodBuff();
	}
	return 1;
}
//by marshmellow - see ASKbiphaseDemod
int Cmdaskbiphdemod(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 25 || cmdp == 'h' || cmdp == 'H')
		return usage_data_rawdemod_ab();

	return ASKbiphaseDemod(Cmd, TRUE);
}

//by marshmellow
//attempts to demodulate and identify a G_Prox_II verex/chubb card
//WARNING: if it fails during some points it will destroy the DemodBuffer data
// but will leave the GraphBuffer intact.
//if successful it will push askraw data back to demod buffer ready for emulation
int CmdG_Prox_II_Demod(const char *Cmd)
{
	if (!ASKbiphaseDemod(Cmd, FALSE)){
		if (g_debugMode) PrintAndLog("Error gProxII: ASKbiphaseDemod failed 1st try");
		return 0;
	}
	size_t size = DemodBufferLen;
	//call lfdemod.c demod for gProxII
	int ans = gProxII_Demod(DemodBuffer, &size);
	if (ans < 0){
		if (g_debugMode) PrintAndLog("Error gProxII_Demod");
		return 0;
	}
	//got a good demod of 96 bits
	uint8_t ByteStream[8] = {0x00};
	uint8_t xorKey=0;
	size_t startIdx = ans + 6; //start after 6 bit preamble

	uint8_t bits_no_spacer[90];
	//so as to not mess with raw DemodBuffer copy to a new sample array
	memcpy(bits_no_spacer, DemodBuffer + startIdx, 90);
	// remove the 18 (90/5=18) parity bits (down to 72 bits (96-6-18=72))
	size_t bitLen = removeParity(bits_no_spacer, 0, 5, 3, 90); //source, startloc, paritylen, ptype, length_to_run
	if (bitLen != 72) {
		if (g_debugMode) PrintAndLog("Error gProxII: spacer removal did not produce 72 bits: %u, start: %u", bitLen, startIdx);
				return 0;
			}
	// get key and then get all 8 bytes of payload decoded
	xorKey = (uint8_t)bytebits_to_byteLSBF(bits_no_spacer, 8);
	for (size_t idx = 0; idx < 8; idx++) {
		ByteStream[idx] = ((uint8_t)bytebits_to_byteLSBF(bits_no_spacer+8 + (idx*8),8)) ^ xorKey;
		if (g_debugMode) PrintAndLog("byte %u after xor: %02x", (unsigned int)idx, ByteStream[idx]);
	}
	//now ByteStream contains 8 Bytes (64 bits) of decrypted raw tag data
	// 
	uint8_t fmtLen = ByteStream[0]>>2;
	uint32_t FC = 0;
	uint32_t Card = 0;
	//get raw 96 bits to print
	uint32_t raw1 = bytebits_to_byte(DemodBuffer+ans,32);
	uint32_t raw2 = bytebits_to_byte(DemodBuffer+ans+32, 32);
	uint32_t raw3 = bytebits_to_byte(DemodBuffer+ans+64, 32);

	if (fmtLen==36){
		FC = ((ByteStream[3] & 0x7F)<<7) | (ByteStream[4]>>1);
		Card = ((ByteStream[4]&1)<<19) | (ByteStream[5]<<11) | (ByteStream[6]<<3) | (ByteStream[7]>>5);
		PrintAndLog("G-Prox-II Found: FmtLen %d, FC %u, Card %u", (int)fmtLen, FC, Card);
	} else if(fmtLen==26){
		FC = ((ByteStream[3] & 0x7F)<<1) | (ByteStream[4]>>7);
		Card = ((ByteStream[4]&0x7F)<<9) | (ByteStream[5]<<1) | (ByteStream[6]>>7);
		PrintAndLog("G-Prox-II Found: FmtLen %d, FC %u, Card %u", (int)fmtLen, FC, Card);
	} else {
		PrintAndLog("Unknown G-Prox-II Fmt Found: FmtLen %d",(int)fmtLen);
		PrintAndLog("Decoded Raw: %s", sprint_hex(ByteStream, 8)); 
	}
	PrintAndLog("Raw: %08x%08x%08x", raw1,raw2,raw3);
	setDemodBuf(DemodBuffer+ans, 96, 0);
	return 1;
}

//by marshmellow
//see ASKDemod for what args are accepted
int CmdVikingDemod(const char *Cmd)
{
	if (!ASKDemod(Cmd, false, false, 1)) {
		if (g_debugMode) PrintAndLog("ASKDemod failed");
		return 0;
	}
	size_t size = DemodBufferLen;
	//call lfdemod.c demod for Viking
	int ans = VikingDemod_AM(DemodBuffer, &size);
	if (ans < 0) {
		if (g_debugMode) PrintAndLog("Error Viking_Demod %d %s", ans, (ans == -5)?"[chksum error]":"");
		return 0;
	}
	//got a good demod
	uint32_t raw1 = bytebits_to_byte(DemodBuffer+ans, 32);
	uint32_t raw2 = bytebits_to_byte(DemodBuffer+ans+32, 32);
	uint32_t cardid = bytebits_to_byte(DemodBuffer+ans+24, 32);
	uint8_t  checksum = bytebits_to_byte(DemodBuffer+ans+32+24, 8);
	PrintAndLog("Viking Tag Found: Card ID %08X, Checksum: %02X", cardid, checksum);
	PrintAndLog("Raw: %08X%08X", raw1,raw2);
	setDemodBuf(DemodBuffer+ans, 64, 0);
	return 1;
}

//by marshmellow - see ASKDemod
int Cmdaskrawdemod(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 25 || cmdp == 'h' || cmdp == 'H')
		return usage_data_rawdemod_ar();
	
	return ASKDemod(Cmd, TRUE, FALSE, 0);
}

int AutoCorrelate(int window, bool SaveGrph, bool verbose)
{
	static int CorrelBuffer[MAX_GRAPH_TRACE_LEN];
	size_t Correlation = 0;
	int maxSum = 0;
	int lastMax = 0;
	if (verbose) PrintAndLog("performing %d correlations", GraphTraceLen - window);
	for (int i = 0; i < GraphTraceLen - window; ++i) {
		int sum = 0;
		for (int j = 0; j < window; ++j) {
			sum += (GraphBuffer[j]*GraphBuffer[i + j]) / 256;
		}
		CorrelBuffer[i] = sum;
		if (sum >= maxSum-100 && sum <= maxSum+100){
			//another max
			Correlation = i-lastMax;
			lastMax = i;
			if (sum > maxSum) maxSum = sum;
		} else if (sum > maxSum){
			maxSum=sum;
			lastMax = i;
		}
	}
	if (Correlation==0){
		//try again with wider margin
		for (int i = 0; i < GraphTraceLen - window; i++){
			if (CorrelBuffer[i] >= maxSum-(maxSum*0.05) && CorrelBuffer[i] <= maxSum+(maxSum*0.05)){
				//another max
				Correlation = i-lastMax;
				lastMax = i;
				//if (CorrelBuffer[i] > maxSum) maxSum = sum;
			}
		}
	}
	if (verbose && Correlation > 0) PrintAndLog("Possible Correlation: %d samples",Correlation);

	if (SaveGrph){
		GraphTraceLen = GraphTraceLen - window;
		memcpy(GraphBuffer, CorrelBuffer, GraphTraceLen * sizeof (int));
		RepaintGraphWindow();  
	}
	return Correlation;
}

int CmdAutoCorr(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	if (cmdp == 'h' || cmdp == 'H') return usage_data_autocorr();
	int window = 4000; //set default
	char grph=0;
	bool updateGrph = FALSE;
	sscanf(Cmd, "%i %c", &window, &grph);

	if (window >= GraphTraceLen) {
		PrintAndLog("window must be smaller than trace (%d samples)",
			GraphTraceLen);
		return 0;
	}
	if (grph == 'g') updateGrph=TRUE;
	return AutoCorrelate(window, updateGrph, TRUE);
}

int CmdBitsamples(const char *Cmd)
{
	int cnt = 0;
	uint8_t got[12288];

	GetFromBigBuf(got, sizeof(got), 0);
	WaitForResponse(CMD_ACK, NULL);

	for (int j = 0; j < sizeof(got); j++) {
		for (int k = 0; k < 8; k++) {
			if(got[j] & (1 << (7 - k))) {
				GraphBuffer[cnt++] = 1;
			} else {
				GraphBuffer[cnt++] = 0;
			}
		}
	}
	GraphTraceLen = cnt;
	RepaintGraphWindow();
	return 0;
}

int CmdBuffClear(const char *Cmd)
{
	UsbCommand c = {CMD_BUFF_CLEAR, {0,0,0}};
	SendCommand(&c);
	ClearGraph(true);
	return 0;
}

int CmdDec(const char *Cmd)
{
	for (int i = 0; i < (GraphTraceLen >> 2); ++i)
		GraphBuffer[i] = GraphBuffer[i * 2];

	GraphTraceLen >>= 2;
	PrintAndLog("decimated by 2");
	RepaintGraphWindow();
	return 0;
}
/**
 * Undecimate - I'd call it 'interpolate', but we'll save that
 * name until someone does an actual interpolation command, not just
 * blindly repeating samples
 * @param Cmd
 * @return
 */
int CmdUndec(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	if (cmdp == 'h' || cmdp == 'H')
		return usage_data_undecimate();

	uint8_t factor = param_get8ex(Cmd, 0, 2, 10);

	//We have memory, don't we?
	int swap[MAX_GRAPH_TRACE_LEN] = { 0 };
	uint32_t g_index = 0 ,s_index = 0;
	while(g_index < GraphTraceLen && s_index + factor < MAX_GRAPH_TRACE_LEN)
	{
		int count = 0;
		for (count = 0; count < factor && s_index + count < MAX_GRAPH_TRACE_LEN; count++)
			swap[s_index+count] = GraphBuffer[g_index];
		s_index += count;
		g_index++;
	}

	memcpy(GraphBuffer, swap, s_index * sizeof(int));
	GraphTraceLen = s_index;
	RepaintGraphWindow();
	return 0;
}

//by marshmellow
//shift graph zero up or down based on input + or -
int CmdGraphShiftZero(const char *Cmd)
{
	int shift=0;
	//set options from parameters entered with the command
	sscanf(Cmd, "%i", &shift);
	int shiftedVal=0;
	for(int i = 0; i<GraphTraceLen; i++){
		shiftedVal=GraphBuffer[i]+shift;
		if (shiftedVal>127) 
			shiftedVal=127;
		else if (shiftedVal<-127) 
			shiftedVal=-127;
		GraphBuffer[i]= shiftedVal;
	}
	CmdNorm("");
	return 0;
}

//by marshmellow
//use large jumps in read samples to identify edges of waves and then amplify that wave to max
//similar to dirtheshold, threshold commands 
//takes a threshold length which is the measured length between two samples then determines an edge
int CmdAskEdgeDetect(const char *Cmd)
{
	int thresLen = 25;
	int last = 0;
	sscanf(Cmd, "%i", &thresLen); 

	for(int i = 1; i < GraphTraceLen; ++i){
		if (GraphBuffer[i] - GraphBuffer[i-1] >= thresLen) //large jump up
			last = 127;
		else if(GraphBuffer[i] - GraphBuffer[i-1] <= -1 * thresLen) //large jump down
			last = -127;
			
		GraphBuffer[i-1] = last;
	}
	RepaintGraphWindow();
	return 0;
}

/* Print our clock rate */
// uses data from graphbuffer
// adjusted to take char parameter for type of modulation to find the clock - by marshmellow.
int CmdDetectClockRate(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 6 || strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H')
		return usage_data_detectclock();

	int ans = 0;
	switch ( cmdp ) {
		case 'a' :
		case 'A' :
			ans = GetAskClock(Cmd+1, true, false);
			break;
		case 'f' :
		case 'F' :
			ans = GetFskClock("", true, false);
			break;
		case 'n' :
		case 'N' :
			ans = GetNrzClock("", true, false);
			break;
		case 'p' :
		case 'P' :
			ans = GetPskClock("", true, false);
			break;
		default :
			PrintAndLog ("Please specify a valid modulation to detect the clock of - see option h for help");
			break;
	}
	return ans;
}

char *GetFSKType(uint8_t fchigh, uint8_t fclow, uint8_t invert)
{
	static char fType[8];
	memset(fType, 0x00, 8);	
	char *fskType = fType;
	if (fchigh==10 && fclow==8){
		if (invert) //fsk2a
			memcpy(fskType, "FSK2a", 5);
		else //fsk2
			memcpy(fskType, "FSK2", 4);
	} else if (fchigh == 8 && fclow == 5) {
		if (invert)
			memcpy(fskType, "FSK1", 4);
		else
			memcpy(fskType, "FSK1a", 5);
	} else {
		memcpy(fskType, "FSK??", 5);
	}
	return fskType;
}

//by marshmellow
//fsk raw demod and print binary
//takes 4 arguments - Clock, invert, fchigh, fclow
//defaults: clock = 50, invert=1, fchigh=10, fclow=8 (RF/10 RF/8 (fsk2a))
int FSKrawDemod(const char *Cmd, bool verbose)
{
	//raw fsk demod  no manchester decoding no start bit finding just get binary from wave
	uint8_t rfLen, invert, fchigh, fclow;

	//set defaults
	//set options from parameters entered with the command
	rfLen = param_get8(Cmd, 0);
	invert = param_get8(Cmd, 1);
	fchigh = param_get8(Cmd, 2);
	fclow = param_get8(Cmd, 3);
	if (strlen(Cmd)>0 && strlen(Cmd)<=2) {
		if (rfLen==1) {
			invert = 1;   //if invert option only is used
			rfLen = 0;
		}
	}

	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	size_t BitLen = getFromGraphBuf(BitStream);
	if (BitLen==0) return 0;
	//get field clock lengths
	uint16_t fcs=0;
	if (!fchigh || !fclow) {
		fcs = countFC(BitStream, BitLen, 1);
		if (!fcs) {
			fchigh = 10;
			fclow = 8;
		} else {
			fchigh = (fcs >> 8) & 0x00FF;
			fclow = fcs & 0x00FF;
		}
	}
	//get bit clock length
	if (!rfLen) {
		rfLen = detectFSKClk(BitStream, BitLen, fchigh, fclow);
		if (!rfLen) rfLen = 50;
	}
	int size = fskdemod(BitStream, BitLen, rfLen, invert, fchigh, fclow);
	if (size > 0) {
		setDemodBuf(BitStream, size, 0);

		// Now output the bitstream to the scrollback by line of 16 bits
		if (verbose || g_debugMode) {
			PrintAndLog("\nUsing Clock:%u, invert:%u, fchigh:%u, fclow:%u", (unsigned int)rfLen,  (unsigned int)invert,  (unsigned int)fchigh,  (unsigned int)fclow);
			PrintAndLog("%s decoded bitstream:", GetFSKType(fchigh, fclow, invert));
			printDemodBuff();
		}

		return 1;
	} else {
		if (g_debugMode) PrintAndLog("no FSK data found");
	}
	return 0;
}

//by marshmellow
//fsk raw demod and print binary
//takes 4 arguments - Clock, invert, fchigh, fclow
//defaults: clock = 50, invert=1, fchigh=10, fclow=8 (RF/10 RF/8 (fsk2a))
int CmdFSKrawdemod(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 10 || cmdp == 'h' || cmdp == 'H')
		return usage_data_rawdemod_fs();

	return FSKrawDemod(Cmd, TRUE);
}

//by marshmellow (based on existing demod + holiman's refactor)
//HID Prox demod - FSK RF/50 with preamble of 00011101 (then manchester encoded)
//print full HID Prox ID and some bit format details if found
int CmdFSKdemodHID(const char *Cmd)
{
	//raw fsk demod no manchester decoding no start bit finding just get binary from wave
	uint32_t hi2=0, hi=0, lo=0;

	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	size_t BitLen = getFromGraphBuf(BitStream);
	if (BitLen==0) return 0;
	//get binary from fsk wave
	int idx = HIDdemodFSK(BitStream,&BitLen,&hi2,&hi,&lo);
	if (idx<0){
		if (g_debugMode){
			if (idx==-1){
				PrintAndLog("DEBUG: Just Noise Detected");
			} else if (idx == -2) {
				PrintAndLog("DEBUG: Error demoding fsk");
			} else if (idx == -3) {
				PrintAndLog("DEBUG: Preamble not found");
			} else if (idx == -4) {
				PrintAndLog("DEBUG: Error in Manchester data, SIZE: %d", BitLen);
			} else {
				PrintAndLog("DEBUG: Error demoding fsk %d", idx);
			}   
		}
		return 0;
	}
	if (hi2==0 && hi==0 && lo==0) {
		if (g_debugMode) PrintAndLog("DEBUG: Error - no values found");
		return 0;
	}
	if (hi2 != 0){ //extra large HID tags
		PrintAndLog("HID Prox TAG ID: %x%08x%08x (%d)",
			 (unsigned int) hi2, (unsigned int) hi, (unsigned int) lo, (unsigned int) (lo>>1) & 0xFFFF);
	}
	else {  //standard HID tags <38 bits
		uint8_t fmtLen = 0;
		uint32_t fc = 0;
		uint32_t cardnum = 0;
		if (((hi>>5)&1)==1){//if bit 38 is set then < 37 bit format is used
			uint32_t lo2=0;
			lo2=(((hi & 31) << 12) | (lo>>20)); //get bits 21-37 to check for format len bit
			uint8_t idx3 = 1;
			while(lo2>1){ //find last bit set to 1 (format len bit)
				lo2=lo2>>1;
				idx3++;
			}
			fmtLen =idx3+19;
			fc =0;
			cardnum=0;
			if(fmtLen==26){
				cardnum = (lo>>1)&0xFFFF;
				fc = (lo>>17)&0xFF;
			}
			if(fmtLen==34){
				cardnum = (lo>>1)&0xFFFF;
				fc= ((hi&1)<<15)|(lo>>17);
			}
			if(fmtLen==35){
				cardnum = (lo>>1)&0xFFFFF;
				fc = ((hi&1)<<11)|(lo>>21);
			}
		}
		else { //if bit 38 is not set then 37 bit format is used
			fmtLen = 37;
			fc = 0;
			cardnum = 0;
			if(fmtLen == 37){
				cardnum = (lo>>1)&0x7FFFF;
				fc = ((hi&0xF)<<12)|(lo>>20);
			}
		}
		PrintAndLog("HID Prox TAG ID: %x%08x (%d) - Format Len: %dbit - FC: %d - Card: %d",
			(unsigned int) hi, (unsigned int) lo, (unsigned int) (lo>>1) & 0xFFFF,
			(unsigned int) fmtLen, (unsigned int) fc, (unsigned int) cardnum);
	}
	setDemodBuf(BitStream,BitLen,idx);
	if (g_debugMode){ 
		PrintAndLog("DEBUG: idx: %d, Len: %d, Printing Demod Buffer:", idx, BitLen);
		printDemodBuff();
	}
	return 1;
}

//by marshmellow
//Paradox Prox demod - FSK RF/50 with preamble of 00001111 (then manchester encoded)
//print full Paradox Prox ID and some bit format details if found
int CmdFSKdemodParadox(const char *Cmd)
{
	//raw fsk demod no manchester decoding no start bit finding just get binary from wave
	uint32_t hi2=0, hi=0, lo=0;

	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	size_t BitLen = getFromGraphBuf(BitStream);
	if (BitLen==0) return 0;
	//get binary from fsk wave
	int idx = ParadoxdemodFSK(BitStream,&BitLen,&hi2,&hi,&lo);
	if (idx<0){
		if (g_debugMode){
			if (idx==-1){
				PrintAndLog("DEBUG: Just Noise Detected");     
			} else if (idx == -2) {
				PrintAndLog("DEBUG: Error demoding fsk");
			} else if (idx == -3) {
				PrintAndLog("DEBUG: Preamble not found");
			} else if (idx == -4) {
				PrintAndLog("DEBUG: Error in Manchester data");
			} else {
				PrintAndLog("DEBUG: Error demoding fsk %d", idx);
			}
		}
		return 0;
	}
	if (hi2==0 && hi==0 && lo==0){
		if (g_debugMode) PrintAndLog("DEBUG: Error - no value found");
		return 0;
	}
	uint32_t fc = ((hi & 0x3)<<6) | (lo>>26);
	uint32_t cardnum = (lo>>10)&0xFFFF;
	uint32_t rawLo = bytebits_to_byte(BitStream+idx+64,32);
	uint32_t rawHi = bytebits_to_byte(BitStream+idx+32,32);
	uint32_t rawHi2 = bytebits_to_byte(BitStream+idx,32);

	PrintAndLog("Paradox TAG ID: %x%08x - FC: %d - Card: %d - Checksum: %02x - RAW: %08x%08x%08x",
		hi>>10, (hi & 0x3)<<26 | (lo>>10), fc, cardnum, (lo>>2) & 0xFF, rawHi2, rawHi, rawLo);
	setDemodBuf(BitStream,BitLen,idx);
	if (g_debugMode){ 
		PrintAndLog("DEBUG: idx: %d, len: %d, Printing Demod Buffer:", idx, BitLen);
		printDemodBuff();
	}
	return 1;
}

//by marshmellow
//IO-Prox demod - FSK RF/64 with preamble of 000000001
//print ioprox ID and some format details
int CmdFSKdemodIO(const char *Cmd)
{
	int idx=0;
	//something in graphbuffer?
	if (GraphTraceLen < 65) {
		if (g_debugMode)PrintAndLog("DEBUG: not enough samples in GraphBuffer");
		return 0;
	}
	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	size_t BitLen = getFromGraphBuf(BitStream);
	if (BitLen==0) return 0;

	//get binary from fsk wave
	idx = IOdemodFSK(BitStream,BitLen);
	if (idx<0){
		if (g_debugMode){
			if (idx==-1){
				PrintAndLog("DEBUG: Just Noise Detected");     
			} else if (idx == -2) {
				PrintAndLog("DEBUG: not enough samples");
			} else if (idx == -3) {
				PrintAndLog("DEBUG: error during fskdemod");        
			} else if (idx == -4) {
				PrintAndLog("DEBUG: Preamble not found");
			} else if (idx == -5) {
				PrintAndLog("DEBUG: Separator bits not found");
			} else {
				PrintAndLog("DEBUG: Error demoding fsk %d", idx);
			}
		}
		return 0;
	}
	if (idx==0){
		if (g_debugMode){
			PrintAndLog("DEBUG: IO Prox Data not found - FSK Bits: %d",BitLen);
			if (BitLen > 92) PrintAndLog("%s", sprint_bin_break(BitStream,92,16));
		} 
		return 0;
	}
		//Index map
		//0           10          20          30          40          50          60
		//|           |           |           |           |           |           |
		//01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
		//-----------------------------------------------------------------------------
		//00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1 ???????? 11
		//
		//XSF(version)facility:codeone+codetwo (raw)
		//Handle the data
	if (idx+64>BitLen) {
		if (g_debugMode) PrintAndLog("not enough bits found - bitlen: %d",BitLen);
		return 0;
	}
	PrintAndLog("%d%d%d%d%d%d%d%d %d",BitStream[idx],    BitStream[idx+1],  BitStream[idx+2], BitStream[idx+3], BitStream[idx+4], BitStream[idx+5], BitStream[idx+6], BitStream[idx+7], BitStream[idx+8]);
	PrintAndLog("%d%d%d%d%d%d%d%d %d",BitStream[idx+9],  BitStream[idx+10], BitStream[idx+11],BitStream[idx+12],BitStream[idx+13],BitStream[idx+14],BitStream[idx+15],BitStream[idx+16],BitStream[idx+17]);
	PrintAndLog("%d%d%d%d%d%d%d%d %d facility",BitStream[idx+18], BitStream[idx+19], BitStream[idx+20],BitStream[idx+21],BitStream[idx+22],BitStream[idx+23],BitStream[idx+24],BitStream[idx+25],BitStream[idx+26]);
	PrintAndLog("%d%d%d%d%d%d%d%d %d version",BitStream[idx+27], BitStream[idx+28], BitStream[idx+29],BitStream[idx+30],BitStream[idx+31],BitStream[idx+32],BitStream[idx+33],BitStream[idx+34],BitStream[idx+35]);
	PrintAndLog("%d%d%d%d%d%d%d%d %d code1",BitStream[idx+36], BitStream[idx+37], BitStream[idx+38],BitStream[idx+39],BitStream[idx+40],BitStream[idx+41],BitStream[idx+42],BitStream[idx+43],BitStream[idx+44]);
	PrintAndLog("%d%d%d%d%d%d%d%d %d code2",BitStream[idx+45], BitStream[idx+46], BitStream[idx+47],BitStream[idx+48],BitStream[idx+49],BitStream[idx+50],BitStream[idx+51],BitStream[idx+52],BitStream[idx+53]);
	PrintAndLog("%d%d%d%d%d%d%d%d %d%d checksum",BitStream[idx+54],BitStream[idx+55],BitStream[idx+56],BitStream[idx+57],BitStream[idx+58],BitStream[idx+59],BitStream[idx+60],BitStream[idx+61],BitStream[idx+62],BitStream[idx+63]);

	uint32_t code = bytebits_to_byte(BitStream+idx,32);
	uint32_t code2 = bytebits_to_byte(BitStream+idx+32,32);
	uint8_t version = bytebits_to_byte(BitStream+idx+27,8); //14,4
	uint8_t facilitycode = bytebits_to_byte(BitStream+idx+18,8) ;
	uint16_t number = (bytebits_to_byte(BitStream+idx+36,8)<<8)|(bytebits_to_byte(BitStream+idx+45,8)); //36,9
	uint8_t crc = bytebits_to_byte(BitStream+idx+54,8);
	uint16_t calccrc = 0;

	for (uint8_t i=1; i<6; ++i){
		calccrc += bytebits_to_byte(BitStream+idx+9*i,8);
	}
	calccrc &= 0xff;
	calccrc = 0xff - calccrc;

	char *crcStr = (crc == calccrc) ? "crc ok": "!crc";

	PrintAndLog("IO Prox XSF(%02d)%02x:%05d (%08x%08x) [%02x %s]",version,facilitycode,number,code,code2, crc, crcStr);
	setDemodBuf(BitStream,64,idx);
	if (g_debugMode){
		PrintAndLog("DEBUG: idx: %d, Len: %d, Printing demod buffer:",idx,64);
		printDemodBuff();
	}
	return 1;
}

//by marshmellow
//AWID Prox demod - FSK RF/50 with preamble of 00000001  (always a 96 bit data stream)
//print full AWID Prox ID and some bit format details if found
int CmdFSKdemodAWID(const char *Cmd)
{
	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	size_t size = getFromGraphBuf(BitStream);
	if (size==0) return 0;

	//get binary from fsk wave
	int idx = AWIDdemodFSK(BitStream, &size);
	if (idx<=0){
		if (g_debugMode){
			if (idx == -1)
				PrintAndLog("DEBUG: Error - not enough samples");
			else if (idx == -2)
				PrintAndLog("DEBUG: Error - only noise found");
			else if (idx == -3)
				PrintAndLog("DEBUG: Error - problem during FSK demod");
			else if (idx == -4)
				PrintAndLog("DEBUG: Error - AWID preamble not found");
			else if (idx == -5)
				PrintAndLog("DEBUG: Error - Size not correct: %d", size);
			else
				PrintAndLog("DEBUG: Error %d",idx);
		}
		return 0;
	}

	// Index map
	// 0            10            20            30              40            50              60
	// |            |             |             |               |             |               |
	// 01234567 890 1 234 5 678 9 012 3 456 7 890 1 234 5 678 9 012 3 456 7 890 1 234 5 678 9 012 3 - to 96
	// -----------------------------------------------------------------------------
	// 00000001 000 1 110 1 101 1 011 1 101 1 010 0 000 1 000 1 010 0 001 0 110 1 100 0 000 1 000 1
	// premable bbb o bbb o bbw o fff o fff o ffc o ccc o ccc o ccc o ccc o ccc o wxx o xxx o xxx o - to 96
	//          |---26 bit---|    |-----117----||-------------142-------------|
	// b = format bit len, o = odd parity of last 3 bits
	// f = facility code, c = card number
	// w = wiegand parity
	// (26 bit format shown)
 
	//get raw ID before removing parities
	uint32_t rawLo = bytebits_to_byte(BitStream+idx+64,32);
	uint32_t rawHi = bytebits_to_byte(BitStream+idx+32,32);
	uint32_t rawHi2 = bytebits_to_byte(BitStream+idx,32);
	setDemodBuf(BitStream,96,idx);

	size = removeParity(BitStream, idx+8, 4, 1, 88);
	if (size != 66){
		if (g_debugMode) PrintAndLog("DEBUG: Error - at parity check-tag size does not match AWID format");
		return 0;
	}
	// ok valid card found!

	// Index map
	// 0           10         20        30          40        50        60
	// |           |          |         |           |         |         |
	// 01234567 8 90123456 7890123456789012 3 456789012345678901234567890123456
	// -----------------------------------------------------------------------------
	// 00011010 1 01110101 0000000010001110 1 000000000000000000000000000000000
	// bbbbbbbb w ffffffff cccccccccccccccc w xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	// |26 bit|   |-117--| |-----142------|
    //
	// 00110010 0 0000111110100000 00000000000100010010100010000111 1 000000000 
	// bbbbbbbb w ffffffffffffffff cccccccccccccccccccccccccccccccc w xxxxxxxxx
	// |50 bit|   |----4000------| |-----------2248975------------| 
	// b = format bit len, o = odd parity of last 3 bits
	// f = facility code, c = card number
	// w = wiegand parity

	uint32_t fc = 0;
	uint32_t cardnum = 0;
	uint32_t code1 = 0;
	uint32_t code2 = 0;
	uint8_t fmtLen = bytebits_to_byte(BitStream, 8);
	switch(fmtLen) {
		case 26: 
			fc = bytebits_to_byte(BitStream + 9, 8);
			cardnum = bytebits_to_byte(BitStream + 17, 16);
			code1 = bytebits_to_byte(BitStream + 8,fmtLen);
			PrintAndLog("AWID Found - BitLength: %d, FC: %d, Card: %u - Wiegand: %x, Raw: %08x%08x%08x", fmtLen, fc, cardnum, code1, rawHi2, rawHi, rawLo);
			break;
		case 50:
			fc = bytebits_to_byte(BitStream + 9, 16);
			cardnum = bytebits_to_byte(BitStream + 25, 32);
			code1 = bytebits_to_byte(BitStream + 8, (fmtLen-32) );
			code2 = bytebits_to_byte(BitStream + 8 + (fmtLen-32), 32);
			PrintAndLog("AWID Found - BitLength: %d, FC: %d, Card: %u - Wiegand: %x%08x, Raw: %08x%08x%08x", fmtLen, fc, cardnum, code1, code2, rawHi2, rawHi, rawLo);
			break;
		default:
			if (fmtLen > 32 ) {
				cardnum = bytebits_to_byte(BitStream+8+(fmtLen-17), 16);
				code1 = bytebits_to_byte(BitStream+8,fmtLen-32);
				code2 = bytebits_to_byte(BitStream+8+(fmtLen-32),32);
				PrintAndLog("AWID Found - BitLength: %d -unknown BitLength- (%u) - Wiegand: %x%08x, Raw: %08x%08x%08x", fmtLen, cardnum, code1, code2, rawHi2, rawHi, rawLo);
			} else {
				cardnum = bytebits_to_byte(BitStream+8+(fmtLen-17), 16);
				code1 = bytebits_to_byte(BitStream+8,fmtLen);
				PrintAndLog("AWID Found - BitLength: %d -unknown BitLength- (%u) - Wiegand: %x, Raw: %08x%08x%08x", fmtLen, cardnum, code1, rawHi2, rawHi, rawLo);
			}
			break;		
	}

	if (g_debugMode){
		PrintAndLog("DEBUG: idx: %d, Len: %d Printing Demod Buffer:", idx, 96);
		printDemodBuff();
	}
	return 1;
}

//by marshmellow
//Pyramid Prox demod - FSK RF/50 with preamble of 0000000000000001  (always a 128 bit data stream)
//print full Farpointe Data/Pyramid Prox ID and some bit format details if found
int CmdFSKdemodPyramid(const char *Cmd)
{
	//raw fsk demod no manchester decoding no start bit finding just get binary from wave
	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	size_t size = getFromGraphBuf(BitStream);
	if (size==0) return 0;

	//get binary from fsk wave
	int idx = PyramiddemodFSK(BitStream, &size);
	if (idx < 0){
		if (g_debugMode){
			if (idx == -5)
				PrintAndLog("DEBUG: Error - not enough samples");
			else if (idx == -1)
				PrintAndLog("DEBUG: Error - only noise found");
			else if (idx == -2)
				PrintAndLog("DEBUG: Error - problem during FSK demod");
			else if (idx == -3)
				PrintAndLog("DEBUG: Error - Size not correct: %d", size);
			else if (idx == -4)
				PrintAndLog("DEBUG: Error - Pyramid preamble not found");
			else
				PrintAndLog("DEBUG: Error - idx: %d",idx);
		}
		return 0;
	}
	// Index map
	// 0           10          20          30            40          50          60
	// |           |           |           |             |           |           |
	// 0123456 7 8901234 5 6789012 3 4567890 1 2345678 9 0123456 7 8901234 5 6789012 3
	// -----------------------------------------------------------------------------
	// 0000000 0 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1
	// premable  xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o

	// 64    70            80          90          100         110           120
	// |     |             |           |           |           |             |
	// 4567890 1 2345678 9 0123456 7 8901234 5 6789012 3 4567890 1 2345678 9 0123456 7
	// -----------------------------------------------------------------------------
	// 0000000 1 0000000 1 0000000 1 0110111 0 0011000 1 0000001 0 0001100 1 1001010 0
	// xxxxxxx o xxxxxxx o xxxxxxx o xswffff o ffffccc o ccccccc o ccccccw o ppppppp o
	//                                  |---115---||---------71---------|
	// s = format start bit, o = odd parity of last 7 bits
	// f = facility code, c = card number
	// w = wiegand parity, x = extra space for other formats
	// p = CRC8maxim checksum
	// (26 bit format shown)

	//get bytes for checksum calc
	uint8_t checksum = bytebits_to_byte(BitStream + idx + 120, 8);
	uint8_t csBuff[14] = {0x00};
	for (uint8_t i = 0; i < 13; i++){
		csBuff[i] = bytebits_to_byte(BitStream + idx + 16 + (i*8), 8);
	}
	//check checksum calc
	//checksum calc thanks to ICEMAN!!
	uint32_t checkCS =  CRC8Maxim(csBuff,13);

	//get raw ID before removing parities
	uint32_t rawLo = bytebits_to_byte(BitStream+idx+96,32);
	uint32_t rawHi = bytebits_to_byte(BitStream+idx+64,32);
	uint32_t rawHi2 = bytebits_to_byte(BitStream+idx+32,32);
	uint32_t rawHi3 = bytebits_to_byte(BitStream+idx,32);
	setDemodBuf(BitStream,128,idx);

	size = removeParity(BitStream, idx+8, 8, 1, 120);
	if (size != 105){
		if (g_debugMode) 
			PrintAndLog("DEBUG: Error at parity check - tag size does not match Pyramid format, SIZE: %d, IDX: %d, hi3: %x",size, idx, rawHi3);
		return 0;
	}

	// ok valid card found!

	// Index map
	// 0         10        20        30        40        50        60        70
	// |         |         |         |         |         |         |         |
	// 01234567890123456789012345678901234567890123456789012345678901234567890
	// -----------------------------------------------------------------------
	// 00000000000000000000000000000000000000000000000000000000000000000000000
	// xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

	// 71         80         90          100
	// |          |          |           |
	// 1 2 34567890 1234567890123456 7 8901234
	// ---------------------------------------
	// 1 1 01110011 0000000001000110 0 1001010
	// s w ffffffff cccccccccccccccc w ppppppp
	//     |--115-| |------71------|
	// s = format start bit, o = odd parity of last 7 bits
	// f = facility code, c = card number
	// w = wiegand parity, x = extra space for other formats
	// p = CRC8-Maxim checksum
	// (26 bit format shown)

	//find start bit to get fmtLen
	int j;
	for (j=0; j < size; ++j){
		if(BitStream[j]) break;
	}
	
	uint8_t fmtLen = size-j-8;
	uint32_t fc = 0;
	uint32_t cardnum = 0;
	uint32_t code1 = 0;
	
	if ( fmtLen == 26 ){
		fc = bytebits_to_byte(BitStream+73, 8);
		cardnum = bytebits_to_byte(BitStream+81, 16);
		code1 = bytebits_to_byte(BitStream+72,fmtLen);
		PrintAndLog("Pyramid ID Found - BitLength: %d, FC: %d, Card: %d - Wiegand: %x, Raw: %08x%08x%08x%08x", fmtLen, fc, cardnum, code1, rawHi3, rawHi2, rawHi, rawLo);
	} else if (fmtLen == 45) {
		fmtLen = 42; //end = 10 bits not 7 like 26 bit fmt
		fc = bytebits_to_byte(BitStream+53, 10);
		cardnum = bytebits_to_byte(BitStream+63, 32);
		PrintAndLog("Pyramid ID Found - BitLength: %d, FC: %d, Card: %d - Raw: %08x%08x%08x%08x", fmtLen, fc, cardnum, rawHi3, rawHi2, rawHi, rawLo);
	} else {
		cardnum = bytebits_to_byte(BitStream+81, 16);
		PrintAndLog("Pyramid ID Found - BitLength: %d -unknown BitLength- (%d), Raw: %08x%08x%08x%08x", fmtLen, cardnum, rawHi3, rawHi2, rawHi, rawLo);
	}
	if (checksum == checkCS)
		PrintAndLog("Checksum %02x passed", checksum);
	else
		PrintAndLog("Checksum %02x failed - should have been %02x", checksum, checkCS);

	if (g_debugMode){
		PrintAndLog("DEBUG: idx: %d, Len: %d, Printing Demod Buffer:", idx, 128);
		printDemodBuff();
	}
	return 1;
}

// FDX-B ISO11784/85 demod  (aka animal tag)  BIPHASE, inverted, rf/32,  with preamble of 00000000001 (128bits)
// 8 databits + 1 parity (1)
// CIITT 16 chksum
// NATIONAL CODE, ICAR database
// COUNTRY CODE (ISO3166) or http://cms.abvma.ca/uploads/ManufacturersISOsandCountryCodes.pdf
// FLAG (animal/non-animal)
/*
38 IDbits   
10 country code 
1 extra app bit
14 reserved bits
1 animal bit
16 ccitt CRC chksum over 64bit ID CODE.
24 appli bits.

-- sample: 985121004515220  [ 37FF65B88EF94 ]
*/
int CmdFDXBdemodBI(const char *Cmd){

	int invert = 1;
	int clk = 32;		
	int errCnt = 0;
	int maxErr = 0;
	uint8_t BitStream[MAX_DEMOD_BUF_LEN];	
	size_t size = getFromGraphBuf(BitStream);	
	
	errCnt = askdemod(BitStream, &size, &clk, &invert, maxErr, 0, 0);
	if ( errCnt < 0 || errCnt > maxErr ) { 
		if (g_debugMode) PrintAndLog("DEBUG: no data or error found %d, clock: %d", errCnt, clk);
		return 0;
	}

	errCnt = BiphaseRawDecode(BitStream, &size, maxErr, 1);
	if (errCnt < 0 || errCnt > maxErr ) {
		if (g_debugMode) PrintAndLog("Error BiphaseRawDecode: %d", errCnt);
		return 0;
	} 
	
	int preambleIndex = FDXBdemodBI(BitStream, &size);
	if (preambleIndex < 0){
		if (g_debugMode) PrintAndLog("Error FDXBDemod , no startmarker found :: %d",preambleIndex);
		return 0;
	}
	if (size != 128) {
		if (g_debugMode) PrintAndLog("Error incorrect data length found");
		return 0;
	}
	
	setDemodBuf(BitStream, 128, preambleIndex);

	// remove marker bits (1's every 9th digit after preamble) (pType = 2)
	size = removeParity(BitStream, preambleIndex + 11, 9, 2, 117);
	if ( size != 104 ) {
		if (g_debugMode) PrintAndLog("Error removeParity:: %d", size);
		return 0;
	}
	if (g_debugMode) {
		char *bin = sprint_bin_break(BitStream,size,16);
		PrintAndLog("DEBUG BinStream:\n%s",bin);
	}
	PrintAndLog("\nFDX-B / ISO 11784/5 Animal Tag ID Found:");
	if (g_debugMode) PrintAndLog("Start marker %d;   Size %d", preambleIndex, size);

	//got a good demod
	uint64_t NationalCode = ((uint64_t)(bytebits_to_byteLSBF(BitStream+32,6)) << 32) | bytebits_to_byteLSBF(BitStream,32);
	uint32_t countryCode = bytebits_to_byteLSBF(BitStream+38,10);
	uint8_t dataBlockBit = BitStream[48];
	uint32_t reservedCode = bytebits_to_byteLSBF(BitStream+49,14);
	uint8_t animalBit = BitStream[63];
	uint32_t crc16 = bytebits_to_byteLSBF(BitStream+64,16);
	uint32_t extended = bytebits_to_byteLSBF(BitStream+80,24);

	uint64_t rawid = ((uint64_t)bytebits_to_byte(BitStream,32)<<32) | bytebits_to_byte(BitStream+32,32);
	uint8_t raw[8];
	num_to_bytes(rawid, 8, raw);

	if (g_debugMode) PrintAndLog("Raw ID Hex: %s", sprint_hex(raw,8));

	uint16_t calcCrc = crc16_ccitt_kermit(raw, 8);
	PrintAndLog("Animal ID:     %04u-%012llu", countryCode, NationalCode);
	PrintAndLog("National Code: %012llu", NationalCode);
	PrintAndLog("CountryCode:   %04u", countryCode);
	PrintAndLog("Extended Data: %s", dataBlockBit ? "True" : "False");
	PrintAndLog("reserved Code: %u", reservedCode);
	PrintAndLog("Animal Tag:    %s", animalBit ? "True" : "False");
	PrintAndLog("CRC:           0x%04X - [%04X] - %s", crc16, calcCrc, (calcCrc == crc16) ? "Passed" : "Failed");
	PrintAndLog("Extended:      0x%X\n", extended);
	
	return 1;
}


//by marshmellow
//attempt to psk1 demod graph buffer
int PSKDemod(const char *Cmd, bool verbose)
{
	int invert=0;
	int clk=0;
	int maxErr=100;
	sscanf(Cmd, "%i %i %i", &clk, &invert, &maxErr);
	if (clk==1){
		invert=1;
		clk=0;
	}
	if (invert != 0 && invert != 1) {
		if (g_debugMode || verbose) PrintAndLog("Invalid argument: %s", Cmd);
		return 0;
	}
	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	size_t BitLen = getFromGraphBuf(BitStream);
	if (BitLen==0) return 0;
	uint8_t carrier=countFC(BitStream, BitLen, 0);
	if (carrier!=2 && carrier!=4 && carrier!=8){
		//invalid carrier
		return 0;
	}
	if (g_debugMode){
		PrintAndLog("Carrier: rf/%d",carrier);
	}
	int errCnt=0;
	errCnt = pskRawDemod(BitStream, &BitLen, &clk, &invert);
	if (errCnt > maxErr){
		if (g_debugMode || verbose) PrintAndLog("Too many errors found, clk: %d, invert: %d, numbits: %d, errCnt: %d",clk,invert,BitLen,errCnt);
		return 0;
	} 
	if (errCnt<0|| BitLen<16){  //throw away static - allow 1 and -1 (in case of threshold command first)
		if (g_debugMode || verbose) PrintAndLog("no data found, clk: %d, invert: %d, numbits: %d, errCnt: %d",clk,invert,BitLen,errCnt);
		return 0;
	}
	if (verbose || g_debugMode){
		PrintAndLog("\nUsing Clock:%d, invert:%d, Bits Found:%d",clk,invert,BitLen);
		if (errCnt>0){
			PrintAndLog("# Errors during Demoding (shown as 7 in bit stream): %d",errCnt);
		}
	}
	//prime demod buffer for output
	setDemodBuf(BitStream,BitLen,0);
	return 1;
}

// Indala 26 bit decode
// by marshmellow
// optional arguments - same as CmdpskNRZrawDemod (clock & invert)
int CmdIndalaDecode(const char *Cmd)
{
	int ans;
	if (strlen(Cmd)>0){
		ans = PSKDemod(Cmd, 0);
	} else{ //default to RF/32
		ans = PSKDemod("32", 0);
	}

	if (!ans){
		if (g_debugMode) 
			PrintAndLog("Error1: %d",ans);
		return 0;
	}

	uint8_t invert = 0;
	size_t size = DemodBufferLen;
	int startIdx = indala26decode(DemodBuffer, &size, &invert);
	if (startIdx < 0 || size > 224) {
		if (g_debugMode)
			PrintAndLog("Error2: %d",ans);
		return -1;
	}
	setDemodBuf(DemodBuffer, size, (size_t)startIdx);
	if (invert)
		if (g_debugMode)
			PrintAndLog("Had to invert bits");

	PrintAndLog("BitLen: %d",DemodBufferLen);
	//convert UID to HEX
	uint32_t uid1, uid2, uid3, uid4, uid5, uid6, uid7;
	uid1=bytebits_to_byte(DemodBuffer,32);
	uid2=bytebits_to_byte(DemodBuffer+32,32);
	if (DemodBufferLen==64){
		PrintAndLog("Indala UID=%s (%x%08x)",  sprint_bin_break(DemodBuffer,DemodBufferLen,16), uid1, uid2);
	} else {
		uid3=bytebits_to_byte(DemodBuffer+64,32);
		uid4=bytebits_to_byte(DemodBuffer+96,32);
		uid5=bytebits_to_byte(DemodBuffer+128,32);
		uid6=bytebits_to_byte(DemodBuffer+160,32);
		uid7=bytebits_to_byte(DemodBuffer+192,32);
		PrintAndLog("Indala UID=%s (%x%08x%08x%08x%08x%08x%08x)", 
		     sprint_bin_break(DemodBuffer,DemodBufferLen,16), uid1, uid2, uid3, uid4, uid5, uid6, uid7);
	}
	if (g_debugMode){
		PrintAndLog("DEBUG: printing demodbuffer:");
		printDemodBuff();
	}
	return 1;
}

int CmdPSKNexWatch(const char *Cmd)
{
	if (!PSKDemod("", false)) return 0;

	uint8_t preamble[28] = {0,0,0,0,0,1,0,1,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	size_t startIdx = 0, size = DemodBufferLen; 
	
	// sanity check. 
	if ( size < sizeof(preamble) + 100) return 0;
	
	bool invert = false;
	if (!preambleSearch(DemodBuffer, preamble, sizeof(preamble), &size, &startIdx)){
		// if didn't find preamble try again inverting
		if (!PSKDemod("1", false)) return 0; 

		size = DemodBufferLen;
		if (!preambleSearch(DemodBuffer, preamble, sizeof(preamble), &size, &startIdx)) return 0;
		invert = true;
	} 
	if (size != 128) return 0;
	setDemodBuf(DemodBuffer, size, startIdx+4);
	startIdx = 8+32; //4 = extra i added, 8 = preamble, 32 = reserved bits (always 0)
	//get ID
	uint32_t ID = 0;
	for (uint8_t wordIdx=0; wordIdx<4; wordIdx++){
		for (uint8_t idx=0; idx<8; idx++){
			ID = (ID << 1) | DemodBuffer[startIdx+wordIdx+(idx*4)];
		}	
	}
	//parity check (TBD)

	//checksum check (TBD)

	//output
	PrintAndLog("NexWatch ID: %d", ID);
	if (invert){
		PrintAndLog("Had to Invert - probably NexKey");
		for (uint8_t idx=0; idx<size; idx++)
			DemodBuffer[idx] ^= 1;
	} 

	CmdPrintDemodBuff("x");
	return 1;
}

// by marshmellow
// takes 3 arguments - clock, invert, maxErr as integers
// attempts to demodulate nrz only
// prints binary found and saves in demodbuffer for further commands
int NRZrawDemod(const char *Cmd, bool verbose)
{
	int invert=0;
	int clk=0;
	int maxErr=100;
	sscanf(Cmd, "%i %i %i", &clk, &invert, &maxErr);
	if (clk==1){
		invert=1;
		clk=0;
	}
	if (invert != 0 && invert != 1) {
		PrintAndLog("Invalid argument: %s", Cmd);
		return 0;
	}
	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	size_t BitLen = getFromGraphBuf(BitStream);
	if (BitLen==0) return 0;
	int errCnt=0;
	errCnt = nrzRawDemod(BitStream, &BitLen, &clk, &invert);
	if (errCnt > maxErr){
		if (g_debugMode) PrintAndLog("Too many errors found, clk: %d, invert: %d, numbits: %d, errCnt: %d",clk,invert,BitLen,errCnt);
		return 0;
	} 
	if (errCnt<0 || BitLen<16){  //throw away static - allow 1 and -1 (in case of threshold command first)
		if (g_debugMode) PrintAndLog("no data found, clk: %d, invert: %d, numbits: %d, errCnt: %d",clk,invert,BitLen,errCnt);
		return 0;
	}
	if (verbose || g_debugMode) PrintAndLog("Tried NRZ Demod using Clock: %d - invert: %d - Bits Found: %d",clk,invert,BitLen);
	//prime demod buffer for output
	setDemodBuf(BitStream,BitLen,0);

	if (errCnt>0 && (verbose || g_debugMode)) PrintAndLog("# Errors during Demoding (shown as 7 in bit stream): %d",errCnt);
	if (verbose || g_debugMode) {
		PrintAndLog("NRZ demoded bitstream:");
		// Now output the bitstream to the scrollback by line of 16 bits
		printDemodBuff();
	}
	return 1; 
}

int CmdNRZrawDemod(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 10 || cmdp == 'h' || cmdp == 'H')
		return usage_data_rawdemod_nr();

	return NRZrawDemod(Cmd, TRUE);
}

// by marshmellow
// takes 3 arguments - clock, invert, maxErr as integers
// attempts to demodulate psk only
// prints binary found and saves in demodbuffer for further commands
int CmdPSK1rawDemod(const char *Cmd)
{
	int ans;
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 10 || cmdp == 'h' || cmdp == 'H')
		return usage_data_rawdemod_p1();

	ans = PSKDemod(Cmd, TRUE);
	//output
	if (!ans){
		if (g_debugMode) PrintAndLog("Error demoding: %d",ans); 
		return 0;
	}
	PrintAndLog("PSK1 demoded bitstream:");
	// Now output the bitstream to the scrollback by line of 16 bits
	printDemodBuff();
	return 1;
}

// by marshmellow
// takes same args as cmdpsk1rawdemod
int CmdPSK2rawDemod(const char *Cmd)
{
	int ans = 0;
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 10 || cmdp == 'h' || cmdp == 'H')
		return usage_data_rawdemod_p2();

	ans = PSKDemod(Cmd, TRUE);
	if (!ans){
		if (g_debugMode) PrintAndLog("Error demoding: %d",ans);  
		return 0;
	} 
	psk1TOpsk2(DemodBuffer, DemodBufferLen);
	PrintAndLog("PSK2 demoded bitstream:");
	// Now output the bitstream to the scrollback by line of 16 bits
	printDemodBuff();  
	return 1;
}

// by marshmellow - combines all raw demod functions into one menu command
int CmdRawDemod(const char *Cmd)
{
	char cmdp = Cmd[0]; //param_getchar(Cmd, 0);
	char cmdp2 = Cmd[1];
	int ans = 0;

	if (strlen(Cmd) > 20 || cmdp == 'h' || cmdp == 'H' || strlen(Cmd) < 2)
		return usage_data_rawdemod();

	if (cmdp == 'f' && cmdp2 == 's')
		ans = CmdFSKrawdemod(Cmd+2);
	else if(cmdp == 'a' && cmdp2 == 'b')
		ans = Cmdaskbiphdemod(Cmd+2);
	else if(cmdp == 'a' && cmdp2 == 'm')
		ans = Cmdaskmandemod(Cmd+2);
	else if(cmdp == 'a' && cmdp2 == 'r')
		ans = Cmdaskrawdemod(Cmd+2);
	else if(cmdp == 'n' && cmdp2 == 'r')
		ans = CmdNRZrawDemod(Cmd+2);
	else if(cmdp == 'p' && cmdp2 == '1')
		ans = CmdPSK1rawDemod(Cmd+2);
	else if(cmdp == 'p' && cmdp2 == '2')
		ans = CmdPSK2rawDemod(Cmd+2);
	else
		PrintAndLog("unknown modulation entered - see help ('h') for parameter structure");

	return ans;
}
//iceman: diff sizes on the plotwindow?
int CmdGrid(const char *Cmd)
{
	sscanf(Cmd, "%i %i", &PlotGridX, &PlotGridY);
	PlotGridXdefault = PlotGridX;
	PlotGridYdefault = PlotGridY;
	RepaintGraphWindow();
	return 0;
}

int CmdHexsamples(const char *Cmd)
{
	int i, j;
	int requested = 0;
	int offset = 0;
	char string_buf[25];
	char* string_ptr = string_buf;
	uint8_t got[BIGBUF_SIZE];

	sscanf(Cmd, "%i %i", &requested, &offset);

	/* if no args send something */
	if (requested == 0) {
		requested = 8;
	}
	if (offset + requested > sizeof(got)) {
		PrintAndLog("Tried to read past end of buffer, <bytes> + <offset> > %d", BIGBUF_SIZE);
		return 0;
	}

	GetFromBigBuf(got,requested,offset);
	WaitForResponse(CMD_ACK,NULL);

	i = 0;
	for (j = 0; j < requested; j++) {
		i++;
		string_ptr += sprintf(string_ptr, "%02x ", got[j]);
		if (i == 8) {
			*(string_ptr - 1) = '\0';    // remove the trailing space
			PrintAndLog("%s", string_buf);
			string_buf[0] = '\0';
			string_ptr = string_buf;
			i = 0;
		}
		if (j == requested - 1 && string_buf[0] != '\0') { // print any remaining bytes
			*(string_ptr - 1) = '\0';
			PrintAndLog("%s", string_buf);
			string_buf[0] = '\0';
		}
	}
	return 0;
}

int CmdHide(const char *Cmd)
{
	HideGraphWindow();
	return 0;
}

//zero mean GraphBuffer
int CmdHpf(const char *Cmd)
{
	int i;
	int accum = 0;

	for (i = 10; i < GraphTraceLen; ++i)
		accum += GraphBuffer[i];
	
	accum /= (GraphTraceLen - 10);
	
	for (i = 0; i < GraphTraceLen; ++i)
		GraphBuffer[i] -= accum;

	RepaintGraphWindow();
	return 0;
}

bool _headBit( BitstreamOut *stream)
{
	int bytepos = stream->position >> 3; // divide by 8
	int bitpos = (stream->position++) & 7; // mask out 00000111
	return (*(stream->buffer + bytepos) >> (7-bitpos)) & 1;
}

uint8_t getByte(uint8_t bits_per_sample, BitstreamOut* b)
{
	int i;
	uint8_t val = 0;
	for(i = 0 ; i < bits_per_sample; i++)
		val |= (_headBit(b) << (7-i));

	return val;
}

int getSamples(const char *Cmd, bool silent)
{
	//If we get all but the last byte in bigbuf,
	// we don't have to worry about remaining trash
	// in the last byte in case the bits-per-sample
	// does not line up on byte boundaries

	uint8_t got[BIGBUF_SIZE-1] = { 0 };

	int n = strtol(Cmd, NULL, 0);

	if ( n == 0 || n > sizeof(got))
		n = sizeof(got);

	PrintAndLog("Reading %d bytes from device memory\n", n);
	GetFromBigBuf(got,n,0);
	PrintAndLog("Data fetched");
	UsbCommand response;
	if ( !WaitForResponseTimeout(CMD_ACK, &response, 10000) ) {
        PrintAndLog("timeout while waiting for reply.");
		return 1;
    }
	
	uint8_t bits_per_sample = 8;

	//Old devices without this feature would send 0 at arg[0]
	if (response.arg[0] > 0) {
		sample_config *sc = (sample_config *) response.d.asBytes;
		PrintAndLog("Samples @ %d bits/smpl, decimation 1:%d ", sc->bits_per_sample, sc->decimation);
		bits_per_sample = sc->bits_per_sample;
	}
	
	if (bits_per_sample < 8) {
		PrintAndLog("Unpacking...");
		BitstreamOut bout = { got, bits_per_sample * n,  0};
		int j =0;
		for (j = 0; j * bits_per_sample < n * 8 && j < n; j++) {
			uint8_t sample = getByte(bits_per_sample, &bout);
			GraphBuffer[j] = ((int) sample )- 128;
		}
		GraphTraceLen = j;
		PrintAndLog("Unpacked %d samples" , j );
	} else {
		for (int j = 0; j < n; j++) {
			GraphBuffer[j] = ((int)got[j]) - 128;
		}
		GraphTraceLen = n;
	}

	RepaintGraphWindow();
	return 0;
}

int CmdSamples(const char *Cmd)
{
	return getSamples(Cmd, false);
}

int CmdTuneSamples(const char *Cmd)
{
	int timeout = 0;
	printf("\nMeasuring antenna characteristics, please wait...");

	UsbCommand c = {CMD_MEASURE_ANTENNA_TUNING, {0,0,0}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	while(!WaitForResponseTimeout(CMD_MEASURED_ANTENNA_TUNING, &resp, 2000)) {
		timeout++;
		printf(".");
		if (timeout > 7) {
			PrintAndLog("\nNo response from Proxmark. Aborting...");
			return 1;
		}
	}

	int peakv, peakf;
	int vLf125, vLf134, vHf;
	vLf125 = resp.arg[0] & 0xffff;
	vLf134 = resp.arg[0] >> 16;
	vHf = resp.arg[1] & 0xffff;;
	peakf = resp.arg[2] & 0xffff;
	peakv = resp.arg[2] >> 16;
	PrintAndLog("");
	if ( vLf125 > 0 )
		PrintAndLog("# LF antenna: %5.2f V @   125.00 kHz", vLf125/1000.0);
	if ( vLf134 > 0 )
		PrintAndLog("# LF antenna: %5.2f V @   134.00 kHz", vLf134/1000.0);
	if ( peakv > 0 && peakf > 0 )
		PrintAndLog("# LF optimal: %5.2f V @%9.2f kHz", peakv/1000.0, 12000.0/(peakf+1));
	if ( vHf > 0 )
		PrintAndLog("# HF antenna: %5.2f V @    13.56 MHz", vHf/1000.0);

 #define LF_UNUSABLE_V		2948		// was 2000. Changed due to bugfix in voltage measurements. LF results are now 47% higher.
 #define LF_MARGINAL_V		14739		// was 10000. Changed due to bugfix bug in voltage measurements. LF results are now 47% higher.
 #define HF_UNUSABLE_V		3167		// was 2000. Changed due to bugfix in voltage measurements. HF results are now 58% higher.
 #define HF_MARGINAL_V		7917		// was 5000. Changed due to bugfix in voltage measurements. HF results are now 58% higher.

	if (peakv < LF_UNUSABLE_V)
		PrintAndLog("# Your LF antenna is unusable.");
	else if (peakv < LF_MARGINAL_V)
		PrintAndLog("# Your LF antenna is marginal.");
	if (vHf < HF_UNUSABLE_V)
		PrintAndLog("# Your HF antenna is unusable.");
	else if (vHf < HF_MARGINAL_V)
		PrintAndLog("# Your HF antenna is marginal.");

	if (peakv >= LF_UNUSABLE_V)	{
		for (int i = 0; i < 256; i++) {
			GraphBuffer[i] = resp.d.asBytes[i] - 128;
		}
		PrintAndLog("Displaying LF tuning graph. Divisor 89 is 134khz, 95 is 125khz.\n");
		PrintAndLog("\n");
		GraphTraceLen = 256;
		ShowGraphWindow();
		RepaintGraphWindow();
	}
	return 0;
}

int CmdLoad(const char *Cmd)
{
	char filename[FILE_PATH_SIZE] = {0x00};
	int len = 0;

	len = strlen(Cmd);
	if (len > FILE_PATH_SIZE) len = FILE_PATH_SIZE;
	memcpy(filename, Cmd, len);
	
	FILE *f = fopen(filename, "r");
	if (!f) {
		PrintAndLog("couldn't open '%s'", filename);
		return 0;
	}

	GraphTraceLen = 0;
	char line[80];
	while (fgets(line, sizeof (line), f)) {
		GraphBuffer[GraphTraceLen] = atoi(line);
		GraphTraceLen++;
	}
	fclose(f);
	PrintAndLog("loaded %d samples", GraphTraceLen);
	RepaintGraphWindow();
	return 0;
}

int CmdLtrim(const char *Cmd)
{
	int ds = atoi(Cmd);

	if (GraphTraceLen <= 0) return 0;

	for (int i = ds; i < GraphTraceLen; ++i)
		GraphBuffer[i-ds] = GraphBuffer[i];

	GraphTraceLen -= ds;
	RepaintGraphWindow();
	return 0;
}

// trim graph to input argument length
int CmdRtrim(const char *Cmd)
{
	int ds = atoi(Cmd);
	GraphTraceLen = ds;
	RepaintGraphWindow();
	return 0;
}

int CmdNorm(const char *Cmd)
{
	int i;
	int max = INT_MIN, min = INT_MAX;

	for (i = 10; i < GraphTraceLen; ++i) {
		if (GraphBuffer[i] > max) max = GraphBuffer[i];
		if (GraphBuffer[i] < min) min = GraphBuffer[i];
	}

	if (max != min) {
		for (i = 0; i < GraphTraceLen; ++i) {
			GraphBuffer[i] = (GraphBuffer[i] - ((max + min) / 2)) * 256 / (max - min);
			//marshmelow: adjusted *1000 to *256 to make +/- 128 so demod commands still work
		}
	}
	RepaintGraphWindow();
	return 0;
}

int CmdPlot(const char *Cmd)
{
	ShowGraphWindow();
	return 0;
}

int CmdSave(const char *Cmd)
{
	char filename[FILE_PATH_SIZE] = {0x00};
	int len = 0;

	len = strlen(Cmd);
	if (len > FILE_PATH_SIZE) len = FILE_PATH_SIZE;
	memcpy(filename, Cmd, len);
	 

	FILE *f = fopen(filename, "w");
	if(!f) {
		PrintAndLog("couldn't open '%s'", filename);
		return 0;
	}
	int i;
	for (i = 0; i < GraphTraceLen; i++) {
		fprintf(f, "%d\n", GraphBuffer[i]);
	}
	fclose(f);
	PrintAndLog("saved to '%s'", Cmd);
	return 0;
}

int CmdScale(const char *Cmd)
{
	CursorScaleFactor = atoi(Cmd);
	if (CursorScaleFactor == 0) {
		PrintAndLog("bad, can't have zero scale");
		CursorScaleFactor = 1;
	}
	RepaintGraphWindow();
	return 0;
}

int CmdDirectionalThreshold(const char *Cmd)
{
	int8_t upThres = param_get8(Cmd, 0);
	int8_t downThres = param_get8(Cmd, 1);

	printf("Applying Up Threshold: %d, Down Threshold: %d\n", upThres, downThres);

	int lastValue = GraphBuffer[0];
	GraphBuffer[0] = 0; // Will be changed at the end, but init 0 as we adjust to last samples value if no threshold kicks in.

	for (int i = 1; i < GraphTraceLen; ++i) {
		// Apply first threshold to samples heading up
		if (GraphBuffer[i] >= upThres && GraphBuffer[i] > lastValue)
		{
			lastValue = GraphBuffer[i]; // Buffer last value as we overwrite it.
			GraphBuffer[i] = 1;
		}
		// Apply second threshold to samples heading down
		else if (GraphBuffer[i] <= downThres && GraphBuffer[i] < lastValue)
		{
			lastValue = GraphBuffer[i]; // Buffer last value as we overwrite it.
			GraphBuffer[i] = -1;
		}
		else
		{
			lastValue = GraphBuffer[i]; // Buffer last value as we overwrite it.
			GraphBuffer[i] = GraphBuffer[i-1];
		}
	}
	GraphBuffer[0] = GraphBuffer[1]; // Aline with first edited sample.
	RepaintGraphWindow();
	return 0;
}

int CmdZerocrossings(const char *Cmd)
{
	// Zero-crossings aren't meaningful unless the signal is zero-mean.
	CmdHpf("");

	int sign = 1;
	int zc = 0;
	int lastZc = 0;

	for (int i = 0; i < GraphTraceLen; ++i) {
		if (GraphBuffer[i] * sign >= 0) {
			// No change in sign, reproduce the previous sample count.
			zc++;
			GraphBuffer[i] = lastZc;
		} else {
			// Change in sign, reset the sample count.
			sign = -sign;
			GraphBuffer[i] = lastZc;
			if (sign > 0) {
				lastZc = zc;
				zc = 0;
			}
		}
	}

	RepaintGraphWindow();
	return 0;
}

/**
 * @brief Utility for conversion via cmdline.
 * @param Cmd
 * @return
 */
int Cmdbin2hex(const char *Cmd)
{
	int bg =0, en =0;
	if(param_getptr(Cmd, &bg, &en, 0))
		return usage_data_bin2hex();

	//Number of digits supplied as argument
	size_t length = en  - bg +1;
	size_t bytelen = (length+7) / 8;
	uint8_t* arr = (uint8_t *) malloc(bytelen);
	memset(arr, 0, bytelen);
	BitstreamOut bout = { arr, 0, 0 };

	for (; bg <= en ;bg++) {
		char c = Cmd[bg];
		if( c == '1')	pushBit(&bout, 1);
		else if( c == '0')	pushBit(&bout, 0);
		else PrintAndLog("Ignoring '%c'", c);
	}

	if (bout.numbits % 8 != 0)
		printf("[padded with %d zeroes]\n", 8-(bout.numbits % 8));

	//Uses printf instead of PrintAndLog since the latter
	// adds linebreaks to each printout - this way was more convenient since we don't have to
	// allocate a string and write to that first...
	for(size_t x = 0; x  < bytelen ; x++)
		printf("%02X", arr[x]);

	printf("\n");
	free(arr);
	return 0;
}

int Cmdhex2bin(const char *Cmd)
{
	int bg =0, en =0;
	if(param_getptr(Cmd, &bg, &en, 0))  return usage_data_hex2bin();

	while (bg <= en ) {
		char x = Cmd[bg++];
		// capitalize
		if (x >= 'a' && x <= 'f')
			x -= 32;
		// convert to numeric value
		if (x >= '0' && x <= '9')
			x -= '0';
		else if (x >= 'A' && x <= 'F')
			x -= 'A' - 10;
		else
			continue;

		//Uses printf instead of PrintAndLog since the latter
		// adds linebreaks to each printout - this way was more convenient since we don't have to
		// allocate a string and write to that first...

		for(int i= 0 ; i < 4 ; ++i)
			printf("%d",(x >> (3 - i)) & 1);
	}
	printf("\n");

	return 0;
}

int CmdDataIIR(const char *Cmd){

	uint8_t k = param_get8(Cmd,0);
	//iceIIR_Butterworth(GraphBuffer, GraphTraceLen);
	iceSimple_Filter(GraphBuffer, GraphTraceLen, k);
	RepaintGraphWindow();
	return 0;
}

static command_t CommandTable[] =
{
	{"help",            CmdHelp,            1, "This help"},
	{"askedgedetect",   CmdAskEdgeDetect,   1, "[threshold] Adjust Graph for manual ASK demod using the length of sample differences to detect the edge of a wave (use 20-45, def:25)"},
	{"askem410xdemod",  CmdAskEM410xDemod,  1, "[clock] [invert<0|1>] [maxErr] -- Demodulate an EM410x tag from GraphBuffer (args optional)"},
	{"askgproxiidemod", CmdG_Prox_II_Demod, 1, "Demodulate a G Prox II tag from GraphBuffer"},
	{"askvikingdemod",  CmdVikingDemod,     1, "Demodulate a Viking AM tag from GraphBuffer"},
	{"autocorr",        CmdAutoCorr,        1, "[window length] [g] -- Autocorrelation over window - g to save back to GraphBuffer (overwrite)"},
	{"biphaserawdecode",CmdBiphaseDecodeRaw,1, "[offset] [invert<0|1>] [maxErr] -- Biphase decode bin stream in DemodBuffer (offset = 0|1 bits to shift the decode start)"},
	{"bin2hex",         Cmdbin2hex,         1, "<digits> -- Converts binary to hexadecimal"},
	{"bitsamples",      CmdBitsamples,      0, "Get raw samples as bitstring"},
	{"buffclear",       CmdBuffClear,       1, "Clear sample buffer and graph window"},
	{"dec",             CmdDec,             1, "Decimate samples"},
	{"detectclock",     CmdDetectClockRate, 1, "[<a|f|n|p>] Detect ASK, FSK, NRZ, PSK clock rate of wave in GraphBuffer"},
	{"fdxbdemod",       CmdFDXBdemodBI    , 1, "Demodulate a FDX-B ISO11784/85 Biphase tag from GraphBuffer"},
	{"fskawiddemod",    CmdFSKdemodAWID,    1, "Demodulate an AWID FSK tag from GraphBuffer"},
	//{"fskfcdetect",   CmdFSKfcDetect,     1, "Try to detect the Field Clock of an FSK wave"},
	{"fskhiddemod",     CmdFSKdemodHID,     1, "Demodulate a HID FSK tag from GraphBuffer"},
	{"fskiodemod",      CmdFSKdemodIO,      1, "Demodulate an IO Prox FSK tag from GraphBuffer"},
	{"fskpyramiddemod", CmdFSKdemodPyramid, 1, "Demodulate a Pyramid FSK tag from GraphBuffer"},
	{"fskparadoxdemod", CmdFSKdemodParadox, 1, "Demodulate a Paradox FSK tag from GraphBuffer"},
	{"getbitstream",    CmdGetBitStream,    1, "Convert GraphBuffer's >=1 values to 1 and <1 to 0"},
	{"grid",            CmdGrid,            1, "<x> <y> -- overlay grid on graph window, use zero value to turn off either"},
	{"hexsamples",      CmdHexsamples,      0, "<bytes> [<offset>] -- Dump big buffer as hex bytes"},
	{"hex2bin",         Cmdhex2bin,         1, "<hexadecimal> -- Converts hexadecimal to binary"},
	{"hide",            CmdHide,            1, "Hide graph window"},
	{"hpf",             CmdHpf,             1, "Remove DC offset from trace"},
	{"load",            CmdLoad,            1, "<filename> -- Load trace (to graph window"},
	{"ltrim",           CmdLtrim,           1, "<samples> -- Trim samples from left of trace"},
	{"rtrim",           CmdRtrim,           1, "<location to end trace> -- Trim samples from right of trace"},
	{"manrawdecode",    Cmdmandecoderaw,    1, "[invert] [maxErr] -- Manchester decode binary stream in DemodBuffer"},
	{"norm",            CmdNorm,            1, "Normalize max/min to +/-128"},
	{"plot",            CmdPlot,            1, "Show graph window (hit 'h' in window for keystroke help)"},
	{"printdemodbuffer",CmdPrintDemodBuff,  1, "[x] [o] <offset> [l] <length> -- print the data in the DemodBuffer - 'x' for hex output"},
	{"pskindalademod",  CmdIndalaDecode,    1, "[clock] [invert<0|1>] -- Demodulate an indala tag (PSK1) from GraphBuffer (args optional)"},
	{"psknexwatchdemod",CmdPSKNexWatch,     1, "Demodulate a NexWatch tag (nexkey, quadrakey) (PSK1) from GraphBuffer"},
	{"rawdemod",        CmdRawDemod,        1, "[modulation] ... <options> -see help (h option) -- Demodulate the data in the GraphBuffer and output binary"},  
	{"samples",         CmdSamples,         0, "[512 - 40000] -- Get raw samples for graph window (GraphBuffer)"},
	{"save",            CmdSave,            1, "<filename> -- Save trace (from graph window)"},
	{"scale",           CmdScale,           1, "<int> -- Set cursor display scale"},
	{"setdebugmode",    CmdSetDebugMode,    1, "<0|1|2> -- Turn on or off Debugging Level for lf demods"},
	{"shiftgraphzero",  CmdGraphShiftZero,  1, "<shift> -- Shift 0 for Graphed wave + or - shift value"},
	{"dirthreshold",    CmdDirectionalThreshold,   1, "<thres up> <thres down> -- Max rising higher up-thres/ Min falling lower down-thres, keep rest as prev."},
	{"tune",            CmdTuneSamples,     0, "Get hw tune samples for graph window"},
	{"undec",           CmdUndec,           1, "Un-decimate samples by 2"},
	{"zerocrossings",   CmdZerocrossings,   1, "Count time between zero-crossings"},
	{"iir",				CmdDataIIR,			0, "apply IIR buttersworth filter on plotdata"},
	{NULL, NULL, 0, NULL}
};

int CmdData(const char *Cmd){
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd)
{
	CmdsHelp(CommandTable);
	return 0;
}
