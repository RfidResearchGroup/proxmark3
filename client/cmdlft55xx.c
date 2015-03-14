//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency T55xx commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "proxmark3.h"
#include "ui.h"
#include "graph.h"
#include "cmdmain.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "cmdlft55xx.h"
#include "util.h"
#include "data.h"
#include "lfdemod.h"
#include "../common/crc.h"
#include "../common/iso14443crc.h"

// Default configuration
t55xx_conf_block_t config = { .modulation = DEMOD_ASK, .inversed = FALSE, .offset = 0x00, .block0 = 0x00};

int usage_t55xx_config(){
	PrintAndLog("Usage: lf t55xx config [d <demodulation>] [i 1] [o <offset>]");
	PrintAndLog("Options:        ");
	PrintAndLog("       h                        This help");
	PrintAndLog("       d <FSK|ASK|PSK|NZ|BI>    Set demodulation FSK / ASK / PSK / NZ / Biphase");
	PrintAndLog("       i [1]                    Inverse data signal, defaults to normal");
	PrintAndLog("       o [offsett]              Set offset, where data should start decode from in bitstream");
	PrintAndLog("");
	PrintAndLog("Examples:");
	PrintAndLog("      lf t55xx config d FSK          - FSK demodulation");
	PrintAndLog("      lf t55xx config d FSK i 1      - FSK demodulation, inverse data");
	PrintAndLog("      lf t55xx config d FSK i 1 o 3  - FSK demodulation, inverse data, offset=3,start from bitpos 3 to decode data");
	PrintAndLog("");
	return 0;
}
int usage_t55xx_read(){
	PrintAndLog("Usage:  lf t55xx read <block> <password>");
    PrintAndLog("     <block>, block number to read. Between 0-7");
    PrintAndLog("     <password>, OPTIONAL password (8 hex characters)");
    PrintAndLog("");
	PrintAndLog("Examples:");
    PrintAndLog("      lf t55xx read 0           - read data from block 0");
	PrintAndLog("      lf t55xx read 0 feedbeef  - read data from block 0 password feedbeef");
	PrintAndLog("");
	return 0;
}
int usage_t55xx_write(){
	PrintAndLog("Usage:  lf t55xx wr <block> <data> [password]");
    PrintAndLog("     <block>, block number to read. Between 0-7");
	PrintAndLog("     <data>,  4 bytes of data to write (8 hex characters)");
    PrintAndLog("     [password], OPTIONAL password 4bytes (8 hex characters)");
    PrintAndLog("");
	PrintAndLog("Examples:");
    PrintAndLog("      lf t55xx wd 3 11223344           - write 11223344 to block 3");
	PrintAndLog("      lf t55xx wd 3 11223344 feedbeef  - write 11223344 to block 3 password feedbeef");
	PrintAndLog("");
	return 0;
}
int usage_t55xx_trace() {
	PrintAndLog("Usage:  lf t55xx trace [1]");
	PrintAndLog("     [graph buffer data], if set, use Graphbuffer otherwise read data from tag.");
	PrintAndLog("");
	PrintAndLog("Examples:");
	PrintAndLog("      lf t55xx trace");
	PrintAndLog("      lf t55xx trace 1");
	PrintAndLog("");
	return 0;
}
int usage_t55xx_info() {
	PrintAndLog("Usage:  lf t55xx info [1]");
	PrintAndLog("     [graph buffer data], if set, use Graphbuffer otherwise read data from tag.");
	PrintAndLog("");
	PrintAndLog("Examples:");
	PrintAndLog("      lf t55xx info");
	PrintAndLog("      lf t55xx info 1");
	PrintAndLog("");
	return 0;
}
int usage_t55xx_dump(){
	PrintAndLog("Usage:  lf t55xx dump <password>");
    PrintAndLog("     <password>, OPTIONAL password 4bytes (8 hex symbols)");
	PrintAndLog("");
	PrintAndLog("Examples:");
	PrintAndLog("      lf t55xx dump");
	PrintAndLog("      lf t55xx dump feedbeef");
	PrintAndLog("");
	return 0;
}
int usage_t55xx_detect(){
	PrintAndLog("Usage:  lf t55xx detect");
	PrintAndLog("");
	PrintAndLog("Examples:");
	PrintAndLog("      lf t55xx detect");
	PrintAndLog("      lf t55xx detect 1");
	PrintAndLog("");
	return 0;
}

static int CmdHelp(const char *Cmd);

int CmdT55xxSetConfig(const char *Cmd){

	uint8_t data[] = {0x78,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t cmd[]  = {0x00,0x00};
	ComputeCrc14443(CRC_14443_B, data, 7 , &cmd[0], &cmd[1]);
	PrintAndLog("%02X %02X",cmd[0], cmd[1]);
	int len = 0;
	int foundModulation = 2;
	uint8_t offset = 0;
	bool inverse = FALSE;
	bool errors = FALSE;
	uint8_t cmdp = 0;
	char modulation[4] = {0x00};
	
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors)
	{
		switch(param_getchar(Cmd, cmdp))
		{
		case 'h':
		case 'H':
			return usage_t55xx_config();
		case 'd':
			len = param_getstr(Cmd, cmdp+1, modulation);
			cmdp+= len+1;
			//FSK|ASK|PSK|NZ|BI
			if ( strcmp(modulation, "FSK" ) == 0)
				foundModulation = 1;
			else if ( strcmp(modulation, "ASK" ) == 0)
				foundModulation = 2;
			else if ( strcmp(modulation, "PSK" ) == 0)
				foundModulation = 3;
			else if ( strcmp(modulation, "NZ" ) == 0)
				foundModulation = 4;
			else if ( strcmp(modulation, "BI" ) == 0)
				foundModulation = 5;
			else {
				PrintAndLog("Unknown modulation '%s'", modulation);
				errors = TRUE;
			}
			break;
		case 'i':
			inverse = param_getchar(Cmd,cmdp+1) == '1';
			cmdp+=2;
			break;
		case 'o':
			errors |= param_getdec(Cmd, cmdp+1,&offset);
			if ( offset >= 32 ){
				PrintAndLog("Offset must be smaller than 32");
				errors = TRUE;
			}
			cmdp+=2;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = TRUE;
			break;
		}
	}
	// No args
	if (cmdp == 0) {
		printConfiguration( config );
		return 0;
	}
	//Validations
	if (errors)
		return usage_t55xx_config();
 
	config.modulation = foundModulation;
	config.inversed = inverse;
	config.offset = offset;
	config.block0 = 0;
	return 0;
}

int CmdT55xxReadBlock(const char *Cmd)
{
	int block = -1;
	int password = 0xFFFFFFFF; //default to blank Block 7

	char cmdp = param_getchar(Cmd, 0);
	if (cmdp == 'h' || cmdp == 'H')
		return usage_t55xx_read();

	int res = sscanf(Cmd, "%d %x", &block, &password);

	if ( res < 1 || res > 2 )
		return usage_t55xx_read();

	
	if ((block < 0) | (block > 7)) {
		PrintAndLog("Block must be between 0 and 7");
		return 1;
	}	

	UsbCommand c = {CMD_T55XX_READ_BLOCK, {0, block, 0}};
 	c.d.asBytes[0] = 0x0; 

	//Password mode
	if ( res == 2 ) {
		c.arg[2] = password;
		c.d.asBytes[0] = 0x1; 
	}

	SendCommand(&c);
	if ( !WaitForResponseTimeout(CMD_ACK,NULL,2500) ) {
		PrintAndLog("command execution time out");
		return 2;
	}
	
	uint8_t got[12000];
	GetFromBigBuf(got,sizeof(got),0);
	WaitForResponse(CMD_ACK,NULL);
	setGraphBuf(got, 12000);

	DecodeT55xxBlock();
	printT55xxBlock("");
	return 0;
}

void DecodeT55xxBlock(){
	
	char buf[6] = {0x00};
	char *cmdStr = buf;

	// clearing the DemodBuffer.
	DemodBufferLen = 0x00;
	
	// use the configuration
	switch( config.modulation ){
		case 1:
			sprintf(cmdStr,"0 %d", config.inversed );
			FSKrawDemod(cmdStr, FALSE);
			break;
		case 2:
			sprintf(cmdStr,"0 %d 1", config.inversed );
			ASKmanDemod(cmdStr, FALSE, FALSE);
			break;
		case 3:
			sprintf(cmdStr,"0 %d 1", config.inversed );
			PSKDemod(cmdStr, FALSE);
			break;
		case 4:
			sprintf(cmdStr,"0 %d 1", config.inversed );
			NRZrawDemod(cmdStr, FALSE);
			break;
		case 5:
			//BiphaseRawDecode("0",FALSE);
			break;
		default:
		return;
	}
}

int CmdT55xxDetect(const char *Cmd){
	char cmdp = param_getchar(Cmd, 0);
	if (cmdp == 'h' || cmdp == 'H')
		return usage_t55xx_detect();
	
	// read block 0, Page 0. Configuration.
	UsbCommand c = {CMD_T55XX_READ_BLOCK, {0, 0, 0}};
 	c.d.asBytes[0] = 0x0; 

	//Password mode
	// if ( res == 2 ) {
		// c.arg[2] = password;
		// c.d.asBytes[0] = 0x1; 
	// }

	SendCommand(&c);
	if ( !WaitForResponseTimeout(CMD_ACK,NULL,2500) ) {
		PrintAndLog("command execution time out");
		return FALSE;
	}
	
	uint8_t got[12000];
	GetFromBigBuf(got,sizeof(got),0);
	WaitForResponse(CMD_ACK,NULL);
	setGraphBuf(got, 12000);
	
	if ( !tryDetectModulation() ){
		PrintAndLog("Could not detect modulation automatically. Try setting it manually with \'lf t55xx config\'");
	}
	return 0;
}

// detect configuration?
bool tryDetectModulation(){
	
	uint8_t hits = 0;
	t55xx_conf_block_t tests[10];
	
	if (GetFskClock("", FALSE, FALSE)){ 
		if ( FSKrawDemod("0 0", FALSE) && test()){
			tests[hits].modulation = DEMOD_FSK;
			tests[hits].inversed = FALSE;
			++hits;
		}
		if ( FSKrawDemod("0 1", FALSE) && test()) {
			tests[hits].modulation = DEMOD_FSK;
			tests[hits].inversed = TRUE;
			++hits;
			}
    } else {
		if ( ASKmanDemod("0 0 1", FALSE, FALSE) && test()) {
			tests[hits].modulation = DEMOD_ASK;
			tests[hits].inversed = FALSE;
			++hits;
			}

		if ( ASKmanDemod("0 1 1", FALSE, FALSE)  && test()) {
			tests[hits].modulation = DEMOD_ASK;
			tests[hits].inversed = TRUE;
			++hits;
			}
		
		if ( NRZrawDemod("0 0 1", FALSE)  && test()) {
			tests[hits].modulation = DEMOD_NZR;
			tests[hits].inversed = FALSE;
			++hits;
		}

		if ( NRZrawDemod("0 1 1", FALSE)  && test()) {
			tests[hits].modulation = DEMOD_NZR;
			tests[hits].inversed = TRUE;
			++hits;
			}
		
		if ( PSKDemod("0 0 1", FALSE) && test()) {
			tests[hits].modulation = DEMOD_PSK;
			tests[hits].inversed = FALSE;
			++hits;
		}
		
		if ( PSKDemod("0 1 1", FALSE) && test()) {
			tests[hits].modulation = DEMOD_PSK;
			tests[hits].inversed = TRUE;
			++hits;
		}
		//PSK2?
		// if (!BiphaseRawDecode("0",FALSE)  && test()) {
		//	tests[++hits].modulation = DEMOD_BI;
		//	tests[hits].inversed = FALSE;
		//}
		// if (!BiphaseRawDecode("1",FALSE) && test()) {
		//	tests[++hits].modulation = DEMOD_BI;
		//	tests[hits].inversed = TRUE;
		// }
	}		
	if ( hits == 1) {
		config.modulation = tests[0].modulation;
		config.inversed = tests[0].inversed;
		printConfiguration( config );
		return TRUE;
	}
	
	if ( hits > 1) {
		PrintAndLog("Found [%d] possible matches for modulation.",hits);
		for(int i=0; i<hits; ++i){
			PrintAndLog("--[%d]---------------", i+1);
			printConfiguration( tests[i] );
		}
	}
	return FALSE;
}

bool test(){

	if ( !DemodBufferLen) 
		return false;
	
	uint8_t si = 1;
	uint8_t safer    = PackBits(si, 4, DemodBuffer); si += 4;	
	uint8_t resv     = PackBits(si, 7, DemodBuffer); si += 7+3;
	uint8_t extend   = PackBits(si, 1, DemodBuffer); si += 1;

	//PrintAndLog("test: %X %X %X ", safer, resv, extend);
	
	// 2nibble must be zeroed.
	if ( resv > 0x00) return FALSE;

	if ( safer == 0x6 || safer == 0x9){
		if ( extend == 0x00)
			return TRUE;
	}
	if ( resv== 0x00) return TRUE;
	return FALSE;
}

void printT55xxBlock(const char *demodStr){
	
	uint32_t blockData = 0;
	uint8_t bits[64] = {0x00};
		
	if ( !DemodBufferLen) 
		return;
	
	if ( config.offset > DemodBufferLen){
		PrintAndLog("The configured offset is to big. (%d > %d)", config.offset, DemodBufferLen);
		return;
	}
	
	int i = config.offset;
	int pos = 32 + config.offset;
    for (; i < pos; ++i)
		bits[i]=DemodBuffer[i];
	
	blockData = PackBits(0, 32, bits);
	PrintAndLog("0x%08X  %s [%s]", blockData, sprint_bin(bits,32), demodStr);
}

int special(const char *Cmd) {
	uint32_t blockData = 0;
	uint8_t bits[64] = {0x00};

	PrintAndLog("[OFFSET] [DATA] [BINARY]");
	PrintAndLog("----------------------------------------------------");
	int i,j = 0;
	for (; j < 32; ++j){
		
		for (i = 0; i < 32; ++i)
			bits[i]=DemodBuffer[j+i];
	
		blockData = PackBits(0, 32, bits);
		PrintAndLog("[%d] 0x%08X  %s",j , blockData, sprint_bin(bits,32));	
	}
	
	return 0;
}

void printConfiguration( t55xx_conf_block_t b){
	PrintAndLog("Modulation : %s", GetSelectedModulationStr(b.modulation) );
	PrintAndLog("Inverted   : %s", (b.inversed) ? "Yes" : "No" );
	PrintAndLog("Offset     : %d", b.offset);
	PrintAndLog("Block0     : %08X", b.block0);
	PrintAndLog("");
}

int CmdT55xxWriteBlock(const char *Cmd)
{
	int block = 8; //default to invalid block
	int data = 0xFFFFFFFF; //default to blank Block 
	int password = 0xFFFFFFFF; //default to blank Block 7
	
	char cmdp = param_getchar(Cmd, 0);
	if (cmdp == 'h' || cmdp == 'H') {
		usage_t55xx_write();
		return 0;
	}
  
	int res = sscanf(Cmd, "%d %x %x",&block, &data, &password);
	
	if ( res < 2 || res > 3) {
		usage_t55xx_write();
		return 1;
	}

	if (block > 7) {
		PrintAndLog("Block must be between 0 and 7");
		return 1;
	}
	
	UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {data, block, 0}};
 	c.d.asBytes[0] = 0x0; 

	PrintAndLog("Writing to T55x7");
	PrintAndLog("block : %d", block);
	PrintAndLog("data  : 0x%08X", data);

	//Password mode
	if (res == 3) {
		c.arg[2] = password;
		c.d.asBytes[0] = 0x1; 
		PrintAndLog("pwd   : 0x%08X", password);
	}
	SendCommand(&c);
	return 0;
}

int CmdT55xxReadTrace(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	
	if (strlen(Cmd) > 1 || cmdp == 'h' || cmdp == 'H') 
		return usage_t55xx_trace();

	if ( strlen(Cmd)==0){
	
		UsbCommand c = {CMD_T55XX_READ_TRACE, {0, 0, 0}};
		SendCommand(&c);
		if ( !WaitForResponseTimeout(CMD_ACK,NULL,2500) ) {
			PrintAndLog("command execution time out");
			return 1;
		}

		uint8_t got[12000];
		GetFromBigBuf(got,sizeof(got),0);
		WaitForResponse(CMD_ACK,NULL);
		setGraphBuf(got, 12000);
	}
	
	DecodeT55xxBlock();

	if ( !DemodBufferLen) 
		return 2;
	
	RepaintGraphWindow();

	uint8_t si = 5;
	uint32_t bl0     = PackBits(si, 32, DemodBuffer);
	uint32_t bl1     = PackBits(si+32, 32, DemodBuffer);
	
	uint32_t acl     = PackBits(si,  8, DemodBuffer); si += 8;
	uint32_t mfc     = PackBits(si, 8, DemodBuffer); si += 8;
	uint32_t cid     = PackBits(si, 5, DemodBuffer); si += 5;
	uint32_t icr     = PackBits(si, 3, DemodBuffer); si += 3;
	uint32_t year    = PackBits(si, 4, DemodBuffer); si += 4;
	uint32_t quarter = PackBits(si, 2, DemodBuffer); si += 2;
	uint32_t lotid    = PackBits(si, 12, DemodBuffer); si += 12;
	uint32_t wafer   = PackBits(si, 5, DemodBuffer); si += 5;
	uint32_t dw      = PackBits(si, 15, DemodBuffer); 
	
	year += 2000;
	
	PrintAndLog("");
	PrintAndLog("-- T55xx Trace Information ----------------------------------");
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" ACL Allocation class (ISO/IEC 15963-1)  : 0x%02X (%d)", acl, acl);
	PrintAndLog(" MFC Manufacturer ID (ISO/IEC 7816-6)    : 0x%02X (%d)", mfc, mfc);
	PrintAndLog(" CID                                     : 0x%02X (%d)", cid, cid);
	PrintAndLog(" ICR IC Revision                         : %d",icr );
	PrintAndLog(" Manufactured");
	PrintAndLog("     Year/Quarter : %d/%d",year, quarter );
	PrintAndLog("     Lot ID       : %d", lotid );
	PrintAndLog("     Wafer number : %d", wafer);
	PrintAndLog("     Die Number   : %d", dw);
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" Raw Data - Page 1");
	PrintAndLog("     Block 0  : 0x%08X  %s", bl0, sprint_bin(DemodBuffer+5,32) );
	PrintAndLog("     Block 1  : 0x%08X  %s", bl1, sprint_bin(DemodBuffer+37,32) );
	PrintAndLog("-------------------------------------------------------------");
	/*
	TRACE - BLOCK O
		Bits	Definition								HEX
		1-8		ACL Allocation class (ISO/IEC 15963-1)	0xE0 
		9-16	MFC Manufacturer ID (ISO/IEC 7816-6)	0x15 Atmel Corporation
		17-21	CID										0x1 = Atmel ATA5577M1  0x2 = Atmel ATA5577M2 
		22-24	ICR IC revision
		25-28	YEAR (BCD encoded) 						9 (= 2009)
		29-30	QUARTER									1,2,3,4 
		31-32	LOT ID
	
	TRACE - BLOCK 1
		1-12	LOT ID  
		13-17	Wafer number
		18-32	DW,  die number sequential
	*/
	
  return 0;
}

int CmdT55xxInfo(const char *Cmd){
	/*
		Page 0 Block 0 Configuration data.
		Normal mode
		Extended mode
	*/
	char cmdp = param_getchar(Cmd, 0);

	if (cmdp == 'h' || cmdp == 'H')
		return usage_t55xx_info();
	
	if (strlen(Cmd)==0){
		
		// read block 0, Page 0. Configuration.
		UsbCommand c = {CMD_T55XX_READ_BLOCK, {0, 0, 0}};
		c.d.asBytes[0] = 0x0; 

		//Password mode
		// if ( res == 2 ) {
			// c.arg[2] = password;
			// c.d.asBytes[0] = 0x1; 
		// }

		SendCommand(&c);
		if ( !WaitForResponseTimeout(CMD_ACK,NULL,2500) ) {
			PrintAndLog("command execution time out");
			return 1;
		}

		uint8_t got[12000];
		GetFromBigBuf(got,sizeof(got),0);
		WaitForResponse(CMD_ACK,NULL);
		setGraphBuf(got, 12000);
	}
	
	DecodeT55xxBlock();

	if ( !DemodBufferLen) 
		return 2;
	
	
	uint8_t si = 1;
	uint32_t bl0      = PackBits(si, 32, DemodBuffer);
	
	uint32_t safer    = PackBits(si, 4, DemodBuffer); si += 4;	
	uint32_t resv     = PackBits(si, 7, DemodBuffer); si += 7;
	uint32_t dbr      = PackBits(si, 3, DemodBuffer); si += 3;
	uint32_t extend   = PackBits(si, 1, DemodBuffer); si += 1;
	uint32_t datamod  = PackBits(si, 5, DemodBuffer); si += 5;
	uint32_t pskcf    = PackBits(si, 2, DemodBuffer); si += 2;
	uint32_t aor      = PackBits(si, 1, DemodBuffer); si += 1;	
	uint32_t otp      = PackBits(si, 1, DemodBuffer); si += 1;	
	uint32_t maxblk   = PackBits(si, 3, DemodBuffer); si += 3;
	uint32_t pwd      = PackBits(si, 1, DemodBuffer); si += 1;	
	uint32_t sst      = PackBits(si, 1, DemodBuffer); si += 1;	
	uint32_t fw       = PackBits(si, 1, DemodBuffer); si += 1;
	uint32_t inv      = PackBits(si, 1, DemodBuffer); si += 1;	
	uint32_t por      = PackBits(si, 1, DemodBuffer); si += 1;
		
	PrintAndLog("");
	PrintAndLog("-- T55xx Configuration & Tag Information --------------------");
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" Safer key                 : %s", GetSaferStr(safer));
	PrintAndLog(" reserved                  : %d", resv);
	PrintAndLog(" Data bit rate             : %s", GetBitRateStr(dbr));
	PrintAndLog(" eXtended mode             : %s", (extend) ? "Yes - Warning":"No");
	PrintAndLog(" Modulation                : %s", GetModulationStr(datamod));
	PrintAndLog(" PSK clock freq            : %d", pskcf);
	PrintAndLog(" AOR - Answer on Request   : %s", (aor) ? "Yes":"No");
	PrintAndLog(" OTP - One Time Pad        : %s", (otp) ? "Yes - Warning":"No" );
	PrintAndLog(" Max block                 : %d", maxblk);
	PrintAndLog(" Password mode             : %s", (pwd) ? "Yes":"No");
	PrintAndLog(" Sequence Start Terminator : %s", (sst) ? "Yes":"No");
	PrintAndLog(" Fast Write                : %s", (fw)  ? "Yes":"No");
	PrintAndLog(" Inverse data              : %s", (inv) ? "Yes":"No");
	PrintAndLog(" POR-Delay                 : %s", (por) ? "Yes":"No");
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" Raw Data - Page 0");
	PrintAndLog("     Block 0  : 0x%08X  %s", bl0, sprint_bin(DemodBuffer+5,32) );
	PrintAndLog("-------------------------------------------------------------");
	
	return 0;
}

int CmdT55xxDump(const char *Cmd){

	char s[20] = {0x00};
	uint8_t pwd[4] = {0x00};

	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'h' || cmdp == 'H') {
		usage_t55xx_dump();
		return 0;
	}

	bool hasPwd = ( strlen(Cmd) > 0);	
	if ( hasPwd ){
		if (param_gethex(Cmd, 0, pwd, 8)) {
			PrintAndLog("password must include 8 HEX symbols");
			return 1;
		}
	}
	
	for ( int i = 0; i <8; ++i){
		memset(s,0,sizeof(s));
		if ( hasPwd ) {
			sprintf(s,"%d %02x%02x%02x%02x", i, pwd[0],pwd[1],pwd[2],pwd[3]);
		} else {
			sprintf(s,"%d", i);
		}
		CmdT55xxReadBlock(s);
	}
	return 0;
}

char * GetBitRateStr(uint32_t id){
 	static char buf[40];
	char *retStr = buf;
		switch (id){
		case 0: 
			sprintf(retStr,"%d - RF/8",id);
			break;
		case 1:
			sprintf(retStr,"%d - RF/16",id);
			break;
		case 2:		
			sprintf(retStr,"%d - RF/32",id);
			break;
		case 3:
			sprintf(retStr,"%d - RF/40",id);
			break;
		case 4:
			sprintf(retStr,"%d - RF/50",id);
			break;
		case 5:
			sprintf(retStr,"%d - RF/64",id);
			break;
		case 6:
			sprintf(retStr,"%d - RF/100",id);
			break;
		case 7:
			sprintf(retStr,"%d - RF/128",id);
			break;
		default:
			sprintf(retStr,"%d - (Unknown)",id);
			break;
		}

	return buf;
}

char * GetSaferStr(uint32_t id){
 	static char buf[40];
	char *retStr = buf;
	
	sprintf(retStr,"%d",id);
	if (id == 6) {
		sprintf(retStr,"%d - passwd",id);
	}
	if (id == 9 ){
		sprintf(retStr,"%d - testmode",id);
	}
	
	return buf;
}
char * GetModulationStr( uint32_t id){
 	static char buf[40];
	char *retStr = buf;
	
	switch (id){
		case 0: 
			sprintf(retStr,"%d - DIRECT (ASK/NRZ)",id);
			break;
		case 1:
			sprintf(retStr,"%d - PSK 1 phase change when input changes",id);
			break;
		case 2:		
			sprintf(retStr,"%d - PSK 2 phase change on bitclk if input high",id);
			break;
		case 3:
			sprintf(retStr,"%d - PSK 3 phase change on rising edge of input",id);
			break;
		case 4:
			sprintf(retStr,"%d - FSK 1 RF/8  RF/5",id);
			break;
		case 5:
			sprintf(retStr,"%d - FSK 2 RF/8  RF/10",id);
			break;
		case 6:
			sprintf(retStr,"%d - FSK 1a RF/5  RF/8",id);
			break;
		case 7:
			sprintf(retStr,"%d - FSK 2a RF/10  RF/8",id);
			break;
		case 8:
			sprintf(retStr,"%d - Manschester",id);
			break;
		case 16:
			sprintf(retStr,"%d - Biphase",id);
			break;
		case 17:
			sprintf(retStr,"%d - Reserved",id);
			break;
		default:
			sprintf(retStr,"0x%02X (Unknown)",id);
			break;
		}
	return buf;
}

char * GetSelectedModulationStr( uint8_t id){

 	static char buf[16];
	char *retStr = buf;
	
	switch (id){
		case DEMOD_FSK:
			sprintf(retStr,"FSK (%d)",id);
			break;
		case DEMOD_ASK:		
			sprintf(retStr,"ASK (%d)",id);
			break;
		case DEMOD_NZR:
			sprintf(retStr,"DIRECT/NRZ (%d)",id);
			break;
		case DEMOD_PSK:
			sprintf(retStr,"PSK (%d)",id);
			break;
		case DEMOD_BI:
			sprintf(retStr,"BIPHASE (%d)",id);
			break;
		default:
			sprintf(retStr,"(Unknown)");
			break;
		}
	return buf;
}

uint32_t PackBits(uint8_t start, uint8_t len, uint8_t* bits){
	
	int i = start;
	int j = len-1;
	if (len > 32) {
		return 0;
	}
 	uint32_t tmp = 0;
	for (; j >= 0; --j, ++i){
		tmp	|= bits[i] << j;
	}
	return tmp;
}

static command_t CommandTable[] =
{
  {"help",   CmdHelp,           1, "This help"},
  {"config", CmdT55xxSetConfig, 1, "Set T55XX config for modulation, inversed data"},
  {"detect", CmdT55xxDetect,    0, "Try detecting the tag modulation from reading the configuration block."},
  {"read",   CmdT55xxReadBlock, 0, "<block> [password] -- Read T55xx block data (page 0) [optional password]"},
  {"write",  CmdT55xxWriteBlock,0, "<block> <data> [password] -- Write T55xx block data (page 0) [optional password]"},
  {"trace",  CmdT55xxReadTrace, 0, "[1] Show T55xx traceability data (page 1/ blk 0-1)"},
  {"info",   CmdT55xxInfo,      0, "[1] Show T55xx configuration data (page 0/ blk 0)"},
  {"dump",   CmdT55xxDump,      0, "[password] Dump T55xx card block 0-7. [optional password]"},
  {"special", special,           0, "Shows how a datablock changes with 32 different offsets"},
  {NULL, NULL, 0, NULL}
};

int CmdLFT55XX(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
