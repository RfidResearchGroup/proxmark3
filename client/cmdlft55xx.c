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

#define LF_TRACE_BUFF_SIZE 20000 // 32 x 32 x 10  (32 bit times numofblock (7), times clock skip..)
#define LF_BITSSTREAM_LEN 1000 // more then 1000 bits shouldn't happend..  8block * 4 bytes * 8bits = 

//  0 = FSK
//  1 = ASK
//  2 = PSK
//  4 = NZR (direct)
typedef struct {
	uint8_t modulation;
	bool inversed;
	uint32_t block0;
} t55xx_conf_block;

// Default configuration: FSK, not inversed.
t55xx_conf_block config = {0x00, FALSE, 0x00};

	// FSK
	// FSK inverted
	//FSKrawDemod("", FALSE)
	//FSKrawDemod("1", FALSE)

	// ASK/MAN
	// ASK/MAN inverted
	//ASKmanDemod("", FALSE, FALSE)
	
	// NZR (autoclock, normal, maxerrors 1)
	// NZR (autoclock, inverse, maxerrors 1)
	//NRZrawDemod("0 0 1", FALSE) ) {
		
	// PSK (autoclock, normal, maxerrors 1)
	// PSK (autoclock, inverse, maxerrors 1)
	//PSKDemod("0 0 1", FALSE)

int usage_t55xx_config(){
	PrintAndLog("Usage: lf t55xx config [d <demodulation>] [i 0|1]");
	PrintAndLog("Options:        ");
	PrintAndLog("       h             This help");
	PrintAndLog("       d <>          Set demodulation FSK / ASK / PSK / NZR");
	PrintAndLog("       i [0|1]       Inverse data signal, Default: 0");
	PrintAndLog("Examples:");
	PrintAndLog("      lf t55xx config d FSK ");
	PrintAndLog("                    FSK demodulation");
	PrintAndLog("      lf t55xx config d FSK i 1");
	PrintAndLog("                    FSK demodulation, inverse data");
	PrintAndLog("      lf dump");
	PrintAndLog("                    Dumps all block from tag");
	PrintAndLog("      lf trace");
	PrintAndLog("                    Read trace block and decode it");
	PrintAndLog("      lf info");
	PrintAndLog("                    Read configuration and decode it");
	return 0;
}
int usage_t55xx_read(){
	PrintAndLog("Usage:  lf t55xx read <block> <password>");
    PrintAndLog("     <block>, block number to read. Between 0-7");
    PrintAndLog("     <password>, OPTIONAL password (8 hex characters)");
    PrintAndLog("");
    PrintAndLog("    sample: lf t55xx read 0           = try reading data from block 0");
	PrintAndLog("          : lf t55xx read 0 feedbeef  = try reading data from block 0 using password");
	PrintAndLog("");
	return 0;
}
int usage_t55xx_write(){
	PrintAndLog("Usage:  lf t55xx wr <block> <data> [password]");
    PrintAndLog("     <block>, block number to read. Between 0-7");
	PrintAndLog("     <data>,  4 bytes of data to write (8 hex characters)");
    PrintAndLog("     [password], OPTIONAL password 4bytes (8 hex characters)");
    PrintAndLog("");
    PrintAndLog("    sample: lf t55xx wd 3 11223344  = try writing data 11223344 to block 3");
	PrintAndLog("          : lf t55xx wd 3 11223344 feedbeef  = try writing data 11223344 to block 3 using password feedbeef");
	PrintAndLog("");
	return 0;
}
int usage_t55xx_trace() {
	PrintAndLog("Usage:  lf t55xx trace  [graph buffer data]");
	PrintAndLog("     [graph buffer data], if set, use Graphbuffer otherwise read data from tag.");
	PrintAndLog("");
	PrintAndLog("     sample: lf t55xx trace");
	PrintAndLog("           : lf t55xx trace 1");
	PrintAndLog("");
	return 0;
}
int usage_t55xx_info() {
	PrintAndLog("Usage:  lf t55xx info [graph buffer data]");
	PrintAndLog("     [graph buffer data], if set, use Graphbuffer otherwise read data from tag.");
	PrintAndLog("");
	PrintAndLog("    sample: lf t55xx info");
	PrintAndLog("          : lf t55xx info 1");
	PrintAndLog("");
	return 0;
}
int usage_t55xx_dump(){
	PrintAndLog("Usage:  lf t55xx dump <password>");
    PrintAndLog("     <password>, OPTIONAL password 4bytes (8 hex characters)");
	PrintAndLog("");
	PrintAndLog("        sample: lf t55xx dump");
	PrintAndLog("              : lf t55xx dump feedbeef");
	PrintAndLog("");
	return 0;
}

static int CmdHelp(const char *Cmd);

int CmdT55xxSetConfig(const char *Cmd){
	
	uint8_t paramNum =0;
	if(param_getchar(Cmd, paramNum) == 'h')
	{
		return usage_t55xx_config();
	}

	uint8_t buff[] = { 0x01, 0x01, 0x01, 0x01,
					   0x01, 0x01, 0x01, 0x01,
					   0x01, 0x40, 0x01, 0x01, 0x04 };
	PrintAndLog("CRC-8: %x",CRC8Maxim(buff, 13));

	//config = { 0, FALSE};
	return 0;
}

// detect configuration?

int CmdReadBlk(const char *Cmd)
{
	int block = -1;
	int password = 0xFFFFFFFF; //default to blank Block 7

	char cmdp = param_getchar(Cmd, 0);
	if (cmdp == 'h' || cmdp == 'H')
		return usage_t55xx_read();

	int res = sscanf(Cmd, "%d %x", &block, &password);

	if ( res < 1 || res > 2 ){
		usage_t55xx_read();
		return 1;
	}
	
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

	if (block == 0){
		// try a detection.
		
	}
	
	if (CmdDetectClockRate("f")){ //wave is almost certainly FSK
      //call FSK DEMOD
	  	// FSK
		if ( FSKrawDemod("", FALSE))
			printT55xx("FSK");
		// FSK inverted
		if ( FSKrawDemod("1", FALSE)) 
			printT55xx("FSK inv");
    } else {
		// ASK/MAN (autoclock, normal, maxerrors 1)
		if ( ASKmanDemod("0 0 1", FALSE, FALSE) )
			printT55xx("ASK/MAN");
		
		// ASK/MAN (autoclock, inverted, maxerrors 1)
		if ( ASKmanDemod("0 1 1", FALSE, FALSE) )
			printT55xx("ASK/MAN Inv");

		// NZR (autoclock, normal, maxerrors 1)
		if  ( NRZrawDemod("0 0 1", FALSE) )
			printT55xx("NZR");
		// NZR (autoclock, inverted, maxerrors 1)
		if  ( NRZrawDemod("0 1 1", FALSE) )
			printT55xx("NZR inv");
		
		// PSK (autoclock, normal, maxerrors 1)
		if (!PSKDemod("0 0 1", FALSE))
			printT55xx("PSK");

		// PSK (autoclock, inverted, maxerrors 1)
		if (!PSKDemod("0 1 1", FALSE))
			printT55xx("PSK inv");
	}
	return 0;
}

void printT55xx(const char *demodStr){
	
	uint32_t blockData = 0;
	uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0x00};
		
	if ( !DemodBufferLen) 
		return;
	
	int i =0;
    for (;i<DemodBufferLen;++i)
		bits[i]=DemodBuffer[i];
	
	blockData = PackBits(1, 32, bits);
	PrintAndLog("0x%08X  %s [%s]", blockData, sprint_bin(bits+1,32), demodStr );
}

/*
FSK1 / FSK1a
size = fskdemod(dest, size, 32, 0, 8, 10);  // fsk1 RF/32 
size = fskdemod(dest, size, 32, 1, 8, 10);  // fsk1a RF/32 

FSK2 / FSK2a
size = fskdemod(dest, size, 32, 0, 10, 8);  // fsk2 RF/32 
size = fskdemod(dest, size, 32, 1, 10, 8);  // fsk2a RF/32 
size = fskdemod(dest, size, 50, 1, 10, 8);  // fsk2a RF/50 
size = fskdemod(dest, size, 64, 1, 10, 8);  // FSK2a RF/64 

PSK1
errCnt = pskRawDemod(bits, &bitlen, 32, 0);
*/
int CmdWriteBlk(const char *Cmd)
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

int CmdReadTrace(const char *Cmd)
{
	uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0x00};

	char cmdp = param_getchar(Cmd, 0);
	
	if (strlen(Cmd) > 1 || cmdp == 'h' || cmdp == 'H') {
		usage_t55xx_trace();
		return 0;
	}

	if ( strlen(Cmd)==0){
	
		UsbCommand c = {CMD_T55XX_READ_TRACE, {0, 0, 0}};
		SendCommand(&c);
		if ( !WaitForResponseTimeout(CMD_ACK,NULL,2500) ) {
			PrintAndLog("command execution time out");
			return 1;
		}
		//darn
		//CmdSamples("12000");
	}
	
	size_t bitlen = getFromGraphBuf(bits);
	if ( bitlen == 0 )
		return 2;
	
	RepaintGraphWindow();

	uint8_t si = 5;
	uint32_t bl0     = PackBits(si, 32, bits);
	uint32_t bl1     = PackBits(si+32, 32, bits);
	
	uint32_t acl     = PackBits(si,  8, bits); si += 8;
	uint32_t mfc     = PackBits(si, 8, bits); si += 8;
	uint32_t cid     = PackBits(si, 5, bits); si += 5;
	uint32_t icr     = PackBits(si, 3, bits); si += 3;
	uint32_t year    = PackBits(si, 4, bits); si += 4;
	uint32_t quarter = PackBits(si, 2, bits); si += 2;
	uint32_t lotid    = PackBits(si, 12, bits); si += 12;
	uint32_t wafer   = PackBits(si, 5, bits); si += 5;
	uint32_t dw      = PackBits(si, 15, bits); 
	
	PrintAndLog("");
	PrintAndLog("-- T55xx Trace Information ----------------------------------");
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" ACL Allocation class (ISO/IEC 15963-1)  : 0x%02X (%d)", acl, acl);
	PrintAndLog(" MFC Manufacturer ID (ISO/IEC 7816-6)    : 0x%02X (%d)", mfc, mfc);
	PrintAndLog(" CID                                     : 0x%02X (%d)", cid, cid);
	PrintAndLog(" ICR IC Revision                         : %d",icr );
	PrintAndLog(" Manufactured");
	PrintAndLog("     Year/Quarter : %d/%d",2000+year, quarter );
	PrintAndLog("     Lot ID       : %d", lotid );
	PrintAndLog("     Wafer number : %d", wafer);
	PrintAndLog("     Die Number   : %d", dw);
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" Raw Data - Page 1");
	PrintAndLog("     Block 0  : 0x%08X  %s", bl0, sprint_bin(bits+5,32) );
	PrintAndLog("     Block 0  : 0x%08X  %s", bl1, sprint_bin(bits+37,32) );
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

int CmdInfo(const char *Cmd){
	/*
		Page 0 Block 0 Configuration data.
		Normal mode
		Extended mode
	*/
	char cmdp = param_getchar(Cmd, 0);

	if (cmdp == 'h' || cmdp == 'H') {
		return usage_t55xx_info();
	} else {
		CmdReadBlk("0");
	}	

	// config
	
	uint8_t bits[LF_BITSSTREAM_LEN] = {0x00};

	uint8_t si = 1;
	uint32_t bl0      = PackBits(si, 32, bits);
	
	uint32_t safer    = PackBits(si, 4, bits); si += 4;	
	uint32_t resv     = PackBits(si, 7, bits); si += 7;
	uint32_t dbr      = PackBits(si, 3, bits); si += 3;
	uint32_t extend   = PackBits(si, 1, bits); si += 1;
	uint32_t datamodulation   = PackBits(si, 5, bits); si += 5;
	uint32_t pskcf    = PackBits(si, 2, bits); si += 2;
	uint32_t aor      = PackBits(si, 1, bits); si += 1;	
	uint32_t otp      = PackBits(si, 1, bits); si += 1;	
	uint32_t maxblk   = PackBits(si, 3, bits); si += 3;
	uint32_t pwd      = PackBits(si, 1, bits); si += 1;	
	uint32_t sst      = PackBits(si, 1, bits); si += 1;	
	uint32_t fw       = PackBits(si, 1, bits); si += 1;
	uint32_t inv      = PackBits(si, 1, bits); si += 1;	
	uint32_t por      = PackBits(si, 1, bits); si += 1;
		
	PrintAndLog("");
	PrintAndLog("-- T55xx Configuration & Tag Information --------------------");
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" Safer key                 : %s", GetSaferStr(safer));
	PrintAndLog(" reserved                  : %d", resv);
	PrintAndLog(" Data bit rate             : %s", GetBitRateStr(dbr));
	PrintAndLog(" eXtended mode             : %s", (extend) ? "Yes - Warning":"No");
	PrintAndLog(" Modulation                : %s", GetModulationStr(datamodulation) );
	PrintAndLog(" PSK clock freq            : %d", pskcf);
	PrintAndLog(" AOR - Answer on Request   : %s", (aor) ? "Yes":"No");
	PrintAndLog(" OTP - One Time Pad        : %s", (otp) ? "Yes - Warning":"No" );
	PrintAndLog(" Max block                 : %d", maxblk);
	PrintAndLog(" Password mode             : %s", (pwd) ? "Yes":"No");
	PrintAndLog(" Sequence Start Terminator : %s", (sst) ? "Yes":"No");
	PrintAndLog(" Fast Write                : %s", (fw) ? "Yes":"No");
	PrintAndLog(" Inverse data              : %s", (inv) ? "Yes":"No");
	PrintAndLog(" POR-Delay                 : %s", (por) ? "Yes":"No");
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" Raw Data - Page 0");
	PrintAndLog("     Block 0  : 0x%08X  %s", bl0, sprint_bin(bits+5,32) );
	PrintAndLog("-------------------------------------------------------------");
	
	return 0;
}

int CmdDump(const char *Cmd){

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
		CmdReadBlk(s);
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
		sprintf(retStr,"%d - pasdwd",id);
	}
	if (id == 9 ){
		sprintf(retStr,"%d - testmode ",id);
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
  {"read",   CmdReadBlk,        0, "<block> [password] -- Read T55xx block data (page 0) [optional password]"},
  {"write",  CmdWriteBlk,       0, "<block> <data> [password] -- Write T55xx block data (page 0) [optional password]"},
  {"trace",  CmdReadTrace,      0, "[1] Read T55xx traceability data (page 1/ blk 0-1)"},
  {"info",   CmdInfo,           0, "[1] Read T55xx configuration data (page 0/ blk 0)"},
  {"dump",   CmdDump,           0, "[password] Dump T55xx card block 0-7. [optional password]"},
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
