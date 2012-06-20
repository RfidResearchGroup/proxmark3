//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// Modified 2010-2012 by <adrian -at- atrox.at>
// Modified 2012 by <vsza at vsza.hu>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO15693 commands
//-----------------------------------------------------------------------------
// There are three basic operation modes, depending on which device (proxmark/pc)
// the signal processing, (de)modulation, transmission protocol and logic is done.
// Mode 1:
// All steps are done on the proxmark, the output of the commands is returned via
// USB-debug-print commands.
// Mode 2: 
// The protocol is done on the PC, passing only Iso15693 data frames via USB. This
// allows direct communication with a tag on command level
// Mode 3:
// The proxmark just samples the antenna and passes this "analog" data via USB to
// the client. Signal Processing & decoding is done on the pc. This is the slowest
// variant, but offers the possibility to analyze the waveforms directly. 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "proxusb.h"
#include "data.h"
#include "graph.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf15.h"
#include "iso15693tools.h"
#include "cmdmain.h"

#define FrameSOF              Iso15693FrameSOF
#define Logic0						Iso15693Logic0
#define Logic1						Iso15693Logic1
#define FrameEOF					Iso15693FrameEOF

#define Crc(data,datalen)     Iso15693Crc(data,datalen)
#define AddCrc(data,datalen)  Iso15693AddCrc(data,datalen)
#define sprintUID(target,uid)	Iso15693sprintUID(target,uid)

static int CmdHelp(const char *Cmd);

// structure and database for uid -> tagtype lookups 
typedef struct { 
	uint64_t uid;
	int mask; // how many MSB bits used
	char* desc;
} productName; 


const productName uidmapping[] = {
	// UID, #significant Bits, "Vendor(+Product)"
	{ 0xE001000000000000LL, 16, "Motorola" },
	{ 0xE002000000000000LL, 16, "ST Microelectronics" },
	{ 0xE003000000000000LL, 16, "Hitachi" },
	{ 0xE004000000000000LL, 16, "Philips" },
	{ 0xE004010000000000LL, 24, "Philips; IC SL2 ICS20" },
	{ 0xE005000000000000LL, 16, "Infineon" },
	{ 0xE005400000000000LL, 24, "Infineon; 56x32bit" },
	{ 0xE006000000000000LL, 16, "Cylinc" },
	{ 0xE007000000000000LL, 16, "Texas Instrument; " },
	{ 0xE007000000000000LL, 20, "Texas Instrument; Tag-it HF-I Plus Inlay; 64x32bit" },
	{ 0xE007100000000000LL, 20, "Texas Instrument; Tag-it HF-I Plus Chip; 64x32bit" },
	{ 0xE007800000000000LL, 23, "Texas Instrument; Tag-it HF-I Plus (RF-HDT-DVBB tag or Third Party Products)" },
	{ 0xE007C00000000000LL, 23, "Texas Instrument; Tag-it HF-I Standard; 8x32bit" },
	{ 0xE007C40000000000LL, 23, "Texas Instrument; Tag-it HF-I Pro; 8x23bit; password" },	
	{ 0xE008000000000000LL, 16, "Fujitsu" },
	{ 0xE009000000000000LL, 16, "Matsushita" },
	{ 0xE00A000000000000LL, 16, "NEC" },
	{ 0xE00B000000000000LL, 16, "Oki Electric" },
	{ 0xE00C000000000000LL, 16, "Toshiba" },
	{ 0xE00D000000000000LL, 16, "Mitsubishi" },
	{ 0xE00E000000000000LL, 16, "Samsung" },
	{ 0xE00F000000000000LL, 16, "Hyundai" },
	{ 0xE010000000000000LL, 16, "LG-Semiconductors" },
	{ 0xE012000000000000LL, 16, "HID Corporation" },
	{ 0xE016000000000000LL, 16, "EM-Marin SA (Skidata)" },
	{ 0xE016040000000000LL, 24, "EM-Marin SA (Skidata Keycard-eco); EM4034? no 'read', just 'readmulti'" },
	{ 0xE0160c0000000000LL, 24, "EM-Marin SA; EM4035?" },
	{ 0xE016100000000000LL, 24, "EM-Marin SA (Skidata); EM4135; 36x64bit start page 13" },
	{ 0xE016940000000000LL, 24, "EM-Marin SA (Skidata); 51x64bit" },
	{ 0,0,"no tag-info available" } // must be the last entry
};


// fast method to just read the UID of a tag (collission detection not supported)
//		*buf	should be large enough to fit the 64bit uid
// returns 1 if suceeded
int getUID(uint8_t *buf) 
{
	UsbCommand *r;	
	uint8_t *recv;
	UsbCommand c = {CMD_ISO_15693_COMMAND, {0, 1, 1}}; // len,speed,recv?
	uint8_t *req=c.d.asBytes;
	int reqlen=0;
	
	for (int retry=0;retry<3; retry++) { // don't give up the at the first try		
		
		req[0]= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | 
		        ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
		req[1]=ISO15_CMD_INVENTORY;
		req[2]=0; // mask length
		reqlen=AddCrc(req,3);
		c.arg[0]=reqlen;
	
		SendCommand(&c);
		
		r=WaitForResponseTimeout(CMD_ACK,1000);
		
		if (r!=NULL) {
			recv = r->d.asBytes;
			if (r->arg[0]>=12 && ISO15_CRC_CHECK==Crc(recv,12)) {
			   memcpy(buf,&recv[2],8);
			   return 1;
			} 
		} 
	} // retry
	return 0;
}



// get a product description based on the UID
//		uid[8] 	tag uid
// returns description of the best match	
static char* getTagInfo(uint8_t *uid) {
	uint64_t myuid,mask;
	int i=0, best=-1;	
	memcpy(&myuid,uid,sizeof(uint64_t));
	while (uidmapping[i].mask>0) {
		mask=(~0LL) <<(64-uidmapping[i].mask);
		if ((myuid & mask) == uidmapping[i].uid) {
			if (best==-1) { 
				best=i;
			} else {
				if (uidmapping[i].mask>uidmapping[best].mask) {
					best=i;
				}
			}					
		} 
		i++;
	} 

	if (best>=0) return uidmapping[best].desc;
	
	return uidmapping[i].desc; 
}


// return a clear-text message to an errorcode
static char* TagErrorStr(uint8_t error) {
	switch (error) {
		case 0x01: return "The command is not supported";
		case 0x02: return "The command is not recognised";
		case 0x03: return "The option is not supported.";
		case 0x0f: return "Unknown error.";
		case 0x10: return "The specified block is not available (doesn’t exist).";
		case 0x11: return "The specified block is already -locked and thus cannot be locked again";
		case 0x12: return "The specified block is locked and its content cannot be changed.";
		case 0x13: return "The specified block was not successfully programmed.";
		case 0x14: return "The specified block was not successfully locked.";
		default: return "Reserved for Future Use or Custom command error.";
	}
}


// Mode 3
int CmdHF15Demod(const char *Cmd)
{
	// The sampling rate is 106.353 ksps/s, for T = 18.8 us
	
	int i, j;
	int max = 0, maxPos = 0;

	int skip = 4;

	if (GraphTraceLen < 1000) return 0;

	// First, correlate for SOF
	for (i = 0; i < 100; i++) {
		int corr = 0;
		for (j = 0; j < arraylen(FrameSOF); j += skip) {
			corr += FrameSOF[j] * GraphBuffer[i + (j / skip)];
		}
		if (corr > max) {
			max = corr;
			maxPos = i;
		}
	}
	PrintAndLog("SOF at %d, correlation %d", maxPos,
		max / (arraylen(FrameSOF) / skip));
	
	i = maxPos + arraylen(FrameSOF) / skip;
	int k = 0;
	uint8_t outBuf[20];
	memset(outBuf, 0, sizeof(outBuf));
	uint8_t mask = 0x01;
	for (;;) {
		int corr0 = 0, corr1 = 0, corrEOF = 0;
		for (j = 0; j < arraylen(Logic0); j += skip) {
			corr0 += Logic0[j] * GraphBuffer[i + (j / skip)];
		}
		for (j = 0; j < arraylen(Logic1); j += skip) {
			corr1 += Logic1[j] * GraphBuffer[i + (j / skip)];
		}
		for (j = 0; j < arraylen(FrameEOF); j += skip) {
			corrEOF += FrameEOF[j] * GraphBuffer[i + (j / skip)];
		}
		// Even things out by the length of the target waveform.
		corr0 *= 4;
		corr1 *= 4;
		
		if (corrEOF > corr1 && corrEOF > corr0) {
			PrintAndLog("EOF at %d", i);
			break;
		} else if (corr1 > corr0) {
			i += arraylen(Logic1) / skip;
			outBuf[k] |= mask;
		} else {
			i += arraylen(Logic0) / skip;
		}
		mask <<= 1;
		if (mask == 0) {
			k++;
			mask = 0x01;
		}
		if ((i + (int)arraylen(FrameEOF)) >= GraphTraceLen) {
			PrintAndLog("ran off end!");
			break;
		}
	}
	if (mask != 0x01) {
		PrintAndLog("error, uneven octet! (discard extra bits!)");
		PrintAndLog("   mask=%02x", mask);
	}
	PrintAndLog("%d octets", k);
	
	for (i = 0; i < k; i++) {
		PrintAndLog("# %2d: %02x ", i, outBuf[i]);
	}
	PrintAndLog("CRC=%04x", Iso15693Crc(outBuf, k - 2));
	return 0;
}



// * Acquire Samples as Reader (enables carrier, sends inquiry)
int CmdHF15Read(const char *Cmd)
{
	UsbCommand c = {CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_15693};
	SendCommand(&c);
	return 0;
}

// Record Activity without enabeling carrier
int CmdHF15Record(const char *Cmd)
{
	UsbCommand c = {CMD_RECORD_RAW_ADC_SAMPLES_ISO_15693};
	SendCommand(&c);
	return 0;
}

int CmdHF15Reader(const char *Cmd)
{
	UsbCommand c = {CMD_READER_ISO_15693, {strtol(Cmd, NULL, 0), 0, 0}};
	SendCommand(&c);
	return 0;
}

// Simulation is still not working very good
int CmdHF15Sim(const char *Cmd)
{
	UsbCommand c = {CMD_SIMTAG_ISO_15693, {strtol(Cmd, NULL, 0), 0, 0}};
	SendCommand(&c);
	return 0;
}

// finds the AFI (Application Family Idendifier) of a card, by trying all values
// (There is no standard way of reading the AFI, allthough some tags support this)
int CmdHF15Afi(const char *Cmd)
{
	UsbCommand c = {CMD_ISO_15693_FIND_AFI, {strtol(Cmd, NULL, 0), 0, 0}};
	SendCommand(&c);
	return 0;
}

// Reads all memory pages
int CmdHF15DumpMem(const char*Cmd) {
	UsbCommand *r;	
	uint8_t uid[8];	
	uint8_t *recv=NULL;
	UsbCommand c = {CMD_ISO_15693_COMMAND, {0, 1, 1}}; // len,speed,recv?
	uint8_t *req=c.d.asBytes;
	int reqlen=0;
	int blocknum=0;
	char output[80];
		
	if (!getUID(uid)) {
		PrintAndLog("No Tag found.");
		return 0;
	}
	
	PrintAndLog("Reading memory from tag UID=%s",sprintUID(NULL,uid));
	PrintAndLog("Tag Info: %s",getTagInfo(uid));

	for (int retry=0; retry<5; retry++) {
		
		req[0]= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | 
		        ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS;
		req[1]=ISO15_CMD_READ;
		memcpy(&req[2],uid,8);
		req[10]=blocknum;
		reqlen=AddCrc(req,11);
		c.arg[0]=reqlen;
	
		SendCommand(&c);
		
		r=WaitForResponseTimeout(CMD_ACK,1000);
		
		if (r!=NULL) {
			recv = r->d.asBytes;
			if (ISO15_CRC_CHECK==Crc(recv,r->arg[0])) {
				if (!(recv[0] & ISO15_RES_ERROR)) {
					retry=0;
					*output=0; // reset outputstring
					sprintf(output, "Block %2i   ",blocknum);
					for ( int i=1; i<r->arg[0]-2; i++) { // data in hex
						sprintf(output+strlen(output),"%02hX ",recv[i]);					
					}					
					strcat(output,"   "); 
					for ( int i=1; i<r->arg[0]-2; i++) { // data in cleaned ascii
						sprintf(output+strlen(output),"%c",(recv[i]>31 && recv[i]<127)?recv[i]:'.');					
					}					
					PrintAndLog("%s",output);	
					blocknum++;
					// PrintAndLog("bn=%i",blocknum);
				} else {
					PrintAndLog("Tag returned Error %i: %s",recv[1],TagErrorStr(recv[1])); 
					return 0;
				}
			} // else PrintAndLog("crc");
		} // else PrintAndLog("r null");
		
	} // retry
	if (r && r->arg[0]<3) 
		PrintAndLog("Lost Connection");
	else if (r && ISO15_CRC_CHECK!=Crc(r->d.asBytes,r->arg[0]))
		PrintAndLog("CRC Failed");
	else 
		PrintAndLog("Tag returned Error %i: %s",recv[1],TagErrorStr(recv[1])); 
	return 0;
}


// "HF 15" interface

static command_t CommandTable15[] = 
{
	{"help",    CmdHF15Help,    1, "This help"},
	{"demod",   CmdHF15Demod,   1, "Demodulate ISO15693 from tag"},
	{"read",    CmdHF15Read,    0, "Read HF tag (ISO 15693)"},
	{"record",  CmdHF15Record,  0, "Record Samples (ISO 15693)"}, // atrox
	{"reader",  CmdHF15Reader,  0, "Act like an ISO15693 reader"},
	{"sim",     CmdHF15Sim,     0, "Fake an ISO15693 tag"},
	{"cmd",     CmdHF15Cmd,     0, "Send direct commands to ISO15693 tag"},
	{"findafi", CmdHF15Afi,     0, "Brute force AFI of an ISO15693 tag"},
	{"dumpmemory", CmdHF15DumpMem,     0, "Read all memory pages of an ISO15693 tag"},
		{NULL, NULL, 0, NULL}
};

int CmdHF15(const char *Cmd)
{
	CmdsParse(CommandTable15, Cmd);
	return 0;
}

int CmdHF15Help(const char *Cmd)
{
	CmdsHelp(CommandTable15);
	return 0;
}


// "HF 15 Cmd" Interface
// Allows direct communication with the tag on command level

int CmdHF15CmdInquiry(const char *Cmd) 
{
	UsbCommand *r;	
	uint8_t *recv;
	UsbCommand c = {CMD_ISO_15693_COMMAND, {0, 1, 1}}; // len,speed,recv?
	uint8_t *req=c.d.asBytes;
	int reqlen=0;
	
	req[0]= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | 
	        ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
	req[1]=ISO15_CMD_INVENTORY;
	req[2]=0; // mask length
	reqlen=AddCrc(req,3);
	c.arg[0]=reqlen;

	SendCommand(&c);
	
	r=WaitForResponseTimeout(CMD_ACK,1000);
	
	if (r!=NULL) {
		if (r->arg[0]>=12) {
		   recv = r->d.asBytes;
		   PrintAndLog("UID=%s",sprintUID(NULL,&recv[2]));
		   PrintAndLog("Tag Info: %s",getTagInfo(&recv[2]));	
		} else {
			PrintAndLog("Response to short, just %i bytes. No tag?\n",r->arg[0]);		
		}
	} else {
		PrintAndLog("timeout.");
	}
	return 0;
}


// Turns debugging on(1)/off(0)
int CmdHF15CmdDebug( const char *cmd) {
	int debug=atoi(cmd);
	if (strlen(cmd)<1) {
		PrintAndLog("Usage: hf 15 cmd debug  <0/1>");
		PrintAndLog("	0..no debugging output  1..turn debugging on");	
		return 0;
	}

	UsbCommand c = {CMD_ISO_15693_DEBUG, {debug, 0, 0}};
	SendCommand(&c);
	return 0;
}


int CmdHF15CmdRaw (const char *cmd) {
	UsbCommand *r;	
	uint8_t *recv;
	UsbCommand c = {CMD_ISO_15693_COMMAND, {0, 1, 1}}; // len,speed,recv?
	int reply=1;
	int fast=1;	
	int crc=0;
	char buf[5]="";
	int i=0;
	uint8_t data[100];
	unsigned int datalen=0, temp;
	char *hexout;

	
	if (strlen(cmd)<3) {
		PrintAndLog("Usage: hf 15 cmd raw  [-r] [-2] [-c] <0A 0B 0C ... hex>");
		PrintAndLog("       -r    do not read response");
		PrintAndLog("       -2    use slower '1 out of 256' mode");
		PrintAndLog("       -c	  calculate and append CRC");
		PrintAndLog(" Tip: turn on debugging for verbose output");		
		return 0;	
	}

	// strip
	while (*cmd==' ' || *cmd=='\t') cmd++;
	
	while (cmd[i]!='\0') {
		if (cmd[i]==' ' || cmd[i]=='\t') { i++; continue; }
		if (cmd[i]=='-') {
			switch (cmd[i+1]) {
				case 'r': 
				case 'R': 
					reply=0;
					break;
				case '2':
					fast=0;
					break;
				case 'c':
				case 'C':				
					crc=1;
					break;
				default:
					PrintAndLog("Invalid option");
					return 0;
			}
			i+=2;
			continue;
		}
		if ((cmd[i]>='0' && cmd[i]<='9') ||
		    (cmd[i]>='a' && cmd[i]<='f') ||
		    (cmd[i]>='A' && cmd[i]<='F') ) {
		    buf[strlen(buf)+1]=0;
		    buf[strlen(buf)]=cmd[i];
		    i++;
		    
		    if (strlen(buf)>=2) {
		    	sscanf(buf,"%x",&temp);
		    	data[datalen]=(uint8_t)(temp & 0xff);
		    	datalen++;
		    	*buf=0;
		    }
		    continue;
		}
		PrintAndLog("Invalid char on input");
		return 0;
	}
	if (crc) datalen=AddCrc(data,datalen);
	
	c.arg[0]=datalen;
	c.arg[1]=fast;
	c.arg[2]=reply;
	memcpy(c.d.asBytes,data,datalen);
	
	SendCommand(&c);
	
	if (reply) {
		r=WaitForResponseTimeout(CMD_ACK,1000);
	
		if (r!=NULL) {
			recv = r->d.asBytes;
			PrintAndLog("received %i octets",r->arg[0]);
			hexout = (char *)malloc(r->arg[0] * 3 + 1);
			if (hexout != NULL) {
				for (int i = 0; i < r->arg[0]; i++) { // data in hex
					sprintf(&hexout[i * 3], "%02hX ", recv[i]);
				}
				PrintAndLog("%s", hexout);
				free(hexout);
			}
		} else {
			PrintAndLog("timeout while waiting for reply.");
		}
		
	} // if reply
	return 0;
}


/**
 * parses common HF 15 CMD parameters and prepares some data structures
 * Parameters:
 *  **cmd   	command line
 */
int prepareHF15Cmd(char **cmd, UsbCommand *c, uint8_t iso15cmd[], int iso15cmdlen) {
	int temp;
	uint8_t *req=c->d.asBytes, uid[8];
	uint32_t reqlen=0;

	// strip
	while (**cmd==' ' || **cmd=='\t') (*cmd)++;
	
	if (strstr(*cmd,"-2")==*cmd) {
	 	c->arg[1]=0; // use 1of256
	 	(*cmd)+=2;
	}

	// strip
	while (**cmd==' ' || **cmd=='\t') (*cmd)++;
	
	if (strstr(*cmd,"-o")==*cmd) {
	 	req[reqlen]=ISO15_REQ_OPTION;
	 	(*cmd)+=2;
	}
	
	// strip
	while (**cmd==' ' || **cmd=='\t') (*cmd)++;
	
	switch (**cmd) {
		case 0:
			PrintAndLog("missing addr");
			return 0;
			break;
		case 's':
		case 'S':
			// you must have selected the tag earlier
			req[reqlen++]|= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | 
		       ISO15_REQ_NONINVENTORY | ISO15_REQ_SELECT;
		   memcpy(&req[reqlen],&iso15cmd[0],iso15cmdlen);
			reqlen+=iso15cmdlen;		   
		   break;
		case 'u':
		case 'U':
			// unaddressed mode may not be supported by all vendors
			req[reqlen++]|= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | 
		       ISO15_REQ_NONINVENTORY;
		   memcpy(&req[reqlen],&iso15cmd[0],iso15cmdlen);
			reqlen+=iso15cmdlen;		   
		   break;
		case '*':
			// we scan for the UID ourself
			req[reqlen++]|= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | 
		       ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS;
		   memcpy(&req[reqlen],&iso15cmd[0],iso15cmdlen);
			reqlen+=iso15cmdlen;		   
		   if (!getUID(uid)) {
		   	PrintAndLog("No Tag found");
		   	return 0;
		   }
		   memcpy(req+reqlen,uid,8);
		   PrintAndLog("Detected UID %s",sprintUID(NULL,uid));
		   reqlen+=8;
			break;			
		default:
			req[reqlen++]|= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | 
		       ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS;
			memcpy(&req[reqlen],&iso15cmd[0],iso15cmdlen);
			reqlen+=iso15cmdlen;		   
		   
/* 			sscanf(cmd,"%hX%hX%hX%hX%hX%hX%hX%hX",
				(short unsigned int *)&uid[7],(short unsigned int *)&uid[6],
				(short unsigned int *)&uid[5],(short unsigned int *)&uid[4],
				(short unsigned int *)&uid[3],(short unsigned int *)&uid[2],
				(short unsigned int *)&uid[1],(short unsigned int *)&uid[0]); */
			for (int i=0;i<8 && (*cmd)[i*2] && (*cmd)[i*2+1];i++) { // parse UID
				sscanf((char[]){(*cmd)[i*2],(*cmd)[i*2+1],0},"%X",&temp);
				uid[7-i]=temp&0xff;
			}				
				
			PrintAndLog("Using UID %s",sprintUID(NULL,uid));
			memcpy(&req[reqlen],&uid[0],8);		   
		   reqlen+=8;
	}
	// skip to next space		
	while (**cmd!=' ' && **cmd!='\t') (*cmd)++;
	// skip over the space
	while (**cmd==' ' || **cmd=='\t') (*cmd)++;
	
	c->arg[0]=reqlen;	
	return 1;
}

/**
 * Commandline handling: HF15 CMD SYSINFO
 * get system information from tag/VICC
 */
int CmdHF15CmdSysinfo(const char *Cmd) {
	UsbCommand *r;	
	uint8_t *recv;
	UsbCommand c = {CMD_ISO_15693_COMMAND, {0, 1, 1}}; // len,speed,recv?
	uint8_t *req=c.d.asBytes;
	int reqlen=0;
	char cmdbuf[100];
	char *cmd=cmdbuf;
	char output[2048]="";
	int i;
	
	strncpy(cmd,Cmd,99);

	// usage:
	if (strlen(cmd)<1) {
		PrintAndLog("Usage:  hf 15 cmd sysinfo    [options] <uid|s|u|*>");
		PrintAndLog("           options:");
		PrintAndLog("               -2        use slower '1 out of 256' mode");
		PrintAndLog("           uid (either): ");
		PrintAndLog("               <8B hex>  full UID eg E011223344556677");
		PrintAndLog("               s         selected tag");
		PrintAndLog("               u         unaddressed mode");
		PrintAndLog("               *         scan for tag");
		PrintAndLog("           start#:       page number to start 0-255");  
		PrintAndLog("           count#:       number of pages");  
		return 0;
	}	
	
	prepareHF15Cmd(&cmd, &c,(uint8_t[]){ISO15_CMD_SYSINFO},1);	
	reqlen=c.arg[0];
	
	reqlen=AddCrc(req,reqlen);
	c.arg[0]=reqlen;

	SendCommand(&c);

	r=WaitForResponseTimeout(CMD_ACK,1000);
	
	if (r!=NULL && r->arg[0]>2) {
		recv = r->d.asBytes;
		if (ISO15_CRC_CHECK==Crc(recv,r->arg[0])) {
			if (!(recv[0] & ISO15_RES_ERROR)) {
				*output=0; // reset outputstring
				for ( i=1; i<r->arg[0]-2; i++) {
					sprintf(output+strlen(output),"%02hX ",recv[i]);					
				}					
				strcat(output,"\n\r");
				strcat(output,"UID = ");
				strcat(output,sprintUID(NULL,recv+2));
				strcat(output,"\n\r");
				strcat(output,getTagInfo(recv+2)); //ABC
				strcat(output,"\n\r");
				i=10;
				if (recv[1] & 0x01) 
					sprintf(output+strlen(output),"DSFID supported, set to %02hX\n\r",recv[i++]);
				else 
					strcat(output,"DSFID not supported\n\r");
				if (recv[1] & 0x02) 
					sprintf(output+strlen(output),"AFI supported, set to %03hX\n\r",recv[i++]);
				else 
					strcat(output,"AFI not supported\n\r");
				if (recv[1] & 0x04) {
					strcat(output,"Tag provides info on memory layout (vendor dependent)\n\r");
					sprintf(output+strlen(output)," %i (or %i) bytes/page x %i pages \n\r",
							(recv[i+1]&0x1F)+1, (recv[i+1]&0x1F), recv[i]+1);
					i+=2;
				} else 
					strcat(output,"Tag does not provide information on memory layout\n\r");
				if (recv[1] & 0x08) sprintf(output+strlen(output),"IC reference given: %02hX\n\r",recv[i++]);
					else strcat(output,"IC reference not given\n\r");


				PrintAndLog("%s",output);	
			} else {
				PrintAndLog("Tag returned Error %i: %s",recv[0],TagErrorStr(recv[0])); 
			}		   
		} else {
			PrintAndLog("CRC failed");
		}
	} else {
		PrintAndLog("timeout: no answer");
	}
	
	return 0;
}

/**
 * Commandline handling: HF15 CMD READMULTI
 * Read multiple blocks at once (not all tags support this)
 */
int CmdHF15CmdReadmulti(const char *Cmd) {
	UsbCommand *r;	
	uint8_t *recv;
	UsbCommand c = {CMD_ISO_15693_COMMAND, {0, 1, 1}}; // len,speed,recv?
	uint8_t *req=c.d.asBytes;
	int reqlen=0, pagenum,pagecount;
	char cmdbuf[100];
	char *cmd=cmdbuf;
	char output[2048]="";
	
	strncpy(cmd,Cmd,99);

	// usage:
	if (strlen(cmd)<3) {
		PrintAndLog("Usage:  hf 15 cmd readmulti  [options] <uid|s|u|*> <start#> <count#>");
		PrintAndLog("           options:");
		PrintAndLog("               -2        use slower '1 out of 256' mode");
		PrintAndLog("           uid (either): ");
		PrintAndLog("               <8B hex>  full UID eg E011223344556677");
		PrintAndLog("               s         selected tag");
		PrintAndLog("               u         unaddressed mode");
		PrintAndLog("               *         scan for tag");
		PrintAndLog("           start#:       page number to start 0-255");  
		PrintAndLog("           count#:       number of pages");  
		return 0;
	}	
	
	prepareHF15Cmd(&cmd, &c,(uint8_t[]){ISO15_CMD_READMULTI},1);	
	reqlen=c.arg[0];

	pagenum=strtol(cmd,NULL,0);

	// skip to next space		
	while (*cmd!=' ' && *cmd!='\t') cmd++;
	// skip over the space
	while (*cmd==' ' || *cmd=='\t') cmd++;

	pagecount=strtol(cmd,NULL,0);
	if (pagecount>0) pagecount--; // 0 means 1 page, 1 means 2 pages, ...	
	
	req[reqlen++]=(uint8_t)pagenum;
	req[reqlen++]=(uint8_t)pagecount;
	
	reqlen=AddCrc(req,reqlen);
	
	c.arg[0]=reqlen;

	SendCommand(&c);

	r=WaitForResponseTimeout(CMD_ACK,1000);
	
	if (r!=NULL && r->arg[0]>2) {
		recv = r->d.asBytes;
		if (ISO15_CRC_CHECK==Crc(recv,r->arg[0])) {
			if (!(recv[0] & ISO15_RES_ERROR)) {
				*output=0; // reset outputstring
				for ( int i=1; i<r->arg[0]-2; i++) {
					sprintf(output+strlen(output),"%02hX ",recv[i]);					
				}					
				strcat(output,"   ");
				for ( int i=1; i<r->arg[0]-2; i++) {
					sprintf(output+strlen(output),"%c",recv[i]>31 && recv[i]<127?recv[i]:'.');					
				}					
				PrintAndLog("%s",output);	
			} else {
				PrintAndLog("Tag returned Error %i: %s",recv[0],TagErrorStr(recv[0])); 
			}		   
		} else {
			PrintAndLog("CRC failed");
		}
	} else {
		PrintAndLog("no answer");
	}
	
	return 0;
}

/**
 * Commandline handling: HF15 CMD READ
 * Reads a single Block
 */
int CmdHF15CmdRead(const char *Cmd) {
	UsbCommand *r;	
	uint8_t *recv;
	UsbCommand c = {CMD_ISO_15693_COMMAND, {0, 1, 1}}; // len,speed,recv?
	uint8_t *req=c.d.asBytes;
	int reqlen=0, pagenum;
	char cmdbuf[100];
	char *cmd=cmdbuf;
	char output[100]="";
	
	strncpy(cmd,Cmd,99);

	// usage:
	if (strlen(cmd)<3) {
		PrintAndLog("Usage:  hf 15 cmd read    [options] <uid|s|u|*> <page#>");
		PrintAndLog("           options:");
		PrintAndLog("               -2        use slower '1 out of 256' mode");
		PrintAndLog("           uid (either): ");
		PrintAndLog("               <8B hex>  full UID eg E011223344556677");
		PrintAndLog("               s         selected tag");
		PrintAndLog("               u         unaddressed mode");
		PrintAndLog("               *         scan for tag");
		PrintAndLog("           page#:        page number 0-255");  
		return 0;
	}	
	
	prepareHF15Cmd(&cmd, &c,(uint8_t[]){ISO15_CMD_READ},1);	
	reqlen=c.arg[0];

	pagenum=strtol(cmd,NULL,0);
	/*if (pagenum<0) {
		PrintAndLog("invalid pagenum");
		return 0;
	}	*/
	
	req[reqlen++]=(uint8_t)pagenum;
	
	reqlen=AddCrc(req,reqlen);
	
	c.arg[0]=reqlen;

	SendCommand(&c);

	r=WaitForResponseTimeout(CMD_ACK,1000);
	
	if (r!=NULL && r->arg[0]>2) {
		recv = r->d.asBytes;
		if (ISO15_CRC_CHECK==Crc(recv,r->arg[0])) {
			if (!(recv[0] & ISO15_RES_ERROR)) {
				*output=0; // reset outputstring
				//sprintf(output, "Block %2i   ",blocknum);
				for ( int i=1; i<r->arg[0]-2; i++) {
					sprintf(output+strlen(output),"%02hX ",recv[i]);					
				}					
				strcat(output,"   ");
				for ( int i=1; i<r->arg[0]-2; i++) {
					sprintf(output+strlen(output),"%c",recv[i]>31 && recv[i]<127?recv[i]:'.');					
				}					
				PrintAndLog("%s",output);	
			} else {
				PrintAndLog("Tag returned Error %i: %s",recv[1],TagErrorStr(recv[1])); 
			}		   
		} else {
			PrintAndLog("CRC failed");
		}
	} else {
		PrintAndLog("no answer");
	}
	
	return 0;
}


/**
 * Commandline handling: HF15 CMD WRITE
 * Writes a single Block - might run into timeout, even when successful
 */
int CmdHF15CmdWrite(const char *Cmd) {
	UsbCommand *r;	
	uint8_t *recv;
	UsbCommand c = {CMD_ISO_15693_COMMAND, {0, 1, 1}}; // len,speed,recv?
	uint8_t *req=c.d.asBytes;
	int reqlen=0, pagenum, temp;
	char cmdbuf[100];
	char *cmd=cmdbuf;
	char *cmd2;
	
	strncpy(cmd,Cmd,99);

	// usage:
	if (strlen(cmd)<3) {
		PrintAndLog("Usage:  hf 15 cmd write    [options] <uid|s|u|*> <page#> <hexdata>");
		PrintAndLog("           options:");
		PrintAndLog("               -2        use slower '1 out of 256' mode");
		PrintAndLog("               -o        set OPTION Flag (needed for TI)");
		PrintAndLog("           uid (either): ");
		PrintAndLog("               <8B hex>  full UID eg E011223344556677");
		PrintAndLog("               s         selected tag");
		PrintAndLog("               u         unaddressed mode");
		PrintAndLog("               *         scan for tag");
		PrintAndLog("           page#:        page number 0-255");  
		PrintAndLog("           hexdata:      data to be written eg AA BB CC DD");  
		return 0;
	}	
	
	prepareHF15Cmd(&cmd, &c,(uint8_t[]){ISO15_CMD_WRITE},1);	
	reqlen=c.arg[0];
	
	// *cmd -> page num ; *cmd2 -> data 
	cmd2=cmd;
	while (*cmd2!=' ' && *cmd2!='\t' && *cmd2) cmd2++;
	*cmd2=0;
	cmd2++;	
		
	pagenum=strtol(cmd,NULL,0);
	/*if (pagenum<0) {
		PrintAndLog("invalid pagenum");
		return 0;
	}	*/	
	req[reqlen++]=(uint8_t)pagenum;
	
	
	while (cmd2[0] && cmd2[1]) { // hexdata, read by 2 hexchars 
		if (*cmd2==' ') {
			cmd2++; 
			continue; 
		}
		sscanf((char[]){cmd2[0],cmd2[1],0},"%X",&temp);
		req[reqlen++]=temp & 0xff;
		cmd2+=2;
	} 
	
	reqlen=AddCrc(req,reqlen);
	
	c.arg[0]=reqlen;

	SendCommand(&c);

	r=WaitForResponseTimeout(CMD_ACK,2000);
	
	if (r!=NULL && r->arg[0]>2) {
		recv = r->d.asBytes;
		if (ISO15_CRC_CHECK==Crc(recv,r->arg[0])) {
			if (!(recv[0] & ISO15_RES_ERROR)) {					
				PrintAndLog("OK");	
			} else {
				PrintAndLog("Tag returned Error %i: %s",recv[1],TagErrorStr(recv[1])); 
			}		   
		} else {
			PrintAndLog("CRC failed");
		}
	} else {
		PrintAndLog("timeout: no answer - data may be written anyway");
	}
	
	return 0;
}



static command_t CommandTable15Cmd[] =
{
	{"help",    CmdHF15CmdHelp,    1, "This Help"},
 	{"inquiry", CmdHF15CmdInquiry, 0, "Search for tags in range"},
 /*	
	{"select",  CmdHF15CmdSelect, 0, "Select an tag with a specific UID for further commands"},
 */
	{"read",    CmdHF15CmdRead,    0, "Read a block"},	
	{"write",   CmdHF15CmdWrite,    0, "Write a block"},	
	{"readmulti",CmdHF15CmdReadmulti,    0, "Reads multiple Blocks"},
	{"sysinfo",CmdHF15CmdSysinfo,    0, "Get Card Information"},
	{"raw",		 CmdHF15CmdRaw,		0,	"Send raw hex data to tag"}, 
	{"debug",    CmdHF15CmdDebug,    0, "Turn debugging on/off"},
	{NULL, NULL, 0, NULL}
};

int CmdHF15Cmd(const char *Cmd)
{
	CmdsParse(CommandTable15Cmd, Cmd);
	return 0;
}
	
int CmdHF15CmdHelp(const char *Cmd)
{
	CmdsHelp(CommandTable15Cmd);
	return 0;
}

