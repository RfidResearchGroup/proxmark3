//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443B commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include "iso14443crc.h"
#include "proxmark3.h"
#include "data.h"
#include "graph.h"
#include "util.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf14b.h"
#include "cmdmain.h"
#include "cmdhf14a.h"

static int CmdHelp(const char *Cmd);

int CmdHF14BList(const char *Cmd)
{
	PrintAndLog("Deprecated command, use 'hf list 14b' instead");

	return 0;
}

int CmdHF14BSim(const char *Cmd)
{
	UsbCommand c={CMD_SIMULATE_TAG_ISO_14443B};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdHF14BSnoop(const char *Cmd)
{
	UsbCommand c = {CMD_SNOOP_ISO_14443B};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

/* New command to read the contents of a SRI512 tag
 * SRI512 tags are ISO14443-B modulated memory tags,
 * this command just dumps the contents of the memory
 */
int CmdSri512Read(const char *Cmd)
{
	UsbCommand c = {CMD_READ_SRI512_TAG, {strtol(Cmd, NULL, 0), 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

/* New command to read the contents of a SRIX4K tag
 * SRIX4K tags are ISO14443-B modulated memory tags,
 * this command just dumps the contents of the memory/
 */
int CmdSrix4kRead(const char *Cmd)
{
	UsbCommand c = {CMD_READ_SRIX4K_TAG, {strtol(Cmd, NULL, 0), 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int rawClose(void){
	UsbCommand resp;
	UsbCommand c = {CMD_ISO_14443B_COMMAND, {0, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	if (!WaitForResponseTimeout(CMD_ACK,&resp,1000)) {
		return 0;
	}
	return 0;	
}

int HF14BCmdRaw(bool reply, bool *crc, bool power, uint8_t *data, uint8_t *datalen, bool verbose){
	UsbCommand resp;
	UsbCommand c = {CMD_ISO_14443B_COMMAND, {0, 0, 0}}; // len,recv,power
	if(*crc)
	{
		uint8_t first, second;
		ComputeCrc14443(CRC_14443_B, data, *datalen, &first, &second);
		data[*datalen] = first;
		data[*datalen + 1] = second;
		*datalen += 2;
	}

	c.arg[0] = *datalen;
	c.arg[1] = reply;
	c.arg[2] = power;
	memcpy(c.d.asBytes,data,*datalen);
	clearCommandBuffer();
	SendCommand(&c);

	if (!reply) return 1; 

	if (!WaitForResponseTimeout(CMD_ACK,&resp,1000)) {
		if (verbose) PrintAndLog("timeout while waiting for reply.");
			return 0;
		}
		*datalen = resp.arg[0];
		if (verbose) PrintAndLog("received %u octets", *datalen);
		if(*datalen<2) return 0;

		memcpy(data, resp.d.asBytes, *datalen);
		if (verbose) PrintAndLog("%s", sprint_hex(data, *datalen));

		uint8_t first, second;
		ComputeCrc14443(CRC_14443_B, data, *datalen-2, &first, &second);
		if(data[*datalen-2] == first && data[*datalen-1] == second) {
			if (verbose) PrintAndLog("CRC OK");
			*crc = true;
		} else {
			if (verbose) PrintAndLog("CRC failed");
			*crc = false;
		}
	return 1;
}

int CmdHF14BCmdRaw (const char *Cmd) {
    bool reply = true;
    bool crc = false;
	bool power = false;
    char buf[5]="";
    uint8_t data[100] = {0x00};
    uint8_t datalen = 0;
    unsigned int temp;
    int i = 0;
    if (strlen(Cmd)<3) {
        PrintAndLog("Usage: hf 14b raw [-r] [-c] [-p] <0A 0B 0C ... hex>");
        PrintAndLog("       -r    do not read response");
        PrintAndLog("       -c    calculate and append CRC");
        PrintAndLog("       -p    leave the field on after receive");
        return 0;    
    }

    // strip
    while (*Cmd==' ' || *Cmd=='\t') Cmd++;
    
    while (Cmd[i]!='\0') {
        if (Cmd[i]==' ' || Cmd[i]=='\t') { i++; continue; }
        if (Cmd[i]=='-') {
            switch (Cmd[i+1]) {
                case 'r': 
                case 'R': 
                    reply = false;
                    break;
                case 'c':
                case 'C':                
                    crc = true;
                    break;
                case 'p': 
                case 'P': 
					power = true;
                    break;
                default:
                    PrintAndLog("Invalid option");
                    return 0;
            }
            i+=2;
            continue;
        }
        if ((Cmd[i]>='0' && Cmd[i]<='9') ||
            (Cmd[i]>='a' && Cmd[i]<='f') ||
            (Cmd[i]>='A' && Cmd[i]<='F') ) {
            buf[strlen(buf)+1]=0;
            buf[strlen(buf)]=Cmd[i];
            i++;
            
            if (strlen(buf)>=2) {
                sscanf(buf,"%x",&temp);
                data[datalen++]=(uint8_t)(temp & 0xff);
                *buf=0;
            }
            continue;
        }
        PrintAndLog("Invalid char on input");
        return 1;
    }
    if (datalen == 0)
    {
      PrintAndLog("Missing data input");
      return 0;
    }

	return HF14BCmdRaw(reply, &crc, power, data, &datalen, true);
}

static void print_atqb_resp(uint8_t *data){
	PrintAndLog ("           UID: %s", sprint_hex(data+1,4));
	PrintAndLog ("      App Data: %s", sprint_hex(data+5,4));
	PrintAndLog ("      Protocol: %s", sprint_hex(data+9,3));
	uint8_t BitRate = data[9];
	if (!BitRate) PrintAndLog ("      Bit Rate: 106 kbit/s only PICC <-> PCD");
	if (BitRate & 0x10)	PrintAndLog ("      Bit Rate: 212 kbit/s PICC -> PCD supported");
	if (BitRate & 0x20)	PrintAndLog ("      Bit Rate: 424 kbit/s PICC -> PCD supported"); 
	if (BitRate & 0x40)	PrintAndLog ("      Bit Rate: 847 kbit/s PICC -> PCD supported"); 
	if (BitRate & 0x01)	PrintAndLog ("      Bit Rate: 212 kbit/s PICC <- PCD supported");
	if (BitRate & 0x02)	PrintAndLog ("      Bit Rate: 424 kbit/s PICC <- PCD supported"); 
	if (BitRate & 0x04)	PrintAndLog ("      Bit Rate: 847 kbit/s PICC <- PCD supported"); 
	if (BitRate & 0x80)	PrintAndLog ("                Same bit rate <-> required");

	uint16_t maxFrame = data[10]>>4;
	if (maxFrame < 5) 		maxFrame = 8 * maxFrame + 16;
	else if (maxFrame == 5)	maxFrame = 64;
	else if (maxFrame == 6)	maxFrame = 96;
	else if (maxFrame == 7)	maxFrame = 128;
	else if (maxFrame == 8)	maxFrame = 256;
	else maxFrame = 257;

	PrintAndLog ("Max Frame Size: %d%s", maxFrame, (maxFrame == 257) ? "+ RFU" : "");

	uint8_t protocolT = data[10] & 0xF;
	PrintAndLog (" Protocol Type: Protocol is %scompliant with ISO/IEC 14443-4",(protocolT) ? "" : "not " );
	PrintAndLog ("Frame Wait Int: %d", data[11]>>4);
	PrintAndLog (" App Data Code: Application is %s",(data[11]&4) ? "Standard" : "Proprietary");
	PrintAndLog (" Frame Options: NAD is %ssupported",(data[11]&2) ? "" : "not ");
	PrintAndLog (" Frame Options: CID is %ssupported",(data[11]&1) ? "" : "not ");

	return;
}

char *get_ST_Chip_Model(uint8_t data){
	static char model[20];
	char *retStr = model;
	memset(model,0, sizeof(model));

	switch (data) {
		case 0x0: sprintf(retStr, "SRIX4K (Special)"); break;
		case 0x2: sprintf(retStr, "SR176"); break;
		case 0x3: sprintf(retStr, "SRIX4K"); break;
		case 0x4: sprintf(retStr, "SRIX512"); break;
		case 0x6: sprintf(retStr, "SRI512"); break;
		case 0x7: sprintf(retStr, "SRI4K"); break;
		case 0xC: sprintf(retStr, "SRT512"); break;
		default: sprintf(retStr, "Unknown"); break;
	}
	return retStr;
}

static void print_st_info(uint8_t *data){
	//uid = first 8 bytes in data
	PrintAndLog(" UID: %s", sprint_hex(SwapEndian64(data,8,8),8));
	PrintAndLog(" MFG: %02X, %s", data[6], getTagInfo(data[6]));
	PrintAndLog("Chip: %02X, %s", data[5]>>2, get_ST_Chip_Model(data[5]>>2));
	return;
}

int HF14BStdReader(uint8_t *data, uint8_t *datalen){

	//05 00 00 = find one tag in field
	//1d xx xx xx xx 20 00 08 01 00 = attrib xx=crc
	//a3 = ?  (resp 03 e2 c2)
	//02 = ?  (resp 02 6a d3)
	// 022b (resp 02 67 00 [29  5b])
	// 0200a40400 (resp 02 67 00 [29 5b])
	// 0200a4040c07a0000002480300 (resp 02 67 00 [29 5b])
	// 0200a4040c07a0000002480200 (resp 02 67 00 [29 5b])
	// 0200a4040006a0000000010100 (resp 02 6a 82 [4b 4c])
	// 0200a4040c09d27600002545500200 (resp 02 67 00 [29 5b])
	// 0200a404000cd2760001354b414e4d30310000 (resp 02 6a 82 [4b 4c])
	// 0200a404000ca000000063504b43532d313500 (resp 02 6a 82 [4b 4c])
	// 0200a4040010a000000018300301000000000000000000 (resp 02 6a 82 [4b 4c])
	//03 = ?  (resp 03 [e3 c2])
	//c2 = ?  (resp c2 [66 15])
	//b2 = ?  (resp a3 [e9 67])
	bool crc = true;
	*datalen = 3;
	//std read cmd
	data[0] = 0x05;
	data[1] = 0x00;
	data[2] = 0x00;

	if (HF14BCmdRaw(true, &crc, false, data, datalen, false)==0) return 0;

	if (data[0] != 0x50  || *datalen != 14 || !crc) return 0;

	PrintAndLog ("\n14443-3b tag found:");
	print_atqb_resp(data);

	return 1;
	}

int HF14B_ST_Reader(uint8_t *data, uint8_t *datalen){
	bool crc = true;
	*datalen = 2;
	//wake cmd
	data[0] = 0x06;
	data[1] = 0x00;

	//leave power on
	// verbose on for now for testing - turn off when functional
	if (HF14BCmdRaw(true, &crc, true, data, datalen, false)==0) return rawClose();

	if (*datalen != 3 || !crc) return rawClose();

	uint8_t chipID = data[0];
	// select
	data[0] = 0x0E;
	data[1] = chipID;
	*datalen = 2;

	//leave power on
	// verbose on for now for testing - turn off when functional
	if (HF14BCmdRaw(true, &crc, true, data, datalen, false)==0) return rawClose();

	if (*datalen != 3 || !crc || data[0] != chipID) return rawClose();

	// get uid
	data[0] = 0x0B;
	*datalen = 1;

	//power off
	// verbose on for now for testing - turn off when functional
	if (HF14BCmdRaw(true, &crc, true, data, datalen, false)==0) return 0;
	rawClose();
	if (*datalen != 10 || !crc) return 0;

	PrintAndLog("\n14443-3b ST tag found:");
	print_st_info(data);
	return 1;
}

// test for other 14b type tags (mimic another reader - don't have tags to identify)
int HF14B_Other_Reader(uint8_t *data, uint8_t *datalen){
	bool crc = true;
	*datalen = 4;
	//std read cmd
	data[0] = 0x00;
	data[1] = 0x0b;
	data[2] = 0x3f;
	data[3] = 0x80;

	if (HF14BCmdRaw(true, &crc, false, data, datalen, false)!=0) {
		if (*datalen > 2 || !crc) {
			PrintAndLog ("\n14443-3b tag found:");
			PrintAndLog ("Unknown tag type answered to a 0x000b3f80 command ans:");
			PrintAndLog ("%s",sprint_hex(data,*datalen));
			return 1;
		}
	}

	crc = false;
	*datalen = 1;
	data[0] = 0x0a;

	if (HF14BCmdRaw(true, &crc, false, data, datalen, false)!=0) {
		if (*datalen > 0) {
			PrintAndLog ("\n14443-3b tag found:");
			PrintAndLog ("Unknown tag type answered to a 0x0A command ans:");
			PrintAndLog ("%s",sprint_hex(data,*datalen));
			return 1;
		}
	}
	
	crc = false;
	*datalen = 1;
	data[0] = 0x0c;

	if (HF14BCmdRaw(true, &crc, false, data, datalen, false)!=0) {
		if (*datalen > 0) {
			PrintAndLog ("\n14443-3b tag found:");
			PrintAndLog ("Unknown tag type answered to a 0x0C command ans:");
			PrintAndLog ("%s",sprint_hex(data,*datalen));
			return 1;
		}
	}

	return 0;

}

int HF14BReader(bool verbose){
	uint8_t data[100];
	uint8_t datalen = 5;

	// try std 14b (atqb)
	if (HF14BStdReader(data, &datalen)) return 1;

	// try st 14b
	if (HF14B_ST_Reader(data, &datalen)) return 1;

	// try unknown 14b read commands (to be identified later)
	//   could be read of calypso, CEPAS, moneo, or pico pass.
	if (HF14B_Other_Reader(data, &datalen)) return 1;

	if (verbose) PrintAndLog("no 14443B tag found");
	return 0;
}

int CmdHF14BReader(const char *Cmd){
	return HF14BReader(true);
}

int CmdHF14BWrite( const char *Cmd){
/*
 * For SRIX4K  blocks 00 - 7F
 * hf 14b raw -c -p 09 $srix4kwblock $srix4kwdata
 *
 * For SR512  blocks 00 - 0F
 * hf 14b raw -c -p 09 $sr512wblock $sr512wdata
 * 
 * Special block FF =  otp_lock_reg block.
 * Data len 4 bytes-
 */
 	char cmdp = param_getchar(Cmd, 0);
	uint8_t blockno = -1;
	uint8_t data[4] = {0x00};
	bool isSrix4k = true;
	char str[20];	

	if (strlen(Cmd) < 1 || cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  hf 14b write <1|2> <BLOCK> <DATA>");
		PrintAndLog("    [1 = SRIX4K]");
		PrintAndLog("    [2 = SRI512]");
		PrintAndLog("    [BLOCK number depends on tag, special block == FF]");
		PrintAndLog("     sample: hf 14b write 1 7F 11223344");
		PrintAndLog("           : hf 14b write 1 FF 11223344");
		PrintAndLog("           : hf 14b write 2 15 11223344");
		PrintAndLog("           : hf 14b write 2 FF 11223344");
		return 0;
	}

	if ( cmdp == '2' )
		isSrix4k = false;
	
	//blockno = param_get8(Cmd, 1);
	
	if ( param_gethex(Cmd,1, &blockno, 2) ) {
		PrintAndLog("Block number must include 2 HEX symbols");
		return 0;
	}
	
	if ( isSrix4k ){
		if ( blockno > 0x7f && blockno != 0xff ){
			PrintAndLog("Block number out of range");
			return 0;
		}		
	} else {
		if ( blockno > 0x0f && blockno != 0xff ){
			PrintAndLog("Block number out of range");
			return 0;
		}		
	}
	
	if (param_gethex(Cmd, 2, data, 8)) {
		PrintAndLog("Data must include 8 HEX symbols");
		return 0;
	}
 
	if ( blockno == 0xff)
		PrintAndLog("[%s] Write special block %02X [ %s ]", (isSrix4k)?"SRIX4K":"SRI512" , blockno,  sprint_hex(data,4) );
	else
		PrintAndLog("[%s] Write block %02X [ %s ]", (isSrix4k)?"SRIX4K":"SRI512", blockno,  sprint_hex(data,4) );
 
	sprintf(str, "-c 09 %02x %02x%02x%02x%02x", blockno, data[0], data[1], data[2], data[3]);

	CmdHF14BCmdRaw(str);
	return 0;
}

static command_t CommandTable[] = 
{
	{"help",        CmdHelp,        1, "This help"},
	{"list",        CmdHF14BList,   0, "[Deprecated] List ISO 14443b history"},
	{"reader",      CmdHF14BReader, 0, "Find 14b tag (HF ISO 14443b)"},
	{"sim",         CmdHF14BSim,     0, "Fake ISO 14443B tag"},

	{"snoop",       CmdHF14BSnoop,  0, "Eavesdrop ISO 14443B"},
	{"sri512read",  CmdSri512Read,  0, "Read contents of a SRI512 tag"},
	{"srix4kread",  CmdSrix4kRead,  0, "Read contents of a SRIX4K tag"},
	{"raw",         CmdHF14BCmdRaw, 0, "Send raw hex data to tag"},
	{"write",       CmdHF14BWrite,  0, "Write data to a SRI512 | SRIX4K tag"},
	{NULL, NULL, 0, NULL}
};

int CmdHF14B(const char *Cmd)
{
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd)
{
	CmdsHelp(CommandTable);
	return 0;
}
