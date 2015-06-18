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
//#include "sleep.h"
#include "cmddata.h"

static int CmdHelp(const char *Cmd);

int CmdHF14BDemod(const char *Cmd)
{
  int i, j, iold;
  int isum, qsum;
  int outOfWeakAt;
  bool negateI, negateQ;

  uint8_t data[256];
  int dataLen = 0;

  // As received, the samples are pairs, correlations against I and Q
  // square waves. So estimate angle of initial carrier (or just
  // quadrant, actually), and then do the demod.

  // First, estimate where the tag starts modulating.
  for (i = 0; i < GraphTraceLen; i += 2) {
    if (abs(GraphBuffer[i]) + abs(GraphBuffer[i + 1]) > 40) {
      break;
    }
  }
  if (i >= GraphTraceLen) {
    PrintAndLog("too weak to sync");
    return 0;
  }
  PrintAndLog("out of weak at %d", i);
  outOfWeakAt = i;

  // Now, estimate the phase in the initial modulation of the tag
  isum = 0;
  qsum = 0;
  for (; i < (outOfWeakAt + 16); i += 2) {
    isum += GraphBuffer[i + 0];
    qsum += GraphBuffer[i + 1];
  }
  negateI = (isum < 0);
  negateQ = (qsum < 0);

  // Turn the correlation pairs into soft decisions on the bit.
  j = 0;
  for (i = 0; i < GraphTraceLen / 2; i++) {
    int si = GraphBuffer[j];
    int sq = GraphBuffer[j + 1];
    if (negateI) si = -si;
    if (negateQ) sq = -sq;
    GraphBuffer[i] = si + sq;
    j += 2;
  }
  GraphTraceLen = i;

  i = outOfWeakAt / 2;
  while (GraphBuffer[i] > 0 && i < GraphTraceLen)
    i++;
  if (i >= GraphTraceLen) goto demodError;

  iold = i;
  while (GraphBuffer[i] < 0 && i < GraphTraceLen)
    i++;
  if (i >= GraphTraceLen) goto demodError;
  if ((i - iold) > 23) goto demodError;

  PrintAndLog("make it to demod loop");

  for (;;) {
    iold = i;
    while (GraphBuffer[i] >= 0 && i < GraphTraceLen)
      i++;
    if (i >= GraphTraceLen) goto demodError;
    if ((i - iold) > 6) goto demodError;

    uint16_t shiftReg = 0;
    if (i + 20 >= GraphTraceLen) goto demodError;

    for (j = 0; j < 10; j++) {
      int soft = GraphBuffer[i] + GraphBuffer[i + 1];

      if (abs(soft) < (abs(isum) + abs(qsum)) / 20) {
        PrintAndLog("weak bit");
      }

      shiftReg >>= 1;
      if(GraphBuffer[i] + GraphBuffer[i+1] >= 0) {
        shiftReg |= 0x200;
      }

      i+= 2;
    }

    if ((shiftReg & 0x200) && !(shiftReg & 0x001))
    {
      // valid data byte, start and stop bits okay
      PrintAndLog("   %02x", (shiftReg >> 1) & 0xff);
      data[dataLen++] = (shiftReg >> 1) & 0xff;
      if (dataLen >= sizeof(data)) {
        return 0;
      }
    } else if (shiftReg == 0x000) {
      // this is EOF
      break;
    } else {
      goto demodError;
    }
  }

  uint8_t first, second;
  ComputeCrc14443(CRC_14443_B, data, dataLen-2, &first, &second);
  PrintAndLog("CRC: %02x %02x (%s)\n", first, second,
    (first == data[dataLen-2] && second == data[dataLen-1]) ?
      "ok" : "****FAIL****");

  RepaintGraphWindow();
  return 0;

demodError:
  PrintAndLog("demod error");
  RepaintGraphWindow();
  return 0;
}

int CmdHF14BList(const char *Cmd)
{
	PrintAndLog("Deprecated command, use 'hf list 14b' instead");

	return 0;
}

int CmdHF14Sim(const char *Cmd)
{
  UsbCommand c={CMD_SIMULATE_TAG_ISO_14443};
	clearCommandBuffer();
  SendCommand(&c);
  return 0;
}

int CmdHFSimlisten(const char *Cmd)
{
  UsbCommand c = {CMD_SIMULATE_TAG_HF_LISTEN};
	clearCommandBuffer();
  SendCommand(&c);
  return 0;
}

int CmdHF14BSnoop(const char *Cmd)
{
  UsbCommand c = {CMD_SNOOP_ISO_14443};
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

int HF14BCmdRaw(bool reply, bool *crc, uint8_t power_trace, uint8_t *data, uint8_t *datalen, bool verbose){
	UsbCommand resp;
	UsbCommand c = {CMD_ISO_14443B_COMMAND, {0, 0, 0}}; // len,recv,power/trace
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
	c.arg[2] = power_trace;
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
	uint8_t power_trace = 0;
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
					power_trace |= 1;
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

	return HF14BCmdRaw(reply, &crc, power_trace, data, &datalen, true);
}

static void print_atqb_resp(uint8_t *data){
  PrintAndLog ("           UID: %s", sprint_hex(data+1,4));
  PrintAndLog ("      App Data: %s", sprint_hex(data+5,4));
  PrintAndLog ("      Protocol: %s", sprint_hex(data+9,3));
  uint8_t BitRate = data[9];
  if (!BitRate) 
    PrintAndLog ("      Bit Rate: 106 kbit/s only PICC <-> PCD");
  if (BitRate & 0x10)
    PrintAndLog ("      Bit Rate: 212 kbit/s PICC -> PCD supported");
  if (BitRate & 0x20)
    PrintAndLog ("      Bit Rate: 424 kbit/s PICC -> PCD supported"); 
  if (BitRate & 0x40)
    PrintAndLog ("      Bit Rate: 847 kbit/s PICC -> PCD supported"); 
  if (BitRate & 0x01)
    PrintAndLog ("      Bit Rate: 212 kbit/s PICC <- PCD supported");
  if (BitRate & 0x02)
    PrintAndLog ("      Bit Rate: 424 kbit/s PICC <- PCD supported"); 
  if (BitRate & 0x04)
    PrintAndLog ("      Bit Rate: 847 kbit/s PICC <- PCD supported"); 
  if (BitRate & 0x80) 
    PrintAndLog ("                Same bit rate <-> required");

  uint16_t maxFrame = data[10]>>4;
  if (maxFrame < 5) 
    maxFrame = 8*maxFrame + 16;
  else if (maxFrame == 5)
    maxFrame = 64;
  else if (maxFrame == 6)
    maxFrame = 96;
  else if (maxFrame == 7)
    maxFrame = 128;
  else if (maxFrame == 8)
    maxFrame = 256;
  else
    maxFrame = 257;

  PrintAndLog ("Max Frame Size: %d%s",maxFrame, (maxFrame == 257) ? "+ RFU" : "");

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
	PrintAndLog(" UID: %s", sprint_hex(data,8));
	PrintAndLog(" MFG: %02X, %s", data[1], getTagInfo(data[1]));
	PrintAndLog("Chip: %02X, %s", data[2]>>2, get_ST_Chip_Model(data[2]>>2));
	return;
}

int HF14BStdRead(uint8_t *data, uint8_t *datalen){
  bool crc = true;
  *datalen = 3;
  //std read cmd
  data[0] = 0x05;
  data[1] = 0x00;
  data[2] = 0x08;

	if (HF14BCmdRaw(true, &crc, 0, data, datalen, false)==0) return 0;

	if (data[0] != 0x50  || *datalen != 14 || !crc) return 0;

  PrintAndLog ("\n14443-3b tag found:");
  print_atqb_resp(data);

  return 1;
}

int HF14B_ST_Read(uint8_t *data, uint8_t *datalen){
  bool crc = true;
  *datalen = 2;
	//wake cmd
  data[0] = 0x06;
  data[1] = 0x00;

	//leave power on
	// verbose on for now for testing - turn off when functional
	if (HF14BCmdRaw(true, &crc, 1, data, datalen, true)==0) return rawClose();

	if (*datalen != 3 || !crc) return rawClose();

  uint8_t chipID = data[0];
	// select
  data[0] = 0x0E;
  data[1] = chipID;
  *datalen = 2;

	//leave power on
	// verbose on for now for testing - turn off when functional
	if (HF14BCmdRaw(true, &crc, 1, data, datalen, true)==0) return rawClose();

	if (*datalen != 3 || !crc || data[0] != chipID) return rawClose();

	// get uid
  data[0] = 0x0B;
  *datalen = 1;

	//power off
	// verbose on for now for testing - turn off when functional
	if (HF14BCmdRaw(true, &crc, 1, data, datalen, true)==0) return 0;
	rawClose();
	if (*datalen != 10 || !crc) return 0;

	PrintAndLog("\n14443-3b ST tag found:");
	print_st_info(data);
  return 1;
}

int HF14BReader(bool verbose){
  uint8_t data[100];
  uint8_t datalen = 5;
  
  // try std 14b (atqb)
	if (HF14BStdRead(data, &datalen)) return 1;

  // try st 14b
	if (HF14B_ST_Read(data, &datalen)) return 1;

	if (verbose) PrintAndLog("no 14443B tag found");
	return 0;
}

int CmdHF14BReader(const char *Cmd){
	return HF14BReader(true);
}

int CmdHFRawSamples(const char *Cmd){
	UsbCommand resp;
	UsbCommand c = {CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443, {strtol(Cmd,NULL,0), 0, 0}};
	SendCommand(&c);

	if (!WaitForResponseTimeout(CMD_ACK,&resp,1000)) {
		PrintAndLog("timeout while waiting for reply.");
		return 0;
	}
	getSamples("39999", true);
	return 1;
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
  {"demod",       CmdHF14BDemod,  1, "Demodulate ISO14443 Type B from tag"},
	{"getsamples",  CmdHFRawSamples,0, "[atqb=0 or ST=1] Send wake cmd and Get raw HF samples to GraphBuffer"},
  {"list",        CmdHF14BList,   0, "[Deprecated] List ISO 14443b history"},
  {"reader",      CmdHF14BReader, 0, "Find 14b tag (HF ISO 14443b)"},
  {"sim",         CmdHF14Sim,     0, "Fake ISO 14443 tag"},
  {"simlisten",   CmdHFSimlisten, 0, "Get HF samples as fake tag"},
  {"snoop",       CmdHF14BSnoop,  0, "Eavesdrop ISO 14443"},
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
