//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Legic commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include "proxmark3.h"
#include "data.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhflegic.h"
#include "cmdmain.h"
#include "util.h"
#include "crc.h"
static int CmdHelp(const char *Cmd);

int usage_legic_calccrc8(void){
	PrintAndLog("Calculates the legic crc8 on the input hexbytes.");
	PrintAndLog("There must be an even number of hexsymbols as input.");
	PrintAndLog("Usage:  hf legic crc8 <hexbytes>");
	PrintAndLog("Options :");
	PrintAndLog("  <hexbytes>   : hex bytes in a string");
	PrintAndLog("");
	PrintAndLog("Sample  : hf legic crc8 deadbeef1122");
	return 0;
}

int usage_legic_load(void){
	PrintAndLog("It loads datasamples from the file `filename` to device memory");
	PrintAndLog("Usage:  hf legic load <file name>");
	PrintAndLog(" sample: hf legic load filename");
	return 0;
}

/*
 *  Output BigBuf and deobfuscate LEGIC RF tag data.
 *   This is based on information given in the talk held
 *  by Henryk Ploetz and Karsten Nohl at 26c3
 */
int CmdLegicDecode(const char *Cmd) {
	// Index for the bytearray.
	int i = 0;
	int k = 0, segmentNum;
	int segment_len = 0;
	int segment_flag = 0;
	uint8_t stamp_len = 0;
	int crc = 0;
	int wrp = 0;
	int wrc = 0;
	uint8_t data_buf[1200]; // receiver buffer,  should be 1024..
	char token_type[4];

	// copy data from proxmark into buffer
	GetFromBigBuf(data_buf, sizeof(data_buf), 0);
	if ( !WaitForResponseTimeout(CMD_ACK, NULL, 2000)){
		PrintAndLog("Command execute timeout");
		return 1;
	}
	
	// Output CDF System area (9 bytes) plus remaining header area (12 bytes)
	crc = data_buf[4];
	uint32_t calc_crc =  CRC8Legic(data_buf, 4);	
	
	PrintAndLog("\nCDF: System Area");

	PrintAndLog("MCD: %02x, MSN: %02x %02x %02x, MCC: %02x %s",
		data_buf[0],
		data_buf[1],
		data_buf[2],
		data_buf[3],
		data_buf[4],
		(calc_crc == crc) ? "OK":"Fail" 
	);
 
	switch (data_buf[5] & 0x7f) {
		case 0x00 ... 0x2f:
			strncpy(token_type, "IAM",sizeof(token_type));
			break;
		case 0x30 ... 0x6f:
			strncpy(token_type, "SAM",sizeof(token_type));
			break;
		case 0x70 ... 0x7f:
			strncpy(token_type, "GAM",sizeof(token_type));
			break;
		default:
			strncpy(token_type, "???",sizeof(token_type));
			break;
	}

	stamp_len = 0xfc - data_buf[6];

	PrintAndLog("DCF: %02x %02x, Token Type=%s (OLE=%01u), Stamp len=%02u",
		data_buf[5],
		data_buf[6],
		token_type,
		(data_buf[5]&0x80)>>7,
		stamp_len
	);

	PrintAndLog("WRP=%02u, WRC=%01u, RD=%01u, raw=%02x, SSC=%02x",
		data_buf[7]&0x0f,
		(data_buf[7]&0x70)>>4,
		(data_buf[7]&0x80)>>7,
		data_buf[7],
		data_buf[8]
	);

	PrintAndLog("Remaining Header Area");
	PrintAndLog("%s", sprint_hex(data_buf+9, 13));
	
	uint8_t segCrcBytes[8] = {0x00};
	uint32_t segCalcCRC = 0;
	uint32_t segCRC = 0;

	PrintAndLog("\nADF: User Area");
	printf("-------------------------------------\n");
	i = 22;  
	// 64 potential segements
	// how to detect there is no segments?!?
	for ( segmentNum=0; segmentNum<64; segmentNum++ ) {
		segment_len = ((data_buf[i+1]^crc)&0x0f) * 256 + (data_buf[i]^crc);
		segment_flag = ((data_buf[i+1]^crc)&0xf0)>>4;

		wrp = (data_buf[i+2]^crc);
		wrc = ((data_buf[i+3]^crc)&0x70)>>4;

		bool hasWRC = (wrc > 0);
		bool hasWRP = (wrp > wrc);
		int wrp_len = (wrp - wrc);
		int remain_seg_payload_len = (segment_len - wrp - 5);
		
		// validate segment-crc
		segCrcBytes[0]=data_buf[0];			//uid0
		segCrcBytes[1]=data_buf[1];			//uid1
		segCrcBytes[2]=data_buf[2];			//uid2
		segCrcBytes[3]=data_buf[3];			//uid3
		segCrcBytes[4]=(data_buf[i]^crc); 	//hdr0
		segCrcBytes[5]=(data_buf[i+1]^crc); //hdr1
		segCrcBytes[6]=(data_buf[i+2]^crc); //hdr2
		segCrcBytes[7]=(data_buf[i+3]^crc); //hdr3

		segCalcCRC = CRC8Legic(segCrcBytes, 8);
		segCRC = data_buf[i+4]^crc;

		PrintAndLog("Segment %02u \nraw header=0x%02X 0x%02X 0x%02X 0x%02X \nSegment len: %u,  Flag: 0x%X (valid:%01u, last:%01u), WRP: %02u, WRC: %02u, RD: %01u, CRC: 0x%02X (%s)",
			segmentNum,
			data_buf[i]^crc,
			data_buf[i+1]^crc,
			data_buf[i+2]^crc,
			data_buf[i+3]^crc,
			segment_len, 
			segment_flag,
			(segment_flag & 0x4) >> 2,
			(segment_flag & 0x8) >> 3,
			wrp,
			wrc,
			((data_buf[i+3]^crc) & 0x80) >> 7,
			segCRC,
			( segCRC == segCalcCRC ) ? "OK" : "fail"
		);

		i += 5;
    
		if ( hasWRC ) {
			PrintAndLog("WRC protected area:   (I %d | K %d| WRC %d)", i, k, wrc);

			// de-xor?  if not zero, assume it needs xoring.
			if ( data_buf[i] > 0) {
				for ( k=i; k < wrc; ++k)
					data_buf[k] ^= crc;
			}
			print_hex_break( data_buf+i, wrc, 16);
			
			i += wrc;
		}
    
		if ( hasWRP ) {
			PrintAndLog("Remaining write protected area:  (I %d | K %d | WRC %d | WRP %d  WRP_LEN %d)",i, k, wrc, wrp, wrp_len);

			// de-xor?  if not zero, assume it needs xoring.
			if ( data_buf[i] > 0) {
				for (k=i; k < wrp_len; ++k)
					data_buf[k] ^= crc;
			}
			
			print_hex_break( data_buf+i, wrp_len, 16);
			
			i += wrp_len;
			
			// does this one work?
			if( wrp_len == 8 )
				PrintAndLog("Card ID: %2X%02X%02X", data_buf[i-4]^crc, data_buf[i-3]^crc, data_buf[i-2]^crc);			
		}
    
		PrintAndLog("Remaining segment payload:  (I %d | K %d | Remain LEN %d)", i, k, remain_seg_payload_len);
		
		if ( data_buf[i] > 0 ) {
			for ( k=i; k < remain_seg_payload_len; ++k)
				data_buf[k] ^= crc;
		}
		
		print_hex_break( data_buf+i, remain_seg_payload_len, 16);
    
		i += remain_seg_payload_len;
		
		printf("\n-------------------------------------\n");

		// end with last segment
		if (segment_flag & 0x8) return 0;

	} // end for loop
	return 0;
}

int CmdLegicRFRead(const char *Cmd) {
	int byte_count=0, offset=0;
	sscanf(Cmd, "%i %i", &offset, &byte_count);
	if(byte_count == 0) byte_count = -1;
	if(byte_count + offset > 1024) byte_count = 1024 - offset;

	UsbCommand c= {CMD_READER_LEGIC_RF, {offset, byte_count, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdLegicLoad(const char *Cmd) {
	
	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'H' || cmdp == 'h' || cmdp == 0x00) return usage_legic_load();

	char filename[FILE_PATH_SIZE] = {0x00};
	int len = strlen(Cmd);
	
	if (len > FILE_PATH_SIZE) {
		PrintAndLog("Filepath too long (was %s bytes), max allowed is %s ", len, FILE_PATH_SIZE);
		return 0;
	}
	memcpy(filename, Cmd, len);

    FILE *f = fopen(filename, "r");
    if(!f) {
        PrintAndLog("couldn't open '%s'", Cmd);
        return -1;
    }
	
    char line[80]; 
	int offset = 0; 
	uint8_t data[USB_CMD_DATA_SIZE] = {0x00};
	int index = 0;
	int totalbytes = 0;
    while ( fgets(line, sizeof(line), f) ) {
        int res = sscanf(line, "%x %x %x %x %x %x %x %x", 
            (unsigned int *)&data[index],
			(unsigned int *)&data[index + 1],
			(unsigned int *)&data[index + 2],
			(unsigned int *)&data[index + 3],
            (unsigned int *)&data[index + 4],
			(unsigned int *)&data[index + 5],
			(unsigned int *)&data[index + 6],
			(unsigned int *)&data[index + 7]);
			
        if(res != 8) {
          PrintAndLog("Error: could not read samples");
          fclose(f);
          return -1;
        }
		index += res;
			
		if ( index == USB_CMD_DATA_SIZE ){
//			PrintAndLog("sent %d | %d | %d", index, offset, totalbytes);
			UsbCommand c = { CMD_DOWNLOADED_SIM_SAMPLES_125K, {offset, 0, 0}};
			memcpy(c.d.asBytes, data, sizeof(data));
			clearCommandBuffer();
			SendCommand(&c);
			if ( !WaitForResponseTimeout(CMD_ACK, NULL, 1500)){
				PrintAndLog("Command execute timeout");
				fclose(f);
				return 1;
			}
			offset += index;
			totalbytes += index;
			index = 0;
		}
    }
    fclose(f);
	
	// left over bytes?
	if ( index != 0 ) {
		UsbCommand c = { CMD_DOWNLOADED_SIM_SAMPLES_125K, {offset, 0, 0}};
		memcpy(c.d.asBytes, data, 8);
		clearCommandBuffer();
		SendCommand(&c);
		if ( !WaitForResponseTimeout(CMD_ACK, NULL, 1500)){
				PrintAndLog("Command execute timeout");
				return 1;
		}
		totalbytes += index;		
	}
	
    PrintAndLog("loaded %u samples", totalbytes);
    return 0;
}

int CmdLegicSave(const char *Cmd) {
	int requested = 1024;
	int offset = 0;
	int delivered = 0;
	char filename[FILE_PATH_SIZE];
	uint8_t got[1024] = {0x00};

	sscanf(Cmd, " %s %i %i", filename, &requested, &offset);

	/* If no length given save entire legic read buffer */
	/* round up to nearest 8 bytes so the saved data can be used with legicload */
	if (requested == 0)
		requested = 1024;

	if (requested % 8 != 0) {
		int remainder = requested % 8;
		requested = requested + 8 - remainder;
	}

	if (offset + requested > sizeof(got)) {
		PrintAndLog("Tried to read past end of buffer, <bytes> + <offset> > 1024");
		return 0;
	}

	FILE *f = fopen(filename, "w");
	if(!f) {
		PrintAndLog("couldn't open '%s'", Cmd+1);
		return -1;
	}

	GetFromBigBuf(got, requested, offset);
	if ( !WaitForResponseTimeout(CMD_ACK, NULL, 2000)){
		PrintAndLog("Command execute timeout");
		return 1;
	}

	for (int j = 0; j < requested; j += 8) {
		fprintf(f, "%02x %02x %02x %02x %02x %02x %02x %02x\n",
			got[j+0], got[j+1], got[j+2], got[j+3],
			got[j+4], got[j+5],	got[j+6], got[j+7]
		);
		delivered += 8;
		if (delivered >= requested) break;
	}

	fclose(f);
	PrintAndLog("saved %u samples", delivered);
	return 0;
}

//TODO: write a help text (iceman)
int CmdLegicRfSim(const char *Cmd) {
	UsbCommand c = {CMD_SIMULATE_TAG_LEGIC_RF, {6,3,0}};
	sscanf(Cmd, " %"lli" %"lli" %"lli, &c.arg[0], &c.arg[1], &c.arg[2]);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

//TODO: write a help text (iceman)
int CmdLegicRfWrite(const char *Cmd) {
    UsbCommand c = {CMD_WRITER_LEGIC_RF};
    int res = sscanf(Cmd, " 0x%"llx" 0x%"llx, &c.arg[0], &c.arg[1]);
	if(res != 2) {
		PrintAndLog("Please specify the offset and length as two hex strings");
        return -1;
    }
	clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

int CmdLegicRfFill(const char *Cmd) {
    UsbCommand cmd = {CMD_WRITER_LEGIC_RF};
    int res = sscanf(Cmd, " 0x%"llx" 0x%"llx" 0x%"llx, &cmd.arg[0], &cmd.arg[1], &cmd.arg[2]);
    if(res != 3) {
        PrintAndLog("Please specify the offset, length and value as two hex strings");
        return -1;
    }

    int i;
    UsbCommand c = {CMD_DOWNLOADED_SIM_SAMPLES_125K, {0, 0, 0}};
    for(i = 0; i < 48; i++) {
		c.d.asBytes[i] = cmd.arg[2];
    }
	
	for(i = 0; i < 22; i++) {
		c.arg[0] = i*48;
		SendCommand(&c);
		WaitForResponse(CMD_ACK,NULL);
	}
	clearCommandBuffer();
    SendCommand(&cmd);
    return 0;
 }

int CmdLegicCalcCrc8(const char *Cmd){

	int len =  strlen(Cmd);	
	if (len & 1 ) return usage_legic_calccrc8(); 
	
	uint8_t *data = malloc(len);
	if ( data == NULL ) return 1;
		
	param_gethex(Cmd, 0, data, len );
	
	uint32_t checksum =  CRC8Legic(data, len/2);	
	PrintAndLog("Bytes: %s || CRC8: %X", sprint_hex(data, len/2), checksum );
	free(data);
	return 0;
} 
 
static command_t CommandTable[] =  {
	{"help",	CmdHelp,        1, "This help"},
	{"decode",	CmdLegicDecode, 0, "Display deobfuscated and decoded LEGIC RF tag data (use after hf legic reader)"},
	{"read",	CmdLegicRFRead, 0, "[offset][length] -- read bytes from a LEGIC card"},
	{"save",	CmdLegicSave,   0, "<filename> [<length>] -- Store samples"},
	{"load",	CmdLegicLoad,   0, "<filename> -- Restore samples"},
	{"sim",		CmdLegicRfSim,  0, "[phase drift [frame drift [req/resp drift]]] Start tag simulator (use after load or read)"},
	{"write",	CmdLegicRfWrite,0, "<offset> <length> -- Write sample buffer (user after load or read)"},
	{"fill",	CmdLegicRfFill, 0, "<offset> <length> <value> -- Fill/Write tag with constant value"},
	{"crc8",	CmdLegicCalcCrc8, 1, "Calculate Legic CRC8 over given hexbytes"},
	{NULL, NULL, 0, NULL}
};

int CmdHFLegic(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}