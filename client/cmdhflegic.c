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
	int i, k, n;
	int segment_len = 0;
	int segment_flag = 0;
	int stamp_len = 0;
	int crc = 0;
	int wrp = 0;
	int wrc = 0;
	uint8_t data_buf[1200]; // receiver buffer
	//char out_string[3076]; // just use big buffer - bad practice
	char token_type[4];

	// copy data from proxmark into buffer
	GetFromBigBuf(data_buf,sizeof(data_buf),0);
	WaitForResponse(CMD_ACK,NULL);

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
 
	switch (data_buf[5]&0x7f) {
		case 0x00 ... 0x2f:
			strncpy(token_type, "IAM",sizeof(token_type));
			break;
		case 0x30 ... 0x6f:
			strcpy(token_type, "SAM");
			break;
		case 0x70 ... 0x7f:
			strcpy(token_type, "GAM");
			break;
		default:
			strcpy(token_type, "???");
			break;
	}

	stamp_len = 0xfc - data_buf[6];

	PrintAndLog("DCF: %02x %02x, Token_Type=%s (OLE=%01u), Stamp_len=%02u",
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
	PrintAndLog("\nADF: User Area");
  
	i = 22;  
	uint8_t segCrcBytes[8] = {0x00};
	uint32_t segCalcCRC = 0;
	uint32_t segCRC = 0;
	
	for ( n=0; n<64; n++ ) {
		segment_len = ((data_buf[i+1]^crc)&0x0f) * 256 + (data_buf[i]^crc);
		segment_flag = ((data_buf[i+1]^crc)&0xf0)>>4;

		wrp = (data_buf[i+2]^crc);
		wrc = ((data_buf[i+3]^crc)&0x70)>>4;

		/* validate segment-crc */
		segCRC = data_buf[i+4]^crc;
		
		segCrcBytes[0]=data_buf[0]; //uid0
		segCrcBytes[1]=data_buf[1]; //uid1
		segCrcBytes[2]=data_buf[2]; //uid2
		segCrcBytes[3]=data_buf[3]; //uid3
		segCrcBytes[4]=(data_buf[i]^crc); //hdr0
		segCrcBytes[5]=(data_buf[i+1]^crc); //hdr1
		segCrcBytes[6]=(data_buf[i+2]^crc); //hdr2
		segCrcBytes[7]=(data_buf[i+3]^crc); //hdr3
		segCalcCRC = CRC8Legic(segCrcBytes, 8);

		PrintAndLog("Segment %02u: raw header=%02x %02x %02x %02x, flag=%01x (valid=%01u, last=%01u), len=%04u, WRP=%02u, WRC=%02u, RD=%01u, CRC=%02x  (%s)",
			n,
			data_buf[i]^crc,
			data_buf[i+1]^crc,
			data_buf[i+2]^crc,
			data_buf[i+3]^crc,
			segment_flag,
			(segment_flag&0x4)>>2,
			(segment_flag&0x8)>>3,
			segment_len,
			wrp,
			wrc,
			((data_buf[i+3]^crc)&0x80)>>7,
			segCRC,
			( segCRC == segCalcCRC ) ? "OK" : "fail"
		);

		i += 5;
    
		if ( wrc>0 ) {
			PrintAndLog("WRC protected area:");
			
			for ( k=i; k < wrc; k++)
				data_buf[k] ^= crc;
			
			for ( k=i; k < wrc; k += 8)
				PrintAndLog("%s", sprint_hex( data_buf+k, 8)  );
			
			i += wrc;
		}
    
		if ( wrp>wrc ) {
			PrintAndLog("Remaining write protected area:");

			if ( data_buf[k] > 0) {
				for (k=i; k < (wrp-wrc); k++)
					data_buf[k] ^= crc;
			}
			
			for (k=i; k < (wrp-wrc); k++)
				PrintAndLog("%s", sprint_hex( data_buf+k, 16)  );

			i += (wrp-wrc);
			
			if( (wrp-wrc) == 8 )
				PrintAndLog("Card ID: %2X%02X%02X", data_buf[i-4]^crc, data_buf[i-3]^crc, data_buf[i-2]^crc);			
		}
    
		PrintAndLog("Remaining segment payload:");
		
		if ( data_buf[k] > 0 ) {
			for ( k=i; k < (segment_len - wrp - 5); k++)
				data_buf[k] ^= crc;
		}
		
		for ( k=i; k < (segment_len - wrp - 5); k++)
			PrintAndLog("%s", sprint_hex( data_buf+k, 16)  );
    
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
	uint8_t data[8] = {0x00};
	
    while ( fgets(line, sizeof(line), f) ) {
        int res = sscanf(line, "%x %x %x %x %x %x %x %x", 
            (unsigned int *)&data[0], (unsigned int *)&data[1], (unsigned int *)&data[2], (unsigned int *)&data[3],
            (unsigned int *)&data[4], (unsigned int *)&data[5], (unsigned int *)&data[6], (unsigned int *)&data[7]);
			
        if(res != 8) {
          PrintAndLog("Error: could not read samples");
          fclose(f);
          return -1;
        }
		
        UsbCommand c = { CMD_DOWNLOADED_SIM_SAMPLES_125K, {offset, 0, 0}};
		memcpy(c.d.asBytes, data, 8);
		clearCommandBuffer();
        SendCommand(&c);
        WaitForResponse(CMD_ACK, NULL);
        offset += 8;
    }
    fclose(f);
    PrintAndLog("loaded %u samples", offset);
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

	GetFromBigBuf(got,requested,offset);
	WaitForResponse(CMD_ACK,NULL);

	for (int j = 0; j < requested; j += 8) {
		fprintf(f, "%02x %02x %02x %02x %02x %02x %02x %02x\n",
			got[j+0],
			got[j+1],
			got[j+2],
			got[j+3],
			got[j+4],
			got[j+5],
			got[j+6],
			got[j+7]
		);
		delivered += 8;
		if (delivered >= requested) break;
	}

	fclose(f);
	PrintAndLog("saved %u samples", delivered);
	return 0;
}

int CmdLegicRfSim(const char *Cmd) {
	UsbCommand c = {CMD_SIMULATE_TAG_LEGIC_RF, {6,3,0}};
	sscanf(Cmd, " %"lli" %"lli" %"lli, &c.arg[0], &c.arg[1], &c.arg[2]);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

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