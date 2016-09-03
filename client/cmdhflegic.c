//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Legic commands
//-----------------------------------------------------------------------------
#include "cmdhflegic.h"

static int CmdHelp(const char *Cmd);

#define SESSION_IV 0x55
#define MAX_LENGTH 1024	

int usage_legic_calccrc8(void){
	PrintAndLog("Calculates the legic crc8/crc16 on the input hexbytes.");
	PrintAndLog("There must be an even number of hexsymbols as input.");
	PrintAndLog("Usage:  hf legic crc8 [h] b <hexbytes> u <uidcrc> c <crc type>");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");
	PrintAndLog("      b <hexbytes>  : hex bytes");
	PrintAndLog("      u <uidcrc>    : MCC hexbyte");
	PrintAndLog("      c <crc type>  : 8|16 bit crc size");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic crc8 b deadbeef1122");
	PrintAndLog("      hf legic crc8 b deadbeef1122 u 9A c 16");
	return 0;
}
int usage_legic_load(void){
	PrintAndLog("It loads datasamples from the file `filename` to device memory");
	PrintAndLog("Usage:  hf legic load [h] <file name>");
	PrintAndLog("Options:");
	PrintAndLog("  h             : this help");
	PrintAndLog("  <filename>    : Name of file to load");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic load filename");
	return 0;
}
int usage_legic_read(void){	
	PrintAndLog("Read data from a legic tag.");
	PrintAndLog("Usage:  hf legic read [h] <offset> <length> <IV>");
	PrintAndLog("Options:");
	PrintAndLog("  h             : this help");
	PrintAndLog("  <offset>      : offset in data array to start download from");
	PrintAndLog("  <length>      : number of bytes to download");
	PrintAndLog("  <IV>          : (optional) Initialization vector to use (ODD and 7bits)");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic read");
	PrintAndLog("      hf legic read 10 4");
	return 0;
}
int usage_legic_sim(void){
	PrintAndLog("Missing help text.");
	return 0;
}
int usage_legic_write(void){
	PrintAndLog(" Write sample buffer to a legic tag. (use after load or read)");
	PrintAndLog("Usage:  hf legic write [h] <offset> <length> <IV>");
	PrintAndLog("Options:");
	PrintAndLog("  h             : this help");
	PrintAndLog("  <offset>      : offset in data array to start writing from");
	PrintAndLog("  <length>      : number of bytes to write");
	PrintAndLog("  <IV>          : (optional) Initialization vector to use (ODD and 7bits)");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic write");
	PrintAndLog("      hf legic write 10 4");
	return 0;
}
int usage_legic_rawwrite(void){
	PrintAndLog("Write raw data direct to a specific address on legic tag.");
	PrintAndLog("Usage:  hf legic writeraw [h] <address> <value> <IV>");
	PrintAndLog("Options:");
	PrintAndLog("  h             : this help");
	PrintAndLog("  <address>     : address to write to");
	PrintAndLog("  <value>       : value to write");
	PrintAndLog("  <IV>          : (optional) Initialization vector to use (ODD and 7bits)");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic writeraw");
	PrintAndLog("      hf legic writeraw 10 4");
	return 0;
}
int usage_legic_fill(void){
	PrintAndLog("Missing help text.");
	return 0;
}

/*
 *  Output BigBuf and deobfuscate LEGIC RF tag data.
 *  This is based on information given in the talk held
 *  by Henryk Ploetz and Karsten Nohl at 26c3
 */
int CmdLegicDecode(const char *Cmd) {

	int i = 0, k = 0, segmentNum = 0, segment_len = 0, segment_flag = 0;
	int crc = 0, wrp = 0, wrc = 0;
	uint8_t stamp_len = 0;
	uint8_t data_buf[1024]; // receiver buffer
	char token_type[5] = {0,0,0,0,0};
	int dcf = 0;
	int bIsSegmented = 0;

	// copy data from proxmark into buffer
	GetFromBigBuf(data_buf,sizeof(data_buf),0);
	if ( !WaitForResponseTimeout(CMD_ACK, NULL, 2000)){
		PrintAndLog("Command execute timeout");
		return 1;
	}
	
	// Output CDF System area (9 bytes) plus remaining header area (12 bytes)
	crc = data_buf[4];
	uint32_t calc_crc =  CRC8Legic(data_buf, 4);	
	
	PrintAndLog("\nCDF: System Area");
	PrintAndLog("------------------------------------------------------");
	PrintAndLog("MCD: %02x, MSN: %02x %02x %02x, MCC: %02x %s",
		data_buf[0],
		data_buf[1],
		data_buf[2],
		data_buf[3],
		data_buf[4],
		(calc_crc == crc) ? "OK":"Fail" 
	);
 

	token_type[0] = 0;
	dcf = ((int)data_buf[6] << 8) | (int)data_buf[5];

	// New unwritten media?
	if(dcf == 0xFFFF) {

		PrintAndLog("DCF: %d (%02x %02x), Token Type=NM (New Media)",
			dcf,
			data_buf[5],
			data_buf[6]
		);
	
	} else if(dcf > 60000) {		// Master token?

		int fl = 0;

		if(data_buf[6] == 0xec) {
			strncpy(token_type, "XAM", sizeof(token_type));
			fl = 1;
			stamp_len = 0x0c - (data_buf[5] >> 4);
		} else {
			switch (data_buf[5] & 0x7f) {
			case 0x00 ... 0x2f:
				strncpy(token_type, "IAM", sizeof(token_type));
				fl = (0x2f - (data_buf[5] & 0x7f)) + 1;
				break;
			case 0x30 ... 0x6f:
				strncpy(token_type, "SAM", sizeof(token_type));
				fl = (0x6f - (data_buf[5] & 0x7f)) + 1;
				break;
			case 0x70 ... 0x7f:
				strncpy(token_type, "GAM", sizeof(token_type));
				fl = (0x7f - (data_buf[5] & 0x7f)) + 1;
				break;
			}

			stamp_len = 0xfc - data_buf[6];
		}

		PrintAndLog("DCF: %d (%02x %02x), Token Type=%s (OLE=%01u), OL=%02u, FL=%02u",
			dcf,
			data_buf[5],
			data_buf[6],
			token_type,
			(data_buf[5] & 0x80 )>> 7,
			stamp_len,
			fl
		);

	} else {	// Is IM(-S) type of card...

		if(data_buf[7] == 0x9F && data_buf[8] == 0xFF) {
			bIsSegmented = 1;
			strncpy(token_type, "IM-S", sizeof(token_type));
		} else {
			strncpy(token_type, "IM", sizeof(token_type));
		}

		PrintAndLog("DCF: %d (%02x %02x), Token Type=%s (OLE=%01u)",
			dcf,
			data_buf[5],
			data_buf[6],
			token_type,
			(data_buf[5]&0x80) >> 7
		);
	}

	// Makes no sence to show this on blank media...
	if(dcf != 0xFFFF) {

		if(bIsSegmented) {
			PrintAndLog("WRP=%02u, WRC=%01u, RD=%01u, SSC=%02x",
				data_buf[7] & 0x0f,
				(data_buf[7] & 0x70) >> 4,
				(data_buf[7] & 0x80) >> 7,
				data_buf[8]
			);
		}

		// Header area is only available on IM-S cards, on master tokens this data is the master token data itself
		if(bIsSegmented || dcf > 60000) {
			if(dcf > 60000) {
				PrintAndLog("Master token data");
				PrintAndLog("%s", sprint_hex(data_buf+8, 14));
			} else {
				PrintAndLog("Remaining Header Area");
				PrintAndLog("%s", sprint_hex(data_buf+9, 13));
			}
		}
	}
	
	uint8_t segCrcBytes[8] = {0,0,0,0,0,0,0,0};
	uint32_t segCalcCRC = 0;
	uint32_t segCRC = 0;

	// Data card?
	if(dcf <= 60000) {
	
		PrintAndLog("\nADF: User Area");
		PrintAndLog("------------------------------------------------------");

		if(bIsSegmented) {

			// Data start point on segmented cards
			i = 22;  

			// decode segments
			for (segmentNum=1; segmentNum < 128; segmentNum++ )
			{
				segment_len = ((data_buf[i+1] ^ crc) & 0x0f) * 256 + (data_buf[i] ^ crc);
				segment_flag = ((data_buf[i+1] ^ crc) & 0xf0) >> 4;
				wrp = (data_buf[i+2] ^ crc);
				wrc = ((data_buf[i+3] ^ crc) & 0x70) >> 4;

				bool hasWRC = (wrc > 0);
				bool hasWRP = (wrp > wrc);
				int wrp_len = (wrp - wrc);
				int remain_seg_payload_len = (segment_len - wrp - 5);
		
				// validate segment-crc
				segCrcBytes[0]=data_buf[0];			//uid0
				segCrcBytes[1]=data_buf[1];			//uid1
				segCrcBytes[2]=data_buf[2];			//uid2
				segCrcBytes[3]=data_buf[3];			//uid3
				segCrcBytes[4]=(data_buf[i] ^ crc);   //hdr0
				segCrcBytes[5]=(data_buf[i+1] ^ crc); //hdr1
				segCrcBytes[6]=(data_buf[i+2] ^ crc); //hdr2
				segCrcBytes[7]=(data_buf[i+3] ^ crc); //hdr3

				segCalcCRC = CRC8Legic(segCrcBytes, 8);
				segCRC = data_buf[i+4] ^ crc;

				PrintAndLog("Segment %02u \nraw header | 0x%02X 0x%02X 0x%02X 0x%02X \nSegment len: %u,  Flag: 0x%X (valid:%01u, last:%01u), WRP: %02u, WRC: %02u, RD: %01u, CRC: 0x%02X (%s)",
					segmentNum,
					data_buf[i] ^ crc,
					data_buf[i+1] ^ crc,
					data_buf[i+2] ^ crc,
					data_buf[i+3] ^ crc,
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
					PrintAndLog("\nrow  | data");
					PrintAndLog("-----+------------------------------------------------");

					for ( k=i; k < (i + wrc); ++k)
						data_buf[k] ^= crc;

					print_hex_break( data_buf+i, wrc, 16);
			
					i += wrc;
				}
    
				if ( hasWRP ) {
					PrintAndLog("Remaining write protected area:  (I %d | K %d | WRC %d | WRP %d  WRP_LEN %d)",i, k, wrc, wrp, wrp_len);
					PrintAndLog("\nrow  | data");
					PrintAndLog("-----+------------------------------------------------");

					for (k=i; k < (i+wrp_len); ++k)
						data_buf[k] ^= crc;
			
					print_hex_break( data_buf+i, wrp_len, 16);
			
					i += wrp_len;
			
					// does this one work? (Answer: Only if KGH/BGH is used with BCD encoded card number! So maybe this will show just garbage...)
					if( wrp_len == 8 )
						PrintAndLog("Card ID: %2X%02X%02X", data_buf[i-4]^crc, data_buf[i-3]^crc, data_buf[i-2]^crc);			
				}
    
				PrintAndLog("Remaining segment payload:  (I %d | K %d | Remain LEN %d)", i, k, remain_seg_payload_len);
				PrintAndLog("\nrow  | data");
				PrintAndLog("-----+------------------------------------------------");

				for ( k=i; k < (i+remain_seg_payload_len); ++k)
					data_buf[k] ^= crc;
		
				print_hex_break( data_buf+i, remain_seg_payload_len, 16);
    
				i += remain_seg_payload_len;
		
				PrintAndLog("-----+------------------------------------------------\n");

				// end with last segment
				if (segment_flag & 0x8) return 0;

			} // end for loop
		
		} else {

			// Data start point on unsegmented cards
			i = 8;

			wrp = data_buf[7] & 0x0F;
			wrc = (data_buf[7] & 0x70) >> 4;

			bool hasWRC = (wrc > 0);
			bool hasWRP = (wrp > wrc);
			int wrp_len = (wrp - wrc);
			int remain_seg_payload_len = (1024 - 22 - wrp);	// Any chance to get physical card size here!?

			PrintAndLog("Unsegmented card - WRP: %02u, WRC: %02u, RD: %01u",
				wrp,
				wrc,
				(data_buf[7] & 0x80) >> 7
			);

			if ( hasWRC ) {
				PrintAndLog("WRC protected area:   (I %d | WRC %d)", i, wrc);
				PrintAndLog("\nrow  | data");
				PrintAndLog("-----+------------------------------------------------");
				print_hex_break( data_buf+i, wrc, 16);
				i += wrc;
			}
    
			if ( hasWRP ) {
				PrintAndLog("Remaining write protected area:  (I %d | WRC %d | WRP %d | WRP_LEN %d)", i, wrc, wrp, wrp_len);
				PrintAndLog("\nrow  | data");
				PrintAndLog("-----+------------------------------------------------");
				print_hex_break( data_buf + i, wrp_len, 16);
				i += wrp_len;
			
				// does this one work? (Answer: Only if KGH/BGH is used with BCD encoded card number! So maybe this will show just garbage...)
				if( wrp_len == 8 )
					PrintAndLog("Card ID: %2X%02X%02X", data_buf[i-4], data_buf[i-3], data_buf[i-2]);
			}
    
			PrintAndLog("Remaining segment payload:  (I %d | Remain LEN %d)", i, remain_seg_payload_len);
			PrintAndLog("\nrow  | data");
			PrintAndLog("-----+------------------------------------------------");
			print_hex_break( data_buf + i, remain_seg_payload_len, 16);
			i += remain_seg_payload_len;
		
			PrintAndLog("-----+------------------------------------------------\n");
		}
	}
	return 0;
}

int CmdLegicRFRead(const char *Cmd) {

	// params:
	// offset in data
	// number of bytes.
	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'H' || cmdp == 'h' ) return usage_legic_read();
	
	uint32_t offset = 0, len = 0, IV = 1;
	sscanf(Cmd, "%x %x %x", &offset, &len, &IV);

	// OUT-OF-BOUNDS check
	if(len + offset > MAX_LENGTH) len = MAX_LENGTH - offset;
	
	if ( (IV & 0x7F) != IV ){
		IV &= 0x7F;
		PrintAndLog("Truncating IV to 7bits");
	}
	if ( (IV & 1) == 0 ){
		IV |= 0x01;  // IV must be odd
		PrintAndLog("LSB of IV must be SET");	
	}
	PrintAndLog("Current IV: 0x%02x", IV);
	
	UsbCommand c= {CMD_READER_LEGIC_RF, {offset, len, IV}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdLegicLoad(const char *Cmd) {

// iceman: potential bug, where all filepaths or filename which starts with H or h will print the helptext :)	
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
	char filename[FILE_PATH_SIZE] = {0x00};
	uint8_t got[1024] = {0x00};

	memset(filename, 0, FILE_PATH_SIZE);
	
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

	GetFromBigBuf(got, requested, offset);
	if ( !WaitForResponseTimeout(CMD_ACK, NULL, 2000)){
		PrintAndLog("Command execute timeout");	
		return 1;
	}

	FILE *f = fopen(filename, "w");
	if(!f) {
		PrintAndLog("couldn't open '%s'", Cmd+1);
		return -1;
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

int CmdLegicRfWrite(const char *Cmd) {

	// params:
	// offset - in tag memory
	// length - num of bytes to be written
	// IV - initialisation vector
	
	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'H' || cmdp == 'h' ) return usage_legic_write();
	
	uint32_t offset = 0, len = 0, IV = 0;
	
    UsbCommand c = {CMD_WRITER_LEGIC_RF, {0,0,0}};
    int res = sscanf(Cmd, "%x %x %x", &offset, &len, &IV);
	if(res < 2) {
		PrintAndLog("Please specify the offset and length as two hex strings and, optionally, the IV also as an hex string");
        return -1;
    }

	// OUT-OF-BOUNDS check
	if(len + offset > MAX_LENGTH) len = MAX_LENGTH - offset;

	if ( (IV & 0x7F) != IV ){
		IV &= 0x7F;
		PrintAndLog("Truncating IV to 7bits");
	}
	if ( (IV & 1) == 0 ){
		IV |= 0x01;  // IV must be odd
		PrintAndLog("LSB of IV must be SET");	
	}
	
	PrintAndLog("Current IV: 0x%02x", IV);
	
	c.arg[0] = offset;
	c.arg[1] = len;
    c.arg[2] = IV;
	
	clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

int CmdLegicRfRawWrite(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'H' || cmdp == 'h' ) return usage_legic_rawwrite();
	
	uint32_t address = 0, data = 0, IV = 0;	
	char answer;

    UsbCommand c = { CMD_RAW_WRITER_LEGIC_RF, {0,0,0} };
    int res = sscanf(Cmd, "%x %x %x", &address, &data, &IV);
	if(res < 2)
		return usage_legic_rawwrite();

	// OUT-OF-BOUNDS check
	if(address > MAX_LENGTH)
		return usage_legic_rawwrite();
	
	if ( (IV & 0x7F) != IV ){
		IV &= 0x7F;
		PrintAndLog("Truncating IV to 7bits");
	}
	if ( (IV & 1) == 0 ){
		IV |= 0x01;  // IV must be odd
		PrintAndLog("LSB of IV must be SET");	
	}
	PrintAndLog("Current IV: 0x%02x", IV);

	c.arg[0] = address;
	c.arg[1] = data;
    c.arg[2] = IV;
	
	if (c.arg[0] == 0x05 || c.arg[0] == 0x06) {
		PrintAndLog("############# DANGER !! #############");
		PrintAndLog("# changing the DCF is irreversible  #");
		PrintAndLog("#####################################");
		PrintAndLog("do youe really want to continue? y(es) n(o)");		
		if (scanf(" %c", &answer) > 0 && (answer == 'y' || answer == 'Y')) {
			SendCommand(&c);
			return 0;
		}
		return -1;
	}
	
	clearCommandBuffer();
    SendCommand(&c);
	return 0;
}

//TODO: write a help text (iceman)
int CmdLegicRfFill(const char *Cmd) {
    UsbCommand cmd = {CMD_WRITER_LEGIC_RF, {0,0,0} };
    int res = sscanf(Cmd, " 0x%"llx" 0x%"llx" 0x%"llx, &cmd.arg[0], &cmd.arg[1], &cmd.arg[2]);
    if(res != 3) {
        PrintAndLog("Please specify the offset, length and value as two hex strings");
        return -1;
    }

    int i;
    UsbCommand c = {CMD_DOWNLOADED_SIM_SAMPLES_125K, {0, 0, 0}};
	memset(c.d.asBytes, cmd.arg[2], 48);

	for(i = 0; i < 22; i++) {
		c.arg[0] = i*48;
		
		clearCommandBuffer();
		SendCommand(&c);
		WaitForResponse(CMD_ACK, NULL);
	}
	clearCommandBuffer();
    SendCommand(&cmd);
    return 0;
 }

int CmdLegicCalcCrc8(const char *Cmd){

	uint8_t *data = NULL;
	uint8_t cmdp = 0, uidcrc = 0, type=0;
	bool errors = false;
	int len = 0;
	int bg, en;
	
	while(param_getchar(Cmd, cmdp) != 0x00) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'b':
		case 'B':
			// peek at length of the input string so we can
			// figure out how many elements to malloc in "data"
			bg=en=0;
			if (param_getptr(Cmd, &bg, &en, cmdp+1)) {
				errors = true;
				break;
			}
			len = (en - bg + 1);

			// check that user entered even number of characters
			// for hex data string
			if (len & 1) {
				errors = true;
				break;
			}

			// it's possible for user to accidentally enter "b" parameter
			// more than once - we have to clean previous malloc
			if (data) free(data);
			data = malloc(len >> 1);
			if ( data == NULL ) {
				PrintAndLog("Can't allocate memory. exiting");
				errors = true;
				break;
			}
			
			if (param_gethex(Cmd, cmdp+1, data, len)) {
				errors = true;
				break;
			}

			len >>= 1;	
			cmdp += 2;
			break;
		case 'u':
		case 'U':		 
			uidcrc = param_get8ex(Cmd, cmdp+1, 0, 16);
			cmdp += 2;
			break;
		case 'c':
		case 'C':
			type = param_get8ex(Cmd, cmdp+1, 0, 10);
			cmdp += 2;
			break;
		case 'h':
		case 'H':
			errors = true;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
		if (errors) break;
	}
	//Validations
	if (errors){
		if (data) free(data);
		return usage_legic_calccrc8();
	}
	
	switch (type){
		case 16:
			PrintAndLog("LEGIC CRC16: %X", CRC16Legic(data, len, uidcrc));
			break;
		default:
			PrintAndLog("LEGIC CRC8: %X",  CRC8Legic(data, len) );
			break;
	}
	
	if (data) free(data);
	return 0;
} 
 
static command_t CommandTable[] =  {
	{"help",	CmdHelp,        1, "This help"},
	{"decode",	CmdLegicDecode, 0, "Display deobfuscated and decoded LEGIC RF tag data (use after hf legic reader)"},
	{"read",	CmdLegicRFRead, 0, "[offset][length] <iv> -- read bytes from a LEGIC card"},
	{"save",	CmdLegicSave,   0, "<filename> [<length>] -- Store samples"},
	{"load",	CmdLegicLoad,   0, "<filename> -- Restore samples"},
	{"sim",		CmdLegicRfSim,  0, "[phase drift [frame drift [req/resp drift]]] Start tag simulator (use after load or read)"},
	{"write",	CmdLegicRfWrite,0, "<offset> <length> <iv> -- Write sample buffer (user after load or read)"},
	{"writeraw",CmdLegicRfRawWrite,	0, "<address> <value> <iv> -- Write direct to address"},
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