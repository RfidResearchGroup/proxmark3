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
int usage_legic_rdmem(void){	
	PrintAndLog("Read data from a legic tag.");
	PrintAndLog("Usage:  hf legic rdmem [h] <offset> <length> <IV>");
	PrintAndLog("Options:");
	PrintAndLog("  h             : this help");
	PrintAndLog("  <offset>      : offset in data array to start download from (hex)");
	PrintAndLog("  <length>      : number of bytes to read (hex)");
	PrintAndLog("  <IV>          : (optional) Initialization vector to use (hex, odd and 7bits)");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic rdmem 0 21        - reads from byte[0] 21 bytes(system header)");
	PrintAndLog("      hf legic rdmem 0 4 55      - reads from byte[0] 4 bytes with IV 0x55");
	PrintAndLog("      hf legic rdmem 0 100 55    - reads 256bytes with IV 0x55");
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
	PrintAndLog("  <offset>      : offset in data array to start writing from (hex)");
	PrintAndLog("  <length>      : number of bytes to write (hex)");
	PrintAndLog("  <IV>          : (optional) Initialization vector to use (ODD and 7bits)");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic write 10 4      - writes 0x4 to byte[0x10]");
	return 0;
}
int usage_legic_rawwrite(void){
	PrintAndLog("Write raw data direct to a specific offset on legic tag.");
	PrintAndLog("Usage:  hf legic writeraw [h] <offset> <value> <IV>");
	PrintAndLog("Options:");
	PrintAndLog("  h             : this help");
	PrintAndLog("  <offset>      : offset to write to (hex)");
	PrintAndLog("  <value>       : value (hex)");
	PrintAndLog("  <IV>          : (optional) Initialization vector to use (hex, odd and 7bits)");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic writeraw 10 4    - writes 0x4 to byte[0x10]");
	return 0;
}
int usage_legic_fill(void){
	PrintAndLog("Missing help text.");
	return 0;
}
int usage_legic_reader(void){
	PrintAndLog("Read UID and type information from a legic tag.");
	PrintAndLog("Usage:  hf legic reader [h]");
	PrintAndLog("Options:");
	PrintAndLog("  h             : this help");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic reader");
	return 0;
}
int usage_legic_info(void){
	PrintAndLog("Reads information from a legic prime tag.");
	PrintAndLog("Shows systemarea, user areas etc");
	PrintAndLog("Usage:  hf legic info [h]");
	PrintAndLog("Options:");
	PrintAndLog("  h             : this help");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic info");
	return 0;
}
int usage_legic_dump(void){
	PrintAndLog("Reads all pages from LEGIC MIM22, MIM256, MIM1024");
	PrintAndLog("and saves binary dump into the file `filename.bin` or `cardUID.bin`");
	PrintAndLog("It autodetects card type.\n");	
	PrintAndLog("Usage:  hf legic dump [h] o <filename w/o .bin>");
	PrintAndLog("Options:");
	PrintAndLog("  h             : this help");
	PrintAndLog("  n <FN>  : filename w/o .bin to save the dump as");	
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic dump");
	PrintAndLog("      hf legic dump o myfile");
	return 0;
}

/*
 *  Output BigBuf and deobfuscate LEGIC RF tag data.
 *  This is based on information given in the talk held
 *  by Henryk Ploetz and Karsten Nohl at 26c3
 */
int CmdLegicInfo(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'H' || cmdp == 'h' ) return usage_legic_info();

	int i = 0, k = 0, segmentNum = 0, segment_len = 0, segment_flag = 0;
	int crc = 0, wrp = 0, wrc = 0;
	uint8_t stamp_len = 0;
	uint8_t data[1024]; // receiver buffer
	char token_type[5] = {0,0,0,0,0};
	int dcf = 0;
	int bIsSegmented = 0;

	CmdLegicRdmem("0 22 55");
	
	// copy data from device
	GetEMLFromBigBuf(data, sizeof(data), 0);
	if ( !WaitForResponseTimeout(CMD_ACK, NULL, 2000)){
		PrintAndLog("Command execute timeout");
		return 1;
	}
	
	// Output CDF System area (9 bytes) plus remaining header area (12 bytes)
	crc = data[4];
	uint32_t calc_crc =  CRC8Legic(data, 4);	
	
	PrintAndLog("\nCDF: System Area");
	PrintAndLog("------------------------------------------------------");
	PrintAndLog("MCD: %02x, MSN: %02x %02x %02x, MCC: %02x %s",
		data[0],
		data[1],
		data[2],
		data[3],
		data[4],
		(calc_crc == crc) ? "OK":"Fail"
	);
 

	token_type[0] = 0;
	dcf = ((int)data[6] << 8) | (int)data[5];

	// New unwritten media?
	if(dcf == 0xFFFF) {

		PrintAndLog("DCF: %d (%02x %02x), Token Type=NM (New Media)",
			dcf,
			data[5],
			data[6]
		);
	
	} else if(dcf > 60000) {		// Master token?

		int fl = 0;

		if(data[6] == 0xec) {
			strncpy(token_type, "XAM", sizeof(token_type));
			fl = 1;
			stamp_len = 0x0c - (data[5] >> 4);
		} else {
			switch (data[5] & 0x7f) {
			case 0x00 ... 0x2f:
				strncpy(token_type, "IAM", sizeof(token_type));
				fl = (0x2f - (data[5] & 0x7f)) + 1;
				break;
			case 0x30 ... 0x6f:
				strncpy(token_type, "SAM", sizeof(token_type));
				fl = (0x6f - (data[5] & 0x7f)) + 1;
				break;
			case 0x70 ... 0x7f:
				strncpy(token_type, "GAM", sizeof(token_type));
				fl = (0x7f - (data[5] & 0x7f)) + 1;
				break;
			}

			stamp_len = 0xfc - data[6];
		}

		PrintAndLog("DCF: %d (%02x %02x), Token Type=%s (OLE=%01u), OL=%02u, FL=%02u",
			dcf,
			data[5],
			data[6],
			token_type,
			(data[5] & 0x80 )>> 7,
			stamp_len,
			fl
		);

	} else {	// Is IM(-S) type of card...

		if(data[7] == 0x9F && data[8] == 0xFF) {
			bIsSegmented = 1;
			strncpy(token_type, "IM-S", sizeof(token_type));
		} else {
			strncpy(token_type, "IM", sizeof(token_type));
		}

		PrintAndLog("DCF: %d (%02x %02x), Token Type=%s (OLE=%01u)",
			dcf,
			data[5],
			data[6],
			token_type,
			(data[5]&0x80) >> 7
		);
	}

	// Makes no sence to show this on blank media...
	if(dcf != 0xFFFF) {

		if(bIsSegmented) {
			PrintAndLog("WRP=%02u, WRC=%01u, RD=%01u, SSC=%02x",
				data[7] & 0x0f,
				(data[7] & 0x70) >> 4,
				(data[7] & 0x80) >> 7,
				data[8]
			);
		}

		// Header area is only available on IM-S cards, on master tokens this data is the master token data itself
		if(bIsSegmented || dcf > 60000) {
			if(dcf > 60000) {
				PrintAndLog("Master token data");
				PrintAndLog("%s", sprint_hex(data+8, 14));
			} else {
				PrintAndLog("Remaining Header Area");
				PrintAndLog("%s", sprint_hex(data+9, 13));
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
				segment_len = ((data[i+1] ^ crc) & 0x0f) * 256 + (data[i] ^ crc);
				segment_flag = ((data[i+1] ^ crc) & 0xf0) >> 4;
				wrp = (data[i+2] ^ crc);
				wrc = ((data[i+3] ^ crc) & 0x70) >> 4;

				bool hasWRC = (wrc > 0);
				bool hasWRP = (wrp > wrc);
				int wrp_len = (wrp - wrc);
				int remain_seg_payload_len = (segment_len - wrp - 5);
		
				// validate segment-crc
				segCrcBytes[0]=data[0];			//uid0
				segCrcBytes[1]=data[1];			//uid1
				segCrcBytes[2]=data[2];			//uid2
				segCrcBytes[3]=data[3];			//uid3
				segCrcBytes[4]=(data[i] ^ crc);   //hdr0
				segCrcBytes[5]=(data[i+1] ^ crc); //hdr1
				segCrcBytes[6]=(data[i+2] ^ crc); //hdr2
				segCrcBytes[7]=(data[i+3] ^ crc); //hdr3

				segCalcCRC = CRC8Legic(segCrcBytes, 8);
				segCRC = data[i+4] ^ crc;

				PrintAndLog("Segment %02u \nraw header | 0x%02X 0x%02X 0x%02X 0x%02X \nSegment len: %u,  Flag: 0x%X (valid:%01u, last:%01u), WRP: %02u, WRC: %02u, RD: %01u, CRC: 0x%02X (%s)",
					segmentNum,
					data[i] ^ crc,
					data[i+1] ^ crc,
					data[i+2] ^ crc,
					data[i+3] ^ crc,
					segment_len, 
					segment_flag,
					(segment_flag & 0x4) >> 2,
					(segment_flag & 0x8) >> 3,
					wrp,
					wrc,
					((data[i+3]^crc) & 0x80) >> 7,
					segCRC,
					( segCRC == segCalcCRC ) ? "OK" : "fail"
				);

				i += 5;
    
				if ( hasWRC ) {
					PrintAndLog("WRC protected area:   (I %d | K %d| WRC %d)", i, k, wrc);
					PrintAndLog("\nrow  | data");
					PrintAndLog("-----+------------------------------------------------");

					for ( k=i; k < (i + wrc); ++k)
						data[k] ^= crc;

					print_hex_break( data+i, wrc, 16);
			
					i += wrc;
				}
    
				if ( hasWRP ) {
					PrintAndLog("Remaining write protected area:  (I %d | K %d | WRC %d | WRP %d  WRP_LEN %d)",i, k, wrc, wrp, wrp_len);
					PrintAndLog("\nrow  | data");
					PrintAndLog("-----+------------------------------------------------");

					for (k=i; k < (i+wrp_len); ++k)
						data[k] ^= crc;
			
					print_hex_break( data+i, wrp_len, 16);
			
					i += wrp_len;
			
					// does this one work? (Answer: Only if KGH/BGH is used with BCD encoded card number! So maybe this will show just garbage...)
					if( wrp_len == 8 )
						PrintAndLog("Card ID: %2X%02X%02X", data[i-4]^crc, data[i-3]^crc, data[i-2]^crc);			
				}
    
				PrintAndLog("Remaining segment payload:  (I %d | K %d | Remain LEN %d)", i, k, remain_seg_payload_len);
				PrintAndLog("\nrow  | data");
				PrintAndLog("-----+------------------------------------------------");

				for ( k=i; k < (i+remain_seg_payload_len); ++k)
					data[k] ^= crc;
		
				print_hex_break( data+i, remain_seg_payload_len, 16);
    
				i += remain_seg_payload_len;
		
				PrintAndLog("-----+------------------------------------------------\n");

				// end with last segment
				if (segment_flag & 0x8) return 0;

			} // end for loop
		
		} else {

			// Data start point on unsegmented cards
			i = 8;

			wrp = data[7] & 0x0F;
			wrc = (data[7] & 0x70) >> 4;

			bool hasWRC = (wrc > 0);
			bool hasWRP = (wrp > wrc);
			int wrp_len = (wrp - wrc);
			int remain_seg_payload_len = (1024 - 22 - wrp);	// Any chance to get physical card size here!?

			PrintAndLog("Unsegmented card - WRP: %02u, WRC: %02u, RD: %01u",
				wrp,
				wrc,
				(data[7] & 0x80) >> 7
			);

			if ( hasWRC ) {
				PrintAndLog("WRC protected area:   (I %d | WRC %d)", i, wrc);
				PrintAndLog("\nrow  | data");
				PrintAndLog("-----+------------------------------------------------");
				print_hex_break( data+i, wrc, 16);
				i += wrc;
			}
    
			if ( hasWRP ) {
				PrintAndLog("Remaining write protected area:  (I %d | WRC %d | WRP %d | WRP_LEN %d)", i, wrc, wrp, wrp_len);
				PrintAndLog("\nrow  | data");
				PrintAndLog("-----+------------------------------------------------");
				print_hex_break( data + i, wrp_len, 16);
				i += wrp_len;
			
				// does this one work? (Answer: Only if KGH/BGH is used with BCD encoded card number! So maybe this will show just garbage...)
				if( wrp_len == 8 )
					PrintAndLog("Card ID: %2X%02X%02X", data[i-4], data[i-3], data[i-2]);
			}
    
			PrintAndLog("Remaining segment payload:  (I %d | Remain LEN %d)", i, remain_seg_payload_len);
			PrintAndLog("\nrow  | data");
			PrintAndLog("-----+------------------------------------------------");
			print_hex_break( data + i, remain_seg_payload_len, 16);
			i += remain_seg_payload_len;
		
			PrintAndLog("-----+------------------------------------------------\n");
		}
	}
	return 0;
}

int CmdLegicRdmem(const char *Cmd) {

	// params:
	// offset in data memory
	// number of bytes to read
	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'H' || cmdp == 'h' ) return usage_legic_rdmem();
	
	uint32_t offset = 0, len = 0, IV = 1;
	sscanf(Cmd, "%x %x %x", &offset, &len, &IV);

	// OUT-OF-BOUNDS check
	if ( len + offset > MAX_LENGTH ) {
		len = MAX_LENGTH - offset;
		PrintAndLog("Out-of-bound, shorten len to %d (0x%02X)", len, len);
	}
	
	if ( (IV & 0x7F) != IV ){
		IV &= 0x7F;
		PrintAndLog("Truncating IV to 7bits");
	}
	
	if ( (IV & 1) == 0 ){
		IV |= 0x01;
		PrintAndLog("LSB of IV must be SET");	
	}
	
	UsbCommand c = {CMD_READER_LEGIC_RF, {offset, len, IV}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK, &resp, 3000)) {
		uint8_t isOK = resp.arg[0] & 0xFF;
		uint16_t readlen = resp.arg[1];
		 if ( isOK ) {

			uint8_t *data = malloc(readlen);
			if ( !data ){
				PrintAndLog("Cannot allocate memory");
				return 2;
			}
			
			if ( readlen != len )
				PrintAndLog("Fail, only managed to read 0x%02X bytes", readlen);
			
			// copy data from device
			GetEMLFromBigBuf(data, readlen, 0);
			if ( !WaitForResponseTimeout(CMD_ACK, NULL, 2500)){
				PrintAndLog("Command execute timeout");
				if ( data ) 
					free(data);
				return 1;
			}
	
			PrintAndLog("\n ##  | Data");
			PrintAndLog("-----+-----");
			print_hex_break( data, readlen, 32);
		 } else {
			 PrintAndLog("failed reading tag");
		 }
	} else {
		PrintAndLog("command execution time out");
		return 1;
	}
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
	
    int res = sscanf(Cmd, "%x %x %x", &offset, &len, &IV);
	if(res < 2) {
		PrintAndLog("Please specify the offset and length as two hex strings and, optionally, the IV also as an hex string");
        return -1;
    }

	// OUT-OF-BOUNDS check
	if ( len + offset > MAX_LENGTH ) {
		len = MAX_LENGTH - offset;
		PrintAndLog("Out-of-bound, shorten len to %d (0x%02X)", len, len);
	}
	if ( (IV & 0x7F) != IV ){
		IV &= 0x7F;
		PrintAndLog("Truncating IV to 7bits");
	}
	if ( (IV & 1) == 0 ){
		IV |= 0x01;  // IV must be odd
		PrintAndLog("LSB of IV must be SET");	
	}
	
    UsbCommand c = {CMD_WRITER_LEGIC_RF, {offset, len, IV}};	
	clearCommandBuffer();
    SendCommand(&c);
	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
		uint8_t isOK = resp.arg[0] & 0xFF;
		 if ( isOK ) {
		 } else {
			 PrintAndLog("failed writig tag");
		 }
	} else {
		PrintAndLog("command execution time out");
		return 1;
	}
	
    return 0;
}

int CmdLegicRfRawWrite(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'H' || cmdp == 'h' ) return usage_legic_rawwrite();
	
	uint32_t offset = 0, data = 0, IV = 0;	
	char answer;

    int res = sscanf(Cmd, "%x %x %x", &offset, &data, &IV);
	if(res < 2)
		return usage_legic_rawwrite();
	
	// OUT-OF-BOUNDS check
	if ( offset > MAX_LENGTH ) {
		PrintAndLog("Out-of-bound, offset");
		return 1;
	}
	
	if ( (IV & 0x7F) != IV ){
		IV &= 0x7F;
		PrintAndLog("Truncating IV to 7bits");
	}
	if ( (IV & 1) == 0 ){
		IV |= 0x01;  // IV must be odd
		PrintAndLog("LSB of IV must be SET");	
	}

	UsbCommand c = { CMD_RAW_WRITER_LEGIC_RF, {offset, data, IV} };
	
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

void static calc4(uint8_t *cmd, uint8_t len){
	crc_t crc;
 	//crc_init_ref(&crc, 4, 0x19 >> 1, 0x5, 0, TRUE, TRUE);
	crc_init(&crc, 4, 0x19 >> 1, 0x5, 0);

	crc_clear(&crc);
	crc_update(&crc, 1, 1); /* CMD_READ */
	crc_update(&crc, cmd[0], 8);
	crc_update(&crc, cmd[1], 8);
	printf("crc4 %X\n", reflect(crc_finish(&crc), 4) ) ;

	crc_clear(&crc);
	crc_update(&crc, 1, 1); /* CMD_READ */
	crc_update(&crc, cmd[0], 8);
	crc_update(&crc, cmd[1], 8);
	printf("crc4 %X\n",  crc_finish(&crc) ) ;

	printf("---- old ---\n");
	crc_update2(&crc, 1, 1); /* CMD_READ */
	crc_update2(&crc, cmd[0], 8);
	crc_update2(&crc, cmd[1], 8);
	printf("crc4 %X \n", reflect(crc_finish(&crc), 4) ) ;

	
	crc_clear(&crc);
	crc_update2(&crc, 1, 1); /* CMD_READ */
	crc_update2(&crc, cmd[0], 8);
	crc_update2(&crc, cmd[1], 8);
	printf("crc4 %X\n",  crc_finish(&crc) ) ;
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
			PrintAndLog("Legic crc16: %X", CRC16Legic(data, len, uidcrc));
			break;
		case 4:
			calc4(data, 0);
			break;
		default:
			PrintAndLog("Legic crc8: %X",  CRC8Legic(data, len) );
			break;
	}
	
	if (data) free(data);
	return 0;
} 

int legic_print_type(uint32_t tagtype, uint8_t spaces){
	char spc[11] = "          ";
	spc[10]=0x00;
	char *spacer = spc + (10-spaces);

	if ( tagtype == 22 )	
		PrintAndLog("%sTYPE : MIM%d card (outdated)", spacer, tagtype);
	else if ( tagtype == 256 )
		PrintAndLog("%sTYPE : MIM%d card (234 bytes)", spacer, tagtype);
	else if ( tagtype == 1024 )
		PrintAndLog("%sTYPE : MIM%d card (1002 bytes)", spacer, tagtype);
	else
		PrintAndLog("%sTYPE : Unknown %06x", spacer, tagtype);
	return 0;
}
int legic_get_type(legic_card_select_t *card){

	if ( card == NULL ) return 1;

	UsbCommand c = {CMD_LEGIC_INFO, {0,0,0}};
	clearCommandBuffer();
    SendCommand(&c);
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 500))
		return 2;
	
	uint8_t isOK = resp.arg[0] & 0xFF;
	if ( !isOK ) 
		return 3;
	
	memcpy(card, (legic_card_select_t *)resp.d.asBytes, sizeof(legic_card_select_t));
	return 0;
}

int HFLegicReader(const char *Cmd, bool verbose) {

	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'H' || cmdp == 'h' ) return usage_legic_reader();
	
	legic_card_select_t card;
	switch(legic_get_type(&card)){
		case 1: 
			if ( verbose ) PrintAndLog("command execution time out"); 
			return 1;
		case 2: 
		case 3: 
			if ( verbose ) PrintAndLog("legic card select failed");
			return 2;
		default: break;
	}
	PrintAndLog(" UID : %s", sprint_hex(card.uid, sizeof(card.uid)));
	legic_print_type(card.cardsize, 0);
	return 0;
}
int CmdLegicReader(const char *Cmd){
	return HFLegicReader(Cmd, TRUE);
}

int CmdLegicDump(const char *Cmd){

	FILE *fout;
	char filename[FILE_PATH_SIZE] = {0x00};
	char *fnameptr = filename;
	size_t fileNlen = 0;
	bool errors = false;
	uint16_t dumplen;	
	uint8_t cmdp = 0;
	
	while(param_getchar(Cmd, cmdp) != 0x00)
	{
		switch(param_getchar(Cmd, cmdp))
		{
		case 'h':
		case 'H':
			return usage_legic_dump();
		case 'o':
		case 'O':
			fileNlen = param_getstr(Cmd, cmdp+1, filename);
			if (!fileNlen) errors = true; 
			if (fileNlen > FILE_PATH_SIZE-5) fileNlen = FILE_PATH_SIZE-5;
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
	if(errors) return usage_legic_dump();
	
	// tagtype
	legic_card_select_t card;
	if (legic_get_type(&card)) {
		PrintAndLog("Failed to identify tagtype");
		return -1;
	}
	dumplen = card.cardsize;
	
	legic_print_type(dumplen, 0);	
	PrintAndLog("Reading tag memory...");

	UsbCommand c = {CMD_READER_LEGIC_RF, {0x00, dumplen, 0x55}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) {
		PrintAndLog("Command execute time-out");
		return 1;
	}
		
	uint8_t isOK = resp.arg[0] & 0xFF;
	if ( !isOK ) {
		PrintAndLog("Failed dumping tag data");
		return 2;
	}

	uint16_t readlen = resp.arg[1];
	uint8_t *data = malloc(readlen);
	if ( !data ){
		PrintAndLog("Fail, cannot allocate memory");
		return 3;
	}
	
	if ( readlen != dumplen )
		PrintAndLog("Fail, only managed to read 0x%02X bytes of 0x%02X", readlen, dumplen);

	// copy data from device
	GetEMLFromBigBuf(data, readlen, 0);
	if ( !WaitForResponseTimeout(CMD_ACK, NULL, 2500)) {
		PrintAndLog("Fail, transfer from device time-out");
		if ( data ) free(data);
		return 4;
	}

	// user supplied filename?
	if (fileNlen < 1)
		sprintf(fnameptr,"%02X%02X%02X%02X.bin", data[0], data[1], data[2], data[3]);
	else
		sprintf(fnameptr + fileNlen,".bin");

	if ((fout = fopen(filename,"wb")) == NULL) { 
		PrintAndLog("Could not create file name %s", filename);
		if ( data ) free(data);
		return 5;
	}
	fwrite( data, 1, readlen, fout );
	fclose(fout);
	if ( data ) free(data);
	
	PrintAndLog("Wrote %d bytes to %s", readlen, filename);
	return 0;
}	
	
static command_t CommandTable[] =  {
	{"help",	CmdHelp,			1, "This help"},
	{"reader",	CmdLegicReader,		1, "LEGIC Prime Reader UID and Type tag info"},
	{"info",	CmdLegicInfo,		0, "Display deobfuscated and decoded LEGIC Prime tag data"},
	{"dump",	CmdLegicDump,		0, "Dump LEGIC Prime card to binary file"},
	{"rdmem",	CmdLegicRdmem,		0, "[offset][length] <iv> -- read bytes from a LEGIC card"},
	{"save",	CmdLegicSave,		0, "<filename> [<length>] -- Store samples"},
	{"load",	CmdLegicLoad,		0, "<filename> -- Restore samples"},
	{"sim",		CmdLegicRfSim,		0, "[phase drift [frame drift [req/resp drift]]] Start tag simulator (use after load or read)"},
	{"write",	CmdLegicRfWrite,	0, "<offset> <length> <iv> -- Write sample buffer (user after load or read)"},
	{"writeraw",CmdLegicRfRawWrite,	0, "<address> <value> <iv> -- Write direct to address"},
	{"fill",	CmdLegicRfFill,		0, "<offset> <length> <value> -- Fill/Write tag with constant value"},
	{"crc8",	CmdLegicCalcCrc8,	1, "Calculate Legic CRC8 over given hexbytes"},
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