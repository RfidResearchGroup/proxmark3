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

int usage_legic_calccrc(void){
	PrintAndLog("Calculates the legic crc8/crc16 on the given data.");
	PrintAndLog("There must be an even number of hexsymbols as input.");
	PrintAndLog("Usage:  hf legic crc [h] d <data> u <uidcrc> c <8|16>");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");
	PrintAndLog("      d <data>      : (hex symbols) bytes to calculate crc over");
	PrintAndLog("      u <uidcrc>    : MCC hexbyte");
	PrintAndLog("      c <8|16>      : Crc type");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic crc d deadbeef1122");
	PrintAndLog("      hf legic crc d deadbeef1122 u 9A c 16");
	return 0;
}
int usage_legic_rdmem(void){	
	PrintAndLog("Read data from a legic tag.");
	PrintAndLog("Usage:  hf legic rdmem [h] <offset> <length> <IV>");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");
	PrintAndLog("      <offset>      : (hex) offset in data array to start download from");
	PrintAndLog("      <length>      : (hex) number of bytes to read");
	PrintAndLog("      <IV>          : (hex) (optional) Initialization vector to use. Must be odd and 7bits max");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic rdmem 0 16        - reads from byte[0] 0x16 bytes(system header)");
	PrintAndLog("      hf legic rdmem 0 4 55      - reads from byte[0] 0x4 bytes with IV 0x55");
	PrintAndLog("      hf legic rdmem 0 100 55    - reads 0x100 bytes with IV 0x55");
	return 0;
}
int usage_legic_sim(void){
	PrintAndLog("Simulates a LEGIC Prime tag. MIM22, MIM256, MIM1024 types can be emulated");
	PrintAndLog("Use eload/esave to upload a dump into emulator memory");
	PrintAndLog("Usage:  hf legic sim [h] <tagtype> <phase> <frame> <reqresp>");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");
	PrintAndLog("      <tagtype>     : 0 = MIM22");
	PrintAndLog("                    : 1 = MIM256 (default)");
	PrintAndLog("                    : 2 = MIM1024");	
	PrintAndLog("      <phase>       : phase drift");
	PrintAndLog("      <frame>       : frame drift");
	PrintAndLog("      <reqresp>     : reqresp drift");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic sim");
	PrintAndLog("      hf legic sim ");
	return 0;
}
int usage_legic_write(void){
	PrintAndLog("Write data to a LEGIC Prime tag. It autodetects tagsize to make sure size");
	PrintAndLog("Usage:  hf legic write [h] o <offset> d <data (hex symbols)>");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");
	PrintAndLog("      o <offset>    : (hex) offset in data array to start writing");
	//PrintAndLog("  <IV>          : (optional) Initialization vector to use (ODD and 7bits)");
	PrintAndLog("      d <data>      : (hex symbols) bytes to write ");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic write o 10 d 11223344    - Write 0x11223344 starting from offset 0x10");
	return 0;
}
int usage_legic_reader(void){
	PrintAndLog("Read UID and type information from a legic tag.");
	PrintAndLog("Usage:  hf legic reader [h]");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");
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
	PrintAndLog("      h             : this help");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic info");
	return 0;
}
int usage_legic_dump(void){
	PrintAndLog("Reads all pages from LEGIC Prime MIM22, MIM256, MIM1024");
	PrintAndLog("and saves binary dump into the file `filename.bin` or `cardUID.bin`");
	PrintAndLog("It autodetects card type.\n");	
	PrintAndLog("Usage:  hf legic dump [h] o <filename w/o .bin>");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");
	PrintAndLog("      o <filename>  : filename w/o '.bin' to dump bytes");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic dump");
	PrintAndLog("      hf legic dump o myfile");
	return 0;
}
int usage_legic_restore(void){
	PrintAndLog("Reads binary file and it autodetects card type and verifies that the file has the same size");
	PrintAndLog("Then write the data back to card. All bytes except the first 7bytes [UID(4) MCC(1) DCF(2)]\n");
	PrintAndLog("Usage:   hf legic restore [h] i <filename w/o .bin>");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");
	PrintAndLog("      i <filename>  : filename w/o '.bin' to restore bytes on to card from");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic restore i myfile");
	return 0;
}
int usage_legic_eload(void){
	PrintAndLog("It loads binary dump from the file `filename.bin`");
	PrintAndLog("Usage:  hf legic eload [h] [card memory] <file name w/o `.bin`>");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");	
	PrintAndLog("      [card memory] : 0 = MIM22");
	PrintAndLog("                    : 1 = MIM256 (default)");
	PrintAndLog("                    : 2 = MIM1024");
	PrintAndLog("      <filename>    : filename w/o .bin to load");	
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf legic eload 2 myfile");
	return 0;
}
int usage_legic_esave(void){
	PrintAndLog("It saves binary dump into the file `filename.bin` or `cardID.bin`");
	PrintAndLog(" Usage:  hf legic esave [h] [card memory] [file name w/o `.bin`]");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");
	PrintAndLog("      [card memory] : 0 = MIM22");
	PrintAndLog("                    : 1 = MIM256 (default)");
	PrintAndLog("                    : 2 = MIM1024");
	PrintAndLog("      <filename>    : filename w/o .bin to load");	
	PrintAndLog("");
	PrintAndLog("Samples:");	
	PrintAndLog("      hf legic esave 2 myfile");
	return 0;
}
int usage_legic_wipe(void){
	PrintAndLog("Fills a legic tag memory with zeros. From byte7 and to the end.");
	PrintAndLog(" Usage:  hf legic wipe [h]");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");
	PrintAndLog("");
	PrintAndLog("Samples:");	
	PrintAndLog("      hf legic wipe");
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
	uint16_t datalen = 0;
	char token_type[5] = {0,0,0,0,0};
	int dcf = 0;
	int bIsSegmented = 0;

	// tagtype
	legic_card_select_t card;
	if (legic_get_type(&card)) {
		PrintAndLog("Failed to identify tagtype");
		return 1;
	}

	PrintAndLog("Reading tag memory %d b...", card.cardsize);
	
	// allocate receiver buffer
	uint8_t *data = malloc(card.cardsize);
	 if (!data) {
		PrintAndLog("Cannot allocate memory");
		return 2;
	}
	memset(data, 0, card.cardsize);

	int status = legic_read_mem(0, card.cardsize, 0x55, data, &datalen);
	if ( status > 0 ) {
		PrintAndLog("Failed reading memory");
		free(data);
		return 3;
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
 
	// MCD = Manufacturer ID (should be list meaning something?)

	token_type[0] = 0;
	dcf = ((int)data[6] << 8) | (int)data[5];

	// New unwritten media?
	if(dcf == 0xFFFF) {

		PrintAndLog("DCF: %d (%02x %02x), Token Type=NM (New Media)",
			dcf,
			data[5],
			data[6]
		);
	
	} else if (dcf > 60000) {		// Master token?

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

	// Not Data card?
	if (dcf > 60000)
		goto out;
	
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
			if (segment_flag & 0x8) 
				goto out;

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

out:
	free(data);
	return 0;
}

// params:
// offset in data memory
// number of bytes to read
int CmdLegicRdmem(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'H' || cmdp == 'h' ) return usage_legic_rdmem();
	
	uint32_t offset = 0, len = 0, iv = 1;
	uint16_t datalen = 0;
	sscanf(Cmd, "%x %x %x", &offset, &len, &iv);
	
	PrintAndLog("Reading %d bytes, from offset %d", len, offset);
	
	// allocate receiver buffer
	uint8_t *data = malloc(len);
	if ( !data ){
		PrintAndLog("Cannot allocate memory");
		return 2;
	}
	memset(data, 0, len);
	
	int status = legic_read_mem(offset, len, iv, data, &datalen);
	if ( status == 0 ) {
	PrintAndLog("\n ##  |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");
	PrintAndLog("-----+------------------------------------------------------------------------------------------------");
		print_hex_break(data, datalen, 32);
	}
	free(data);
	return status;
}

// should say which tagtype
// should load a tag to device mem.
// int phase, int frame, int reqresp
int CmdLegicRfSim(const char *Cmd) {
	UsbCommand c = {CMD_SIMULATE_TAG_LEGIC_RF, {6,3,0}};
	sscanf(Cmd, " %" SCNi64 " %" SCNi64 " %" SCNi64 , &c.arg[0], &c.arg[1], &c.arg[2]);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdLegicRfWrite(const char *Cmd) {

	uint8_t *data = NULL;
	uint8_t cmdp = 0;
	bool errors = false;
	int len = 0, bg, en;
	uint32_t offset = 0, IV = 0x55;
	
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'd':
		case 'D':
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
			
			// limit number of bytes to write. This is not a 'restore' command.
			if ( (len>>1) > 100 ){
				PrintAndLog("Max bound on 100bytes to write a one time.");
				PrintAndLog("Use the 'hf legic restore' command if you want to write the whole tag at once");
				errors = true;
			}

			// it's possible for user to accidentally enter "b" parameter
			// more than once - we have to clean previous malloc
			if (data)
				free(data);
			
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
		case 'o':
		case 'O':
			offset = param_get32ex(Cmd, cmdp+1, 4, 16);
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
	}
	//Validations
	if (errors || cmdp == 0){
		if (data) 
			free(data);
		return usage_legic_write();
	}

	// tagtype
	legic_card_select_t card;
	if (legic_get_type(&card)) {
		PrintAndLog("Failed to identify tagtype");
		return -1;
	}

	legic_print_type(card.cardsize, 0);
	
	// OUT-OF-BOUNDS checks
	// UID 4+1 bytes can't be written to.
	if ( offset < 5 ) {
		PrintAndLog("Out-of-bounds, bytes 0-1-2-3-4 can't be written to. Offset = %d", offset);
		return -2;
	}
	
	if ( len + offset >= card.cardsize ) {
		PrintAndLog("Out-of-bounds, Cardsize = %d, [offset+len = %d ]", card.cardsize, len + offset);
		return -2;
	}

	if (offset == 5 || offset == 6) {
		PrintAndLog("############# DANGER ################");
		PrintAndLog("# changing the DCF is irreversible  #");
		PrintAndLog("#####################################");
		char *answer = NULL;
		answer = readline("do you really want to continue? y(es) n(o) : ");
		bool overwrite = (answer[0] == 'y' || answer[0] == 'Y');
		if (!overwrite){
			PrintAndLog("command cancelled");
			return 0;
		}
	}
	
	legic_chk_iv(&IV);
	
	PrintAndLog("Writing to tag");

	UsbCommand c = {CMD_WRITER_LEGIC_RF, {offset, len, IV}};
	memcpy(c.d.asBytes, data, len);	
	UsbCommand resp;
	clearCommandBuffer();
	SendCommand(&c);
	
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
		PrintAndLog("command execution time out");
		return 1;
	}
	uint8_t isOK = resp.arg[0] & 0xFF;
	if ( !isOK ) {
		PrintAndLog("failed writing tag");
		return 1;
	}

    return 0;
}

int CmdLegicCalcCrc(const char *Cmd){

	uint8_t *data = NULL;
	uint8_t cmdp = 0, uidcrc = 0, type=0;
	bool errors = false;
	int len = 0;
	int bg, en;
	
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'd':
		case 'D':
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
	}
	//Validations
	if (errors || cmdp == 0){
		if (data) free(data);
		return usage_legic_calccrc();
	}
	
	switch (type){
		case 16:
			PrintAndLog("Legic crc16: %X", CRC16Legic(data, len, uidcrc));
			break;
		default:
			PrintAndLog("Legic crc8: %X",  CRC8Legic(data, len) );
			break;
	}
	
	if (data) free(data);
	return 0;
} 

int legic_read_mem(uint32_t offset, uint32_t len, uint32_t iv, uint8_t *out, uint16_t *outlen) {
	
	legic_chk_iv(&iv);
	
	UsbCommand c = {CMD_READER_LEGIC_RF, {offset, len, iv}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if ( !WaitForResponseTimeout(CMD_ACK, &resp, 3000) ) {
		PrintAndLog("command execution time out");
		return 1;
	}

	uint8_t isOK = resp.arg[0] & 0xFF;
	*outlen = resp.arg[1];
	if ( !isOK ) {
		PrintAndLog("failed reading tag");
		return 2;
	}
	
	if ( *outlen != len )
		PrintAndLog("Fail, only managed to read %u bytes", *outlen);
	
	// copy data from device
	if ( !GetEMLFromBigBuf(out, *outlen, 0) ) {
		PrintAndLog("Fail, transfer from device time-out");
		return 4;
	}
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
void legic_chk_iv(uint32_t *iv){
	if ( (*iv & 0x7F) != *iv ){
		*iv &= 0x7F;
		PrintAndLog("Truncating IV to 7bits, %u", *iv);
	}
	// IV must be odd
	if ( (*iv & 1) == 0 ){
		*iv |= 0x01;  
		PrintAndLog("LSB of IV must be SET %u", *iv);	
	}
}
void legic_seteml(uint8_t *src, uint32_t offset, uint32_t numofbytes) {
	size_t len = 0;

	UsbCommand c = {CMD_LEGIC_ESET, {0, 0, 0}};	
	for(size_t i = offset; i < numofbytes; i += USB_CMD_DATA_SIZE) {
		
		len = MIN((numofbytes - i), USB_CMD_DATA_SIZE);		
		c.arg[0] = i; // offset
		c.arg[1] = len; // number of bytes
		memcpy(c.d.asBytes, src+i, len); 
		clearCommandBuffer();
		SendCommand(&c);
	}
}


int HFLegicReader(const char *Cmd, bool verbose) {

	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'H' || cmdp == 'h' ) return usage_legic_reader();
	
	legic_card_select_t card;
	switch(legic_get_type(&card)){
		case 1: 
			return 2;
		case 2: 
			if ( verbose ) PrintAndLog("command execution time out"); 
			return 1;
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
	return HFLegicReader(Cmd, true);
}

int CmdLegicDump(const char *Cmd){

	FILE *f;
	char filename[FILE_PATH_SIZE] = {0x00};
	char *fnameptr = filename;
	size_t fileNlen = 0;
	bool errors = false;
	uint16_t dumplen;	
	uint8_t cmdp = 0;
	
	memset(filename, 0, sizeof(filename));
	
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
			case 'h':
			case 'H':
				return usage_legic_dump();
			case 'o':
			case 'O':
				fileNlen = param_getstr(Cmd, cmdp+1, filename);
				if (!fileNlen) 
					errors = true; 
				if (fileNlen > FILE_PATH_SIZE-5) 
					fileNlen = FILE_PATH_SIZE-5;
				cmdp += 2;
				break;
			default:
				PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = true;
				break;
		}
	}
	//Validations
	if (errors) return usage_legic_dump();
	
	// tagtype
	legic_card_select_t card;
	if (legic_get_type(&card)) {
		PrintAndLog("Failed to identify tagtype");
		return -1;
	}
	dumplen = card.cardsize;
	
	legic_print_type(dumplen, 0);	
	PrintAndLog("Reading tag memory %d b...", dumplen);

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
	if (!data) {
		PrintAndLog("Fail, cannot allocate memory");
		return 3;
	}
	memset(data, 0, readlen);
	
	if ( readlen != dumplen )
		PrintAndLog("Fail, only managed to read 0x%02X bytes of 0x%02X", readlen, dumplen);

	// copy data from device
	if (!GetEMLFromBigBuf(data, readlen, 0) ) {
		PrintAndLog("Fail, transfer from device time-out");
		free(data);
		return 4;
	}

	// user supplied filename?
	if (fileNlen < 1)
		sprintf(fnameptr,"%02X%02X%02X%02X.bin", data[0], data[1], data[2], data[3]);
	else
		sprintf(fnameptr + fileNlen,".bin");

	f = fopen(filename,"wb");
	if (!f) { 
		PrintAndLog("Could not create file name %s", filename);
		if (data)
			free(data);
		return 5;
	}
	fwrite(data, 1, readlen, f);
	fflush(f);
	fclose(f);
	free(data);
	PrintAndLog("Wrote %d bytes to %s", readlen, filename);
	return 0;
}	

int CmdLegicRestore(const char *Cmd){

	FILE *f;
	char filename[FILE_PATH_SIZE] = {0x00};
	char *fnameptr = filename;
	size_t fileNlen = 0;
	bool errors = false;
	uint16_t numofbytes;	
	uint8_t cmdp = 0;
	
	memset(filename, 0, sizeof(filename));
	
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
			case 'h':
			case 'H':
				errors = true;
				break;
			case 'i':
			case 'I':
				fileNlen = param_getstr(Cmd, cmdp+1, filename);
				if (!fileNlen) 
					errors = true;
				
				if (fileNlen > FILE_PATH_SIZE-5) 
					fileNlen = FILE_PATH_SIZE-5;
				cmdp += 2;				
				break;
			default:
				PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = true;
				break;
		}
	}
	//Validations
	if (errors || cmdp == 0) return usage_legic_restore();
	
	// tagtype
	legic_card_select_t card;
	if (legic_get_type(&card)) {
		PrintAndLog("Failed to identify tagtype");
		return 1;
	}
	numofbytes = card.cardsize;	
	
	// set up buffer
	uint8_t *data = malloc(numofbytes);
	if (!data) {
		PrintAndLog("Fail, cannot allocate memory");
		return 2;		
	}
	memset(data, 0, numofbytes);
	
	legic_print_type(numofbytes, 0);	

	// set up file
	fnameptr += fileNlen;
	sprintf(fnameptr, ".bin");

	f = fopen(filename,"rb");
	if (!f) {
		PrintAndLog("File %s not found or locked", filename);
		return 3;
	}	
	
	// verify size of dumpfile is the same as card.	
	fseek(f, 0, SEEK_END); // seek to end of file
	size_t filesize = ftell(f); // get current file pointer
	fseek(f, 0, SEEK_SET); // seek back to beginning of file
	
	if ( filesize != numofbytes) {
		PrintAndLog("Fail, filesize and cardsize is not equal. [%u != %u]", filesize, numofbytes);
		free(data);
		fclose(f);
		return 4;
	}

	// load file
	size_t bytes_read = fread(data, 1, numofbytes, f);
	fclose(f);
	
	if ( bytes_read == 0){
		PrintAndLog("File reading error");
		free(data);
		return 2;
	}
	
	PrintAndLog("Restoring to card");

	// transfer to device
	size_t len = 0;
	UsbCommand c = {CMD_WRITER_LEGIC_RF, {0, 0, 0x55}};
	UsbCommand resp;
	for(size_t i = 7; i < numofbytes; i += USB_CMD_DATA_SIZE) {
		
		len = MIN((numofbytes - i), USB_CMD_DATA_SIZE);		
		c.arg[0] = i; // offset
		c.arg[1] = len; // number of bytes
		memcpy(c.d.asBytes, data+i, len); 
		clearCommandBuffer();
		SendCommand(&c);
	
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 4000)) {
			PrintAndLog("command execution time out");
			free(data);	
			return 1;
		}
		uint8_t isOK = resp.arg[0] & 0xFF;
		if ( !isOK ) {
			PrintAndLog("failed writing tag [msg = %u]", resp.arg[1] & 0xFF);
			free(data);	
			return 1;
		}
		PrintAndLog("Wrote chunk [offset %d | len %d | total %d", i, len, i+len);
	}	
	
	free(data);	
	PrintAndLog("\nWrote %d bytes to card from file %s", numofbytes, filename);
	return 0;
}

int CmdLegicELoad(const char *Cmd) {
	FILE * f;
	char filename[FILE_PATH_SIZE];
	char *fnameptr = filename;
	int len, numofbytes;
	int nameParamNo = 1;
	
	char cmdp = param_getchar(Cmd, 0);		
	if ( cmdp == 'h' || cmdp == 'H' || cmdp == 0x00)
		return usage_legic_eload();

	switch (cmdp) {
		case '0' : numofbytes = 22; break;
		case '1' : 
		case '\0': numofbytes = 256; break;
		case '2' : numofbytes = 1024; break;
		default  : numofbytes = 256;  nameParamNo = 0;break;
	}

	// set up buffer
	uint8_t *data = malloc(numofbytes);
	if (!data) {
		PrintAndLog("Fail, cannot allocate memory");
		return 3;		
	}
	memset(data, 0, numofbytes);
	
	// set up file
	len = param_getstr(Cmd, nameParamNo, filename);
	if (len > FILE_PATH_SIZE - 5) 
		len = FILE_PATH_SIZE - 5;
	fnameptr += len;
	sprintf(fnameptr, ".bin");
	
	// open file
	f = fopen(filename,"rb");
	if (!f) { 
		PrintAndLog("File %s not found or locked", filename);
		free(data);
		return 1;
	}

	// load file
	size_t bytes_read = fread(data, 1, numofbytes, f);
	if ( bytes_read == 0){
		PrintAndLog("File reading error");
		free(data);
		fclose(f);
		f = NULL;		
		return 2;
	}
	fclose(f);
	f = NULL;
	
	// transfer to device
	legic_seteml(data, 0, numofbytes);
		
	free(data);	
	PrintAndLog("\nLoaded %d bytes from file: %s  to emulator memory", numofbytes, filename);
	return 0;
}

int CmdLegicESave(const char *Cmd) {
	FILE *f;
	char filename[FILE_PATH_SIZE];
	char *fnameptr = filename;
	int fileNlen, numofbytes, nameParamNo = 1;
	
	memset(filename, 0, sizeof(filename));

	char cmdp = param_getchar(Cmd, 0);
	
	if ( cmdp == 'h' || cmdp == 'H' || cmdp == 0x00)
		return usage_legic_esave();

	switch (cmdp) {
		case '0' : numofbytes = 22; break;
		case '1' : 
		case '\0': numofbytes = 256; break;
		case '2' : numofbytes = 1024; break;
		default  : numofbytes = 256; nameParamNo = 0; break;
	}

	fileNlen = param_getstr(Cmd, nameParamNo, filename);
	
	if (fileNlen > FILE_PATH_SIZE - 5) 
		fileNlen = FILE_PATH_SIZE - 5;

	// set up buffer
	uint8_t *data = malloc(numofbytes);
	if (!data) {
		PrintAndLog("Fail, cannot allocate memory");
		return 3;		
	}
	memset(data, 0, numofbytes);
		
	// download emulator memory
	PrintAndLog("Reading emulator memory...");	
	if (!GetEMLFromBigBuf(data, numofbytes, 0)) {
		PrintAndLog("Fail, transfer from device time-out");
		free(data);
		return 4;
	}

	// user supplied filename?
	if (fileNlen < 1)		
		sprintf(fnameptr,"%02X%02X%02X%02X.bin", data[0], data[1], data[2], data[3]);
	else
		sprintf(fnameptr + fileNlen,".bin");
	
	// open file
	f = fopen(filename,"wb");
	if (!f) { 
		PrintAndLog("Could not create file name %s", filename);
		free(data);
		return 1;
	}
	fwrite(data, 1, numofbytes, f);
	fclose(f);
	free(data);
	PrintAndLog("\nSaved %d bytes from emulator memory to file: %s", numofbytes, filename);
	return 0;
}

int CmdLegicWipe(const char *Cmd){

	char cmdp = param_getchar(Cmd, 0);
	
	if ( cmdp == 'h' || cmdp == 'H') return usage_legic_wipe();
	
	// tagtype
	legic_card_select_t card;
	if (legic_get_type(&card)) {
		PrintAndLog("Failed to identify tagtype");
		return 1;
	}
	
	// set up buffer
	uint8_t *data = malloc(card.cardsize);
	if (!data) {
		PrintAndLog("Fail, cannot allocate memory");
		return 2;		
	}
	memset(data, 0, card.cardsize);
	
	legic_print_type(card.cardsize, 0);

	printf("Erasing");
	
	// transfer to device
	size_t len = 0;
	UsbCommand c = {CMD_WRITER_LEGIC_RF, {0, 0, 0x55}};
	UsbCommand resp;
	for(size_t i = 7; i < card.cardsize; i += USB_CMD_DATA_SIZE) {
		
		printf(".");
		len = MIN((card.cardsize - i), USB_CMD_DATA_SIZE);		
		c.arg[0] = i; // offset
		c.arg[1] = len; // number of bytes
		memcpy(c.d.asBytes, data+i, len); 
		clearCommandBuffer();
		SendCommand(&c);
	
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 4000)) {
			PrintAndLog("command execution time out");
			free(data);	
			return 3;
		}
		uint8_t isOK = resp.arg[0] & 0xFF;
		if ( !isOK ) {
			PrintAndLog("failed writing tag [msg = %u]", resp.arg[1] & 0xFF);
			free(data);	
			return 4;
		}
	}
	printf("ok\n");
	return 0;
}

int CmdLegicList(const char *Cmd) {
	CmdHFList("legic");
	return 0;
}

static command_t CommandTable[] =  {
	{"help",	CmdHelp,			1, "This help"},
	{"reader",	CmdLegicReader,		1, "LEGIC Prime Reader UID and tag info"},
	{"info",	CmdLegicInfo,		0, "Display deobfuscated and decoded LEGIC Prime tag data"},
	{"dump",	CmdLegicDump,		0, "Dump LEGIC Prime tag to binary file"},
	{"restore", CmdLegicRestore,	0, "Restore a dump onto a LEGIC Prime tag"},
	{"rdmem",	CmdLegicRdmem,		0, "Read bytes from a LEGIC Prime tag"},
	{"sim",		CmdLegicRfSim,		0, "Start tag simulator"},
	{"write",	CmdLegicRfWrite,	0, "Write data to a LEGIC Prime tag"},
	{"crc",		CmdLegicCalcCrc,	1, "Calculate Legic CRC over given bytes"},	
	{"eload",	CmdLegicELoad,		1, "Load binary dump to emulator memory"},
	{"esave",	CmdLegicESave,		1, "Save emulator memory to binary file"},
	{"list",	CmdLegicList,		1, "[Deprecated] List LEGIC history"},
	{"wipe",	CmdLegicWipe,		1, "Wipe a LEGIC Prime tag"},
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