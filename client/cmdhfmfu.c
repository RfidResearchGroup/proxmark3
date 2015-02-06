//-----------------------------------------------------------------------------
// Ultralight Code (c) 2013,2014 Midnitesnake & Andy Davies of Pentura
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE ULTRALIGHT (C) commands
//-----------------------------------------------------------------------------
//#include <openssl/des.h>
#include "loclass/des.h"
#include "cmdhfmfu.h"
#include "cmdhfmf.h"
#include "cmdhf14a.h"


#define MAX_ULTRA_BLOCKS   0x0f
#define MAX_ULTRAC_BLOCKS  0x2f
//#define MAX_ULTRAC_BLOCKS  0x2c


static int CmdHelp(const char *Cmd);

int CmdHF14AMfUInfo(const char *Cmd){

	uint8_t datatemp[7] = {0x00};
	uint8_t isOK  = 0;
	uint8_t *data = NULL;

	UsbCommand c = {CMD_MIFAREU_READCARD, {0, 4}};
	SendCommand(&c);
	UsbCommand resp;

	if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
		isOK  = resp.arg[0] & 0xff;
		data  = resp.d.asBytes;

		if (!isOK) {
			PrintAndLog("Error reading from tag");
			return -1;
		}
	} else {
		PrintAndLog("Command execute timed out");
		return -1;
	}
	
	PrintAndLog("");
	PrintAndLog("-- Mifare Ultralight / Ultralight-C Tag Information ---------");
	PrintAndLog("-------------------------------------------------------------");

	// UID
	memcpy( datatemp, data, 3);
	memcpy( datatemp+3, data+4, 4);
	
	PrintAndLog("MANUFACTURER : %s", getTagInfo(datatemp[0]));
	PrintAndLog("         UID : %s ", sprint_hex(datatemp, 7));
	// BBC
	// CT (cascade tag byte) 0x88 xor SN0 xor SN1 xor SN2 
	int crc0 = 0x88 ^ data[0] ^ data[1] ^data[2];
	if ( data[3] == crc0 )
		PrintAndLog("        BCC0 : %02x - Ok", data[3]);
	else
		PrintAndLog("        BCC0 : %02x - crc should be %02x", data[3], crc0);
		
	int crc1 = data[4] ^ data[5] ^ data[6] ^data[7];
	if ( data[8] == crc1 )
		PrintAndLog("        BCC1 : %02x - Ok", data[8]);
	else
		PrintAndLog("        BCC1 : %02x - crc should be %02x", data[8], crc1 );
	
	PrintAndLog("    Internal : %s ", sprint_hex(data + 9, 1));
	
	memcpy(datatemp, data+10, 2);
	PrintAndLog("        Lock : %s - %s", sprint_hex(datatemp, 2),printBits( 2, &datatemp) );
	PrintAndLog("  OneTimePad : %s ", sprint_hex(data + 3*4, 4));
	PrintAndLog("");

	int len = CmdHF14AMfucAuth("K 0");
//	PrintAndLog("CODE: %d",len);
	
	PrintAndLog("Seems to be a Ultralight %s", (len==0) ? "-C" :"");
	return 0;
}

//
//  Mifare Ultralight Write Single Block
//
int CmdHF14AMfUWrBl(const char *Cmd){
	uint8_t blockNo    = -1;
	bool chinese_card  = FALSE;
	uint8_t bldata[16] = {0x00};
	UsbCommand resp;

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) < 3 || cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  hf mfu wrbl <block number> <block data (8 hex symbols)> [w]");
		PrintAndLog("       [block number]");
		PrintAndLog("       [block data] - (8 hex symbols)");
		PrintAndLog("       [w] - Chinese magic ultralight tag");
		PrintAndLog("");
		PrintAndLog("        sample: hf mfu wrbl 0 01020304");
		PrintAndLog("");		
		return 0;
	}       
	
	blockNo = param_get8(Cmd, 0);

	if (blockNo > MAX_ULTRA_BLOCKS){
		PrintAndLog("Error: Maximum number of blocks is 15 for Ultralight Cards!");
		return 1;
	}
	
	if (param_gethex(Cmd, 1, bldata, 8)) {
		PrintAndLog("Block data must include 8 HEX symbols");
		return 1;
	}
	
	if (strchr(Cmd,'w') != 0  || strchr(Cmd,'W') != 0 ) {
		chinese_card = TRUE; 
	}
	
	if ( blockNo <= 3) {
		if (!chinese_card){
			PrintAndLog("Access Denied");
		} else {
			PrintAndLog("--specialblock no:%02x", blockNo);
			PrintAndLog("--data: %s", sprint_hex(bldata, 4));
			UsbCommand d = {CMD_MIFAREU_WRITEBL, {blockNo}};
			memcpy(d.d.asBytes,bldata, 4);
			SendCommand(&d);
			if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
				uint8_t isOK  = resp.arg[0] & 0xff;
				PrintAndLog("isOk:%02x", isOK);
			} else {
				PrintAndLog("Command execute timeout");
			}  
		}
	} else {
		PrintAndLog("--block no:%02x", blockNo);
		PrintAndLog("--data: %s", sprint_hex(bldata, 4));        	
		UsbCommand e = {CMD_MIFAREU_WRITEBL, {blockNo}};
		memcpy(e.d.asBytes,bldata, 4);
		SendCommand(&e);
		if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
			uint8_t isOK  = resp.arg[0] & 0xff;
			PrintAndLog("isOk:%02x", isOK);
		} else {
			PrintAndLog("Command execute timeout");
		}
	}
	return 0;
}

//
//  Mifare Ultralight Read Single Block
//
int CmdHF14AMfURdBl(const char *Cmd){
  
	uint8_t blockNo = -1;	

	char cmdp = param_getchar(Cmd, 0);
	
	if (strlen(Cmd) < 1 || cmdp == 'h' || cmdp == 'H') {	
		PrintAndLog("Usage:  hf mfu rdbl <block number>");
		PrintAndLog("        sample: hfu mfu rdbl 0");
		return 0;
	}       
		
	blockNo = param_get8(Cmd, 0);

	if (blockNo > MAX_ULTRA_BLOCKS){
	   PrintAndLog("Error: Maximum number of blocks is 15 for Ultralight Cards!");
	   return 1;
	}
	
	PrintAndLog("--block no:0x%02X (%d)", (int)blockNo, blockNo);
	UsbCommand c = {CMD_MIFAREU_READBL, {blockNo}};
	SendCommand(&c);

	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		uint8_t isOK    = resp.arg[0] & 0xff;
		uint8_t * data  = resp.d.asBytes;
		
		PrintAndLog("isOk: %02x", isOK);
			
		if (isOK)
			PrintAndLog("Data: %s", sprint_hex(data, 4));
	} else {
		PrintAndLog("Command execute timeout");
	}
	return 0;
}

//
//  Mifare Ultralight / Ultralight-C;  Read and Dump Card Contents
//
int CmdHF14AMfUDump(const char *Cmd){

	FILE *fout;
	char filename[FILE_PATH_SIZE] = {0x00};
	char * fnameptr = filename;
	
	uint8_t *lockbytes_t = NULL;
	uint8_t lockbytes[2] = {0x00};
	
	uint8_t *lockbytes_t2 = NULL;
	uint8_t lockbytes2[2] = {0x00};

	bool bit[16]  = {0x00};
	bool bit2[16] = {0x00};
	
	int i;
	uint8_t BlockNo      = 0;
	int Pages            = 16;

	bool tmplockbit		 = false;
	uint8_t isOK         = 0;
	uint8_t *data       = NULL;

	char cmdp = param_getchar(Cmd, 0);
	
	if (cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Reads all pages from Mifare Ultralight or Ultralight-C tag.");
		PrintAndLog("It saves binary dump into the file `filename.bin` or `cardUID.bin`");		
		PrintAndLog("Usage:  hf mfu dump <c> <filename w/o .bin>");
		PrintAndLog("     <c>  optional cardtype c == Ultralight-C, if not defaults to Ultralight");
		PrintAndLog("     sample: hf mfu dump");
		PrintAndLog("           : hf mfu dump myfile");
		PrintAndLog("           : hf mfu dump c myfile");
		return 0;
	}

	// UL or UL-C?
	Pages = (cmdp == 'c' || cmdp == 'C') ? 44 : 16;
	
	PrintAndLog("Dumping Ultralight%s Card Data...", (Pages ==16)?"":"-C");
		
	UsbCommand c = {CMD_MIFAREU_READCARD, {BlockNo,Pages}};
	SendCommand(&c);
	UsbCommand resp;

	if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		isOK  = resp.arg[0] & 0xff;
		if (!isOK) {                
			PrintAndLog("Command error");
			return 0;
		}
		data  = resp.d.asBytes;
	} else {
		PrintAndLog("Command execute timeout");
		return 0;
	}
		
	// Load lock bytes.
	int j = 0;
	
	lockbytes_t = data + 8;
	lockbytes[0] = lockbytes_t[2];
	lockbytes[1] = lockbytes_t[3];
	for(j = 0; j < 16; j++){
		bit[j] = lockbytes[j/8] & ( 1 <<(7-j%8));
	}		
	
	// Load bottom lockbytes if available
	if ( Pages == 44 ) {
		
		lockbytes_t2 = data + (40*4);
		lockbytes2[0] = lockbytes_t2[2];
		lockbytes2[1] = lockbytes_t2[3];
		for (j = 0; j < 16; j++) {
			bit2[j] = lockbytes2[j/8] & ( 1 <<(7-j%8));
		}
	}

	for (i = 0; i < Pages; ++i) {
		
		if ( i < 3 ) {
			PrintAndLog("Block %02x:%s ", i,sprint_hex(data + i * 4, 4));
			continue;
		}

		switch(i){
			case 3: tmplockbit = bit[4]; break;
			case 4:	tmplockbit = bit[3]; break;
			case 5:	tmplockbit = bit[2]; break;
			case 6:	tmplockbit = bit[1]; break;
			case 7:	tmplockbit = bit[0]; break;
			case 8:	tmplockbit = bit[15]; break;
			case 9: tmplockbit = bit[14]; break;
			case 10: tmplockbit = bit[13]; break;
			case 11: tmplockbit = bit[12]; break;
			case 12: tmplockbit = bit[11]; break;
			case 13: tmplockbit = bit[10]; break;
			case 14: tmplockbit = bit[9]; break;
			case 15: tmplockbit = bit[8]; break;
			case 16:
			case 17:
			case 18:
			case 19: tmplockbit = bit2[6]; break;
			case 20:
			case 21:
			case 22:
			case 23: tmplockbit = bit2[5]; break; 
			case 24:
			case 25:
			case 26:
			case 27: tmplockbit = bit2[4]; break; 		    
			case 28:
			case 29:
			case 30:
			case 31: tmplockbit = bit2[2]; break;
			case 32:
			case 33:
			case 34:
			case 35: tmplockbit = bit2[1]; break; 
			case 36:
			case 37:
			case 38:
			case 39: tmplockbit = bit2[0]; break; 
			case 40: tmplockbit = bit2[12]; break;
			case 41: tmplockbit = bit2[11]; break;
			case 42: tmplockbit = bit2[10]; break; //auth0
			case 43: tmplockbit = bit2[9]; break;  //auth1
			default: break;
		}
		PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),tmplockbit);
	}  
	
	int len = 0;
	if ( Pages == 16 )
		len = param_getstr(Cmd,0,filename);
	else
		len = param_getstr(Cmd,1,filename);

	if (len > FILE_PATH_SIZE-5) len = FILE_PATH_SIZE-5;

	// user supplied filename?
	if (len < 1) {
	
		// UID = data 0-1-2 4-5-6-7  (skips a beat)
		sprintf(fnameptr,"%02X%02X%02X%02X%02X%02X%02X.bin",
			data[0],data[1], data[2], data[4],data[5],data[6], data[7]);

	} else {
		sprintf(fnameptr + len," .bin");
	}


	if ((fout = fopen(filename,"wb")) == NULL) { 
		PrintAndLog("Could not create file name %s", filename);
		return 1;	
	}
	fwrite( data, 1, Pages*4, fout );
	fclose(fout);
	
	PrintAndLog("Dumped %d pages, wrote %d bytes to %s", Pages, Pages*4, filename);
	return 0;
}

// Needed to Authenticate to Ultralight C tags
void rol (uint8_t *data, const size_t len){
	uint8_t first = data[0];
	for (size_t i = 0; i < len-1; i++) {
		data[i] = data[i+1];
	}
	data[len-1] = first;
}

//-------------------------------------------------------------------------------
// Ultralight C Methods
//-------------------------------------------------------------------------------

//
// Ultralight C Authentication Demo {currently uses hard-coded key}
//
int CmdHF14AMfucAuth(const char *Cmd){

	uint8_t default_keys[5][16] = {
		{ 0x42,0x52,0x45,0x41,0x4b,0x4d,0x45,0x49,0x46,0x59,0x4f,0x55,0x43,0x41,0x4e,0x21 },// 3des std key
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },// all zeroes
		{ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f },// 0x00-0x0F
		{ 0x49,0x45,0x4D,0x4B,0x41,0x45,0x52,0x42,0x21,0x4E,0x41,0x43,0x55,0x4F,0x59,0x46 },// NFC-key
		{ 0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01 }	// all ones
	};

	char cmdp = param_getchar(Cmd, 0);
	
	uint8_t keyNo = 0;
	bool errors = false;
	//Change key to user defined one
	if (cmdp == 'k' || cmdp == 'K'){
		keyNo = param_get8(Cmd, 1);
		if(keyNo >= 4) errors = true;
	}

	if (cmdp == 'h' || cmdp == 'H') {
		errors = true;
	}

	if (errors) {
		PrintAndLog("Usage:  hf mfu cauth k <key number>");
		PrintAndLog("      0 (default): 3DES standard key");
		PrintAndLog("      1 : all zeros key");
		PrintAndLog("      2 : 0x00-0x0F key");
		PrintAndLog("      3 : nfc key");
		PrintAndLog("      4 : all ones key");
		PrintAndLog("        sample : hf mfu cauth k");
		PrintAndLog("               : hf mfu cauth k 3");
		return 0;
	} 

	uint8_t random_a[8]     = { 1,1,1,1,1,1,1,1 };
	//uint8_t enc_random_a[8] = { 0 };
	uint8_t random_b[8]     = { 0 };
	uint8_t enc_random_b[8] = { 0 };
	uint8_t random_a_and_b[16] = { 0 };
	des3_context ctx        = { 0 };
	uint8_t *key = default_keys[keyNo];
	uint8_t blockNo = 0;
	uint32_t cuid = 0;

	//Auth1
	UsbCommand c = {CMD_MIFAREUC_AUTH1, {blockNo}};
	SendCommand(&c);
	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		uint8_t isOK  = resp.arg[0] & 0xff;
		cuid  = resp.arg[1];
		uint8_t * data= resp.d.asBytes;

		if (isOK){
			PrintAndLog("enc(RndB):%s", sprint_hex(data+1, 8));
			memcpy(enc_random_b,data+1,8);
		} else {
			PrintAndLog("Auth failed");
			return 2; // auth failed.
		}		
	} else {
		PrintAndLog("Command execute timeout");
		return 1;
	}

	uint8_t iv[8]           = { 0 };
	// Do we need random ? Right now we use all ones, is that random enough ?
//    DES_random_key(&RndA);

	PrintAndLog("     RndA  :%s",sprint_hex(random_a, 8));
	PrintAndLog("     e_RndB:%s",sprint_hex(enc_random_b, 8));

	des3_set2key_dec(&ctx, key);

	des3_crypt_cbc(&ctx      // des3_context *ctx
		, DES_DECRYPT        // int mode
		, sizeof(random_b)   // size_t length
		, iv                 // unsigned char iv[8]
		, enc_random_b       // const unsigned char *input
		, random_b           // unsigned char *output
		);

	PrintAndLog("     RndB:%s",sprint_hex(random_b, 8));

	rol(random_b,8);
	memcpy(random_a_and_b  ,random_a,8);
	memcpy(random_a_and_b+8,random_b,8);
	
	PrintAndLog("     RA+B:%s",sprint_hex(random_a_and_b, 16));

	des3_set2key_enc(&ctx, key);

	des3_crypt_cbc(&ctx          // des3_context *ctx
		, DES_ENCRYPT            // int mode
		, sizeof(random_a_and_b)   // size_t length
		, enc_random_b           // unsigned char iv[8]
		, random_a_and_b         // const unsigned char *input
		, random_a_and_b         // unsigned char *output
		);

	PrintAndLog("enc(RA+B):%s",sprint_hex(random_a_and_b, 16));

	//Auth2
	UsbCommand d = {CMD_MIFAREUC_AUTH2, {cuid}};
	memcpy(d.d.asBytes,random_a_and_b, 16);
	SendCommand(&d);

	UsbCommand respb;
	if (WaitForResponseTimeout(CMD_ACK,&respb,1500)) {
		uint8_t  isOK  = respb.arg[0] & 0xff;
		uint8_t * data2= respb.d.asBytes;

		if (isOK){
			PrintAndLog("enc(RndA'):%s", sprint_hex(data2+1, 8));
		} else {
			return 2;
		}
		
	} else {
		PrintAndLog("Command execute timeout");
		return 1;
	} 
	return 0;
}
/**
A test function to validate that the polarssl-function works the same 
was as the openssl-implementation. 
Commented out, since it requires openssl 

int CmdTestDES(const char * cmd)
{
	uint8_t key[16] = {0x00};	
	
	memcpy(key,key3_3des_data,16);  
	DES_cblock RndA, RndB;

	PrintAndLog("----------OpenSSL DES implementation----------");
	{
		uint8_t e_RndB[8] = {0x00};
		unsigned char RndARndB[16] = {0x00};

		DES_cblock iv = { 0 };
		DES_key_schedule ks1,ks2;
		DES_cblock key1,key2;

		memcpy(key,key3_3des_data,16);  
		memcpy(key1,key,8);
		memcpy(key2,key+8,8);


		DES_set_key((DES_cblock *)key1,&ks1);
		DES_set_key((DES_cblock *)key2,&ks2);

		DES_random_key(&RndA);
		PrintAndLog("     RndA:%s",sprint_hex(RndA, 8));
		PrintAndLog("     e_RndB:%s",sprint_hex(e_RndB, 8));
		//void DES_ede2_cbc_encrypt(const unsigned char *input,
		//    unsigned char *output, long length, DES_key_schedule *ks1,
		//    DES_key_schedule *ks2, DES_cblock *ivec, int enc);
		DES_ede2_cbc_encrypt(e_RndB,RndB,sizeof(e_RndB),&ks1,&ks2,&iv,0);

		PrintAndLog("     RndB:%s",sprint_hex(RndB, 8));
		rol(RndB,8);
		memcpy(RndARndB,RndA,8);
		memcpy(RndARndB+8,RndB,8);
		PrintAndLog("     RA+B:%s",sprint_hex(RndARndB, 16));
		DES_ede2_cbc_encrypt(RndARndB,RndARndB,sizeof(RndARndB),&ks1,&ks2,&e_RndB,1);
		PrintAndLog("enc(RA+B):%s",sprint_hex(RndARndB, 16));

	}
	PrintAndLog("----------PolarSSL implementation----------");
	{
		uint8_t random_a[8]     = { 0 };
		uint8_t enc_random_a[8] = { 0 };
		uint8_t random_b[8]     = { 0 };
		uint8_t enc_random_b[8] = { 0 };
		uint8_t random_a_and_b[16] = { 0 };
		des3_context ctx        = { 0 };

		memcpy(random_a, RndA,8);

		uint8_t output[8]       = { 0 };
		uint8_t iv[8]           = { 0 };

		PrintAndLog("     RndA  :%s",sprint_hex(random_a, 8));
		PrintAndLog("     e_RndB:%s",sprint_hex(enc_random_b, 8));

		des3_set2key_dec(&ctx, key);

		des3_crypt_cbc(&ctx      // des3_context *ctx
			, DES_DECRYPT        // int mode
			, sizeof(random_b)   // size_t length
			, iv                 // unsigned char iv[8]
			, enc_random_b       // const unsigned char *input
			, random_b           // unsigned char *output
			);

		PrintAndLog("     RndB:%s",sprint_hex(random_b, 8));

		rol(random_b,8);
		memcpy(random_a_and_b  ,random_a,8);
		memcpy(random_a_and_b+8,random_b,8);
		
		PrintAndLog("     RA+B:%s",sprint_hex(random_a_and_b, 16));

		des3_set2key_enc(&ctx, key);

		des3_crypt_cbc(&ctx          // des3_context *ctx
			, DES_ENCRYPT            // int mode
			, sizeof(random_a_and_b)   // size_t length
			, enc_random_b           // unsigned char iv[8]
			, random_a_and_b         // const unsigned char *input
			, random_a_and_b         // unsigned char *output
			);

		PrintAndLog("enc(RA+B):%s",sprint_hex(random_a_and_b, 16));
	}
	return 0;	
}
**/
//
// Ultralight C Read Single Block
//
int CmdHF14AMfUCRdBl(const char *Cmd)
{
	uint8_t blockNo = -1;
	char cmdp = param_getchar(Cmd, 0);
	
	if (strlen(Cmd) < 1 || cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  hf mfu crdbl  <block number>");
		PrintAndLog("        sample: hf mfu crdbl 0");
		return 0;
	}       
		
	blockNo = param_get8(Cmd, 0);
	if (blockNo < 0) {
		PrintAndLog("Wrong block number");
		return 1;
	}
	
	if (blockNo > MAX_ULTRAC_BLOCKS ){
		PrintAndLog("Error: Maximum number of readable blocks is 47 for Ultralight-C Cards!");
		return 1;
	} 
	
	PrintAndLog("--block no: 0x%02X (%d)", (int)blockNo, blockNo);

	//Read Block
	UsbCommand e = {CMD_MIFAREU_READBL, {blockNo}};
	SendCommand(&e);
	UsbCommand resp_c;
	if (WaitForResponseTimeout(CMD_ACK,&resp_c,1500)) {
		uint8_t isOK = resp_c.arg[0] & 0xff;
		uint8_t *data = resp_c.d.asBytes;
		
		PrintAndLog("isOk: %02x", isOK);
		if (isOK)
			PrintAndLog("Data: %s", sprint_hex(data, 4));
			
	} else {
		PrintAndLog("Command execute timeout");
	}
	return 0;
}

//
//  Mifare Ultralight C Write Single Block
//
int CmdHF14AMfUCWrBl(const char *Cmd){
	
	uint8_t blockNo = -1;
	bool chinese_card = FALSE;
	uint8_t bldata[16] = {0x00};
	UsbCommand resp;

	char cmdp = param_getchar(Cmd, 0);
	
	if (strlen(Cmd) < 3 || cmdp == 'h' || cmdp == 'H') {	
		PrintAndLog("Usage:  hf mfu cwrbl <block number> <block data (8 hex symbols)> [w]");
		PrintAndLog("       [block number]");
		PrintAndLog("       [block data] - (8 hex symbols)");
		PrintAndLog("       [w] - Chinese magic ultralight tag");
		PrintAndLog("");
		PrintAndLog("        sample: hf mfu cwrbl 0 01020304");
		PrintAndLog("");
		return 0;
	}
	
	blockNo = param_get8(Cmd, 0);
	if (blockNo > MAX_ULTRAC_BLOCKS ){
		PrintAndLog("Error: Maximum number of blocks is 47 for Ultralight-C Cards!");
		return 1;
	}
	
	if (param_gethex(Cmd, 1, bldata, 8)) {
		PrintAndLog("Block data must include 8 HEX symbols");
		return 1;
	}
	
	if (strchr(Cmd,'w') != 0  || strchr(Cmd,'W') != 0 ) {
		chinese_card = TRUE; 
	}
	
	if ( blockNo <= 3 ) {
		if (!chinese_card){
			 PrintAndLog("Access Denied");  
		} else {
			PrintAndLog("--Special block no: 0x%02x", blockNo);
			PrintAndLog("--Data: %s", sprint_hex(bldata, 4));
			UsbCommand d = {CMD_MIFAREU_WRITEBL, {blockNo}};
			memcpy(d.d.asBytes,bldata, 4);
			SendCommand(&d);
			if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
				uint8_t isOK  = resp.arg[0] & 0xff;
				PrintAndLog("isOk:%02x", isOK);
			} else {
				PrintAndLog("Command execute timeout");
			}  
		}	
	} else {
			PrintAndLog("--Block no : 0x%02x", blockNo);
			PrintAndLog("--Data: %s", sprint_hex(bldata, 4));        	
			UsbCommand e = {CMD_MIFAREU_WRITEBL, {blockNo}};
			memcpy(e.d.asBytes,bldata, 4);
			SendCommand(&e);
			if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
				uint8_t isOK  = resp.arg[0] & 0xff;
				PrintAndLog("isOk : %02x", isOK);
			} else {
				PrintAndLog("Command execute timeout");
			}
	}
	return 0;
}

//------------------------------------
// Menu Stuff
//------------------------------------
static command_t CommandTable[] =
{
	{"help",	CmdHelp,			1,"This help"},
	{"dbg",		CmdHF14AMfDbg,		0,"Set default debug mode"},
	{"info",	CmdHF14AMfUInfo,	0,"Taginfo"},
	{"dump",	CmdHF14AMfUDump,	0,"Dump MIFARE Ultralight / Ultralight-C tag to binary file"},
	{"rdbl",	CmdHF14AMfURdBl,	0,"Read block - MIFARE Ultralight"},
	{"wrbl",	CmdHF14AMfUWrBl,	0,"Write block - MIFARE Ultralight"},    
	{"crdbl",	CmdHF14AMfUCRdBl,	0,"Read block - MIFARE Ultralight C"},
	{"cwrbl",	CmdHF14AMfUCWrBl,	0,"Write MIFARE Ultralight C block"},   
	{"cauth",	CmdHF14AMfucAuth,	0,"try a Ultralight C Authentication"},
	//{"testdes", CmdTestDES ,        1, "Test DES"},
	{NULL, NULL, 0, NULL}
};

int CmdHFMFUltra(const char *Cmd){
	WaitForResponseTimeout(CMD_ACK,NULL,100);
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd){
	CmdsHelp(CommandTable);
	return 0;
}