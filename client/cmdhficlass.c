//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>, Hagen Fritsch
// Copyright (C) 2011 Gerhard de Koning Gans
// Copyright (C) 2014 Midnitesnake & Andy Davies & Martin Holst Swende
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency iClass commands
//-----------------------------------------------------------------------------

#include "cmdhficlass.h"

#define NUM_CSNS 9
#define ICLASS_KEYS_MAX 8

static int CmdHelp(const char *Cmd);

static uint8_t iClass_Key_Table[ICLASS_KEYS_MAX][8] = {
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }
};

int usage_hf_iclass_sim(void) {
	PrintAndLogEx(NORMAL, "Usage:  hf iclass sim <option> [CSN]");
	PrintAndLogEx(NORMAL, "        options");
	PrintAndLogEx(NORMAL, "                0 <CSN> simulate the given CSN");
	PrintAndLogEx(NORMAL, "                1       simulate default CSN");
	PrintAndLogEx(NORMAL, "                2       Reader-attack, gather reader responses to extract elite key");
	PrintAndLogEx(NORMAL, "                3       Full simulation using emulator memory (see 'hf iclass eload')");
	PrintAndLogEx(NORMAL, "                4       Reader-attack, adapted for KeyRoll mode, gather reader responses to extract elite key");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        hf iclass sim 0 031FEC8AF7FF12E0");
	PrintAndLogEx(NORMAL, "        hf iclass sim 2");
	PrintAndLogEx(NORMAL, "        hf iclass eload 'tagdump.bin'");
	PrintAndLogEx(NORMAL, "        hf iclass sim 3");
	PrintAndLogEx(NORMAL, "        hf iclass sim 4");
	return 0;
}
int usage_hf_iclass_eload(void) {
	PrintAndLogEx(NORMAL, "Loads iclass tag-dump into emulator memory on device");
	PrintAndLogEx(NORMAL, "Usage:  hf iclass eload f <filename>");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        hf iclass eload f iclass_tagdump-aa162d30f8ff12f1.bin");
	return 0;
}
int usage_hf_iclass_decrypt(void) {
	PrintAndLogEx(NORMAL, "This is simple implementation, it tries to decrypt every block after block 6.");
	PrintAndLogEx(NORMAL, "Correct behaviour would be to decrypt only the application areas where the key is valid,");
	PrintAndLogEx(NORMAL, "which is defined by the configuration block.");
	PrintAndLogEx(NORMAL, "OBS! In order to use this function, the file 'iclass_decryptionkey.bin' must reside");
	PrintAndLogEx(NORMAL, "in the working directory. The file should be 16 bytes binary data");
	PrintAndLogEx(NORMAL, "");	
	PrintAndLogEx(NORMAL, "Usage: hf iclass decrypt f <tagdump>");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "S       hf iclass decrypt f tagdump_12312342343.bin");
	return 0;
}
int usage_hf_iclass_encrypt(void) {
	PrintAndLogEx(NORMAL, "OBS! In order to use this function, the file 'iclass_decryptionkey.bin' must reside");
	PrintAndLogEx(NORMAL, "in the working directory. The file should be 16 bytes binary data");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Usage: hf iclass encrypt <BlockData>");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        hf iclass encrypt 0102030405060708");
	PrintAndLogEx(NORMAL, "");
	return 0;
}
int usage_hf_iclass_dump(void) {
	PrintAndLogEx(NORMAL, "Usage:  hf iclass dump f <fileName> k <key> c <creditkey> [e|r|v]\n");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "  f <filename> : specify a filename to save dump to");
	PrintAndLogEx(NORMAL, "  k <key>      : <required> access Key as 16 hex symbols or 1 hex to select key from memory");
	PrintAndLogEx(NORMAL, "  c <creditkey>: credit key as 16 hex symbols or 1 hex to select key from memory");
	PrintAndLogEx(NORMAL, "  e            : elite computations applied to key");
	PrintAndLogEx(NORMAL, "  r            : raw, the key is interpreted as raw block 3/4");
	PrintAndLogEx(NORMAL, "  v            : verbose output");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        hf iclass dump k 001122334455667B");
	PrintAndLogEx(NORMAL, "        hf iclass dump k AAAAAAAAAAAAAAAA c 001122334455667B");
	PrintAndLogEx(NORMAL, "        hf iclass dump k AAAAAAAAAAAAAAAA e");
	return 0;
}
int usage_hf_iclass_clone(void) {
	PrintAndLogEx(NORMAL, "Usage:  hf iclass clone f <tagfile.bin> b <first block> l <last block> k <KEY> c e|r");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "  f <filename>: specify a filename to clone from");
	PrintAndLogEx(NORMAL, "  b <Block>   : The first block to clone as 2 hex symbols");
	PrintAndLogEx(NORMAL, "  l <Last Blk>: Set the Data to write as 16 hex symbols");
	PrintAndLogEx(NORMAL, "  k <Key>     : Access Key as 16 hex symbols or 1 hex to select key from memory");
	PrintAndLogEx(NORMAL, "  c           : If 'c' is specified, the key set is assumed to be the credit key\n");
	PrintAndLogEx(NORMAL, "  e           : If 'e' is specified, elite computations applied to key");
	PrintAndLogEx(NORMAL, "  r           : If 'r' is specified, no computations applied to key");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "       hf iclass clone f iclass_tagdump-121345.bin b 06 l 1A k 1122334455667788 e");
	PrintAndLogEx(NORMAL, "       hf iclass clone f iclass_tagdump-121345.bin b 05 l 19 k 0");
	PrintAndLogEx(NORMAL, "       hf iclass clone f iclass_tagdump-121345.bin b 06 l 19 k 0 e");
	return 0;
}
int usage_hf_iclass_writeblock(void) {
	PrintAndLogEx(NORMAL, "Usage:  hf iclass writeblk b <block> d <data> k <key> [c|e|r|v]\n");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "  b <Block> : The block number as 2 hex symbols");
	PrintAndLogEx(NORMAL, "  d <data>  : set the Data to write as 16 hex symbols");
	PrintAndLogEx(NORMAL, "  k <Key>   : access Key as 16 hex symbols or 1 hex to select key from memory");
	PrintAndLogEx(NORMAL, "  c         : credit key assumed\n");
	PrintAndLogEx(NORMAL, "  e         : elite computations applied to key");
	PrintAndLogEx(NORMAL, "  r         : raw, no computations applied to key");
	PrintAndLogEx(NORMAL, "  v         : verbose output");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        hf iclass writeblk b 0A d AAAAAAAAAAAAAAAA k 001122334455667B");
	PrintAndLogEx(NORMAL, "        hf iclass writeblk b 1B d AAAAAAAAAAAAAAAA k 001122334455667B c");
	return 0;
}
int usage_hf_iclass_readblock(void) {
	PrintAndLogEx(NORMAL, "Usage:  hf iclass readblk b <block> k <key> [c|e|r|v]\n");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "  b <block> : The block number as 2 hex symbols");
	PrintAndLogEx(NORMAL, "  k <key>   : Access Key as 16 hex symbols or 1 hex to select key from memory");
	PrintAndLogEx(NORMAL, "  c         : credit key assumed\n");
	PrintAndLogEx(NORMAL, "  e         : elite computations applied to key");
	PrintAndLogEx(NORMAL, "  r         : raw, no computations applied to key");
	PrintAndLogEx(NORMAL, "  v         : verbose output");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        hf iclass readblk b 06 k 0011223344556677");
	PrintAndLogEx(NORMAL, "        hf iclass readblk b 1B k 0011223344556677 c");
	PrintAndLogEx(NORMAL, "        hf iclass readblk b 0A k 0");
	return 0;
}
int usage_hf_iclass_readtagfile() {
	PrintAndLogEx(NORMAL, "Usage: hf iclass readtagfile <filename> [startblock] [endblock]");
	return 0;
}
int usage_hf_iclass_calc_newkey(void) {
	PrintAndLogEx(NORMAL, "Calculate new key for updating\n");
	PrintAndLogEx(NORMAL, "Usage:  hf iclass calc_newkey o <Old key> n <New key> s [csn] e");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "  o <oldkey> : *specify a key as 16 hex symbols or a key number as 1 symbol");
	PrintAndLogEx(NORMAL, "  n <newkey> : *specify a key as 16 hex symbols or a key number as 1 symbol");
	PrintAndLogEx(NORMAL, "  s <csn>    : specify a card Serial number to diversify the key (if omitted will attempt to read a csn)");
	PrintAndLogEx(NORMAL, "  e          : specify new key as elite calc");
	PrintAndLogEx(NORMAL, "  ee         : specify old and new key as elite calc");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, " e key to e key given csn  : hf iclass calcnewkey o 1122334455667788 n 2233445566778899 s deadbeafdeadbeaf ee");
	PrintAndLogEx(NORMAL, " std key to e key read csn : hf iclass calcnewkey o 1122334455667788 n 2233445566778899 e");
	PrintAndLogEx(NORMAL, " std to std read csn       : hf iclass calcnewkey o 1122334455667788 n 2233445566778899");
	PrintAndLogEx(NORMAL, "\nNOTE: * = required\n");
	return 0;
}
int usage_hf_iclass_managekeys(void) {
	PrintAndLogEx(NORMAL, "HELP :  Manage iClass Keys in client memory:\n");
	PrintAndLogEx(NORMAL, "Usage:  hf iclass managekeys n [keynbr] k [key] f [filename] s l p\n");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "  n <keynbr>  : specify the keyNbr to set in memory");
	PrintAndLogEx(NORMAL, "  k <key>     : set a key in memory");
	PrintAndLogEx(NORMAL, "  f <filename>: specify a filename to use with load or save operations");
	PrintAndLogEx(NORMAL, "  s           : save keys in memory to file specified by filename");
	PrintAndLogEx(NORMAL, "  l           : load keys to memory from file specified by filename");
	PrintAndLogEx(NORMAL, "  p           : print keys loaded into memory\n");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, " set key      : hf iclass managekeys n 0 k 1122334455667788");
	PrintAndLogEx(NORMAL, " save key file: hf iclass managekeys f mykeys.bin s");
	PrintAndLogEx(NORMAL, " load key file: hf iclass managekeys f mykeys.bin l");
	PrintAndLogEx(NORMAL, " print keys   : hf iclass managekeys p\n");
	return 0;
}
int usage_hf_iclass_reader(void) {
	PrintAndLogEx(NORMAL, "Act as a Iclass reader.  Look for iClass tags until a key or the pm3 button is pressed\n");
	PrintAndLogEx(NORMAL, "Usage:  hf iclass reader [h] [1]\n");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "    h   This help text");
	PrintAndLogEx(NORMAL, "    1   read only 1 tag");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        hf iclass reader 1");
	return 0;
}
int usage_hf_iclass_replay(void) {
	PrintAndLogEx(NORMAL, "Replay a collected mac message");
	PrintAndLogEx(NORMAL, "Usage:  hf iclass replay [h] <mac>");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "    h       This help text");
	PrintAndLogEx(NORMAL, "    <mac>   Mac bytes to replay (8 hexsymbols)");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        hf iclass replay 00112233");	
	return 0;
}
int usage_hf_iclass_sniff(void) {
	PrintAndLogEx(NORMAL, "Sniff the communication between reader and tag");
	PrintAndLogEx(NORMAL, "Usage:  hf iclass sniff [h]");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "		 hf iclass sniff");	
	return 0;
}
int usage_hf_iclass_loclass(void) {
	PrintAndLogEx(NORMAL, "Usage: hf iclass loclass [options]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "h             Show this help");
	PrintAndLogEx(NORMAL, "t             Perform self-test");
	PrintAndLogEx(NORMAL, "f <filename>  Bruteforce iclass dumpfile");
	PrintAndLogEx(NORMAL, "                   An iclass dumpfile is assumed to consist of an arbitrary number of");
	PrintAndLogEx(NORMAL, "                   malicious CSNs, and their protocol responses");
	PrintAndLogEx(NORMAL, "                   The binary format of the file is expected to be as follows: ");
	PrintAndLogEx(NORMAL, "                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
	PrintAndLogEx(NORMAL, "                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
	PrintAndLogEx(NORMAL, "                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
	PrintAndLogEx(NORMAL, "                  ... totalling N*24 bytes");
	return 0;
}
int usage_hf_iclass_chk(void) {
	PrintAndLogEx(NORMAL, "Checkkeys loads a dictionary text file with 8byte hex keys to test authenticating against a iClass tag");	
	PrintAndLogEx(NORMAL, "Usage: hf iclass chk [h|e|r] [f  (*.dic)]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h             Show this help");
	PrintAndLogEx(NORMAL, "      f <filename>  Dictionary file with default iclass keys");
	PrintAndLogEx(NORMAL, "      r             raw");
	PrintAndLogEx(NORMAL, "      e             elite");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "		 hf iclass chk f default_iclass_keys.dic");	
	PrintAndLogEx(NORMAL, "		 hf iclass chk f default_iclass_keys.dic e");
	return 0;
}
int usage_hf_iclass_lookup(void) {
	PrintAndLogEx(NORMAL, "Lookup keys takes some sniffed trace data and tries to verify what key was used against a dictionary file");	
	PrintAndLogEx(NORMAL, "Usage: hf iclass lookup [h|e|r] [f  (*.dic)] [u <csn>] [p <epurse>] [m <macs>]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h             Show this help");
	PrintAndLogEx(NORMAL, "      f <filename>  Dictionary file with default iclass keys");
	PrintAndLogEx(NORMAL, "      u             CSN");
	PrintAndLogEx(NORMAL, "      p             EPURSE");
	PrintAndLogEx(NORMAL, "      m             macs");
	PrintAndLogEx(NORMAL, "      r             raw");
	PrintAndLogEx(NORMAL, "      e             elite");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        hf iclass lookup u 9655a400f8ff12e0 p f0ffffffffffffff m 0000000089cb984b f default_iclass_keys.dic");
	PrintAndLogEx(NORMAL, "        hf iclass lookup u 9655a400f8ff12e0 p f0ffffffffffffff m 0000000089cb984b f default_iclass_keys.dic e");
	return 0;
}
int usage_hf_iclass_permutekey(void){
	PrintAndLogEx(NORMAL, "Permute function from 'heart of darkness' paper.");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Usage:  hf iclass permute [h] <r|f> <bytes>");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "           h          This help");
	PrintAndLogEx(NORMAL, "           r          reverse permuted key");
	PrintAndLogEx(NORMAL, "           f          permute key");
	PrintAndLogEx(NORMAL, "           <bytes>    input bytes");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "      hf iclass permute r 0123456789abcdef");
	return 0;
}

int xorbits_8(uint8_t val) {
	uint8_t res = val ^ (val >> 1); //1st pass
	res = res ^ (res >> 1); 		// 2nd pass
	res = res ^ (res >> 2); 		// 3rd pass
	res = res ^ (res >> 4); 			// 4th pass
	return res & 1;
}

int CmdHFiClassList(const char *Cmd) {
	//PrintAndLogEx(NORMAL, "Deprecated command, use 'hf list iclass' instead");
	CmdTraceList("iclass");
	return 0;
}

int CmdHFiClassSniff(const char *Cmd) {
	char cmdp = param_getchar(Cmd, 0);
	if (cmdp == 'h' || cmdp == 'H')	return usage_hf_iclass_sniff();
	UsbCommand c = {CMD_SNOOP_ICLASS};
	SendCommand(&c);
	return 0;
}

int CmdHFiClassSim(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd)<1 || cmdp == 'H' || cmdp == 'h') return usage_hf_iclass_sim();

	uint8_t simType = 0;
	uint8_t CSN[8] = {0, 0, 0, 0, 0, 0, 0, 0};

	simType = param_get8ex(Cmd, 0, 0, 10);

	if (simType == 0) {
		if (param_gethex(Cmd, 1, CSN, 16)) {
			PrintAndLogEx(WARNING, "A CSN should consist of 16 HEX symbols");
			return usage_hf_iclass_sim();
		}
		PrintAndLogEx(NORMAL, "--simtype:%02x csn:%s", simType, sprint_hex(CSN, 8));
	}

	if (simType > 4) {
		PrintAndLogEx(WARNING, "Undefined simptype %d", simType);
		return usage_hf_iclass_sim();
	}

	uint8_t numberOfCSNs = 0;
	
/*
		// pre-defined 8 CSN by Holiman
		uint8_t csns[8*NUM_CSNS] = {		
			0x00, 0x0B, 0x0F, 0xFF, 0xF7, 0xFF, 0x12, 0xE0, 
			0x00, 0x13, 0x94, 0x7E, 0x76, 0xFF, 0x12, 0xE0, 
			0x2A, 0x99, 0xAC, 0x79, 0xEC, 0xFF, 0x12, 0xE0,	
			0x17, 0x12, 0x01, 0xFD, 0xF7, 0xFF, 0x12, 0xE0, 
			0xCD, 0x56, 0x01, 0x7C, 0x6F, 0xFF, 0x12, 0xE0, 
			0x4B, 0x5E, 0x0B, 0x72, 0xEF, 0xFF, 0x12, 0xE0, 
			0x00, 0x73, 0xD8, 0x75, 0x58, 0xFF, 0x12, 0xE0, 
			0x0C, 0x90, 0x32, 0xF3, 0x5D, 0xFF, 0x12, 0xE0  
		};
*/
/*
		pre-defined 9 CSN by iceman		
		only one csn depend on several others. 
		six depends only on the first csn,  (0,1, 0x45)
*/
		uint8_t csns[8*NUM_CSNS] = {
			0x01, 0x0A, 0x0F, 0xFF, 0xF7, 0xFF, 0x12, 0xE0, 
			0x0C, 0x06, 0x0C, 0xFE, 0xF7, 0xFF, 0x12, 0xE0, 
			0x10, 0x97, 0x83, 0x7B, 0xF7, 0xFF, 0x12, 0xE0, 
			0x13, 0x97, 0x82, 0x7A, 0xF7, 0xFF, 0x12, 0xE0, 
			0x07, 0x0E, 0x0D, 0xF9, 0xF7, 0xFF, 0x12, 0xE0, 
			0x14, 0x96, 0x84, 0x76, 0xF7, 0xFF, 0x12, 0xE0, 
			0x17, 0x96, 0x85, 0x71, 0xF7, 0xFF, 0x12, 0xE0, 
			0xCE, 0xC5, 0x0F, 0x77, 0xF7, 0xFF, 0x12, 0xE0,
			0xD2, 0x5A, 0x82, 0xF8, 0xF7, 0xFF, 0x12, 0xE0
			//0x04, 0x08, 0x9F, 0x78, 0x6E, 0xFF, 0x12, 0xE0
		};
/*
		// pre-defined 15 CSN by Carl55
		// remember to change the define NUM_CSNS to match.
		uint8_t csns[8*NUM_CSNS] = {
			0x00, 0x0B, 0x0F, 0xFF, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x04, 0x0E, 0x08, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x09, 0x0D, 0x05, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x0A, 0x0C, 0x06, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x0F, 0x0B, 0x03, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x08, 0x0A, 0x0C, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x0D, 0x09, 0x09, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x0E, 0x08, 0x0A, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x03, 0x07, 0x17, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x3C, 0x06, 0xE0, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x01, 0x05, 0x1D, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x02, 0x04, 0x1E, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x07, 0x03, 0x1B, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x00, 0x02, 0x24, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x05, 0x01, 0x21, 0xF7, 0xFF, 0x12, 0xE0 
		};		
*/
	
/* DUMPFILE FORMAT:
 *
 * <8-byte CSN><8-byte CC><4 byte NR><4 byte MAC>....
 * So, it should wind up as
 * 8 * 24 bytes.
 *
 * The returndata from the pm3 is on the following format
 * <4 byte NR><4 byte MAC>
 * CC are all zeroes, CSN is the same as was sent in
 **/
	uint8_t tries = 0;
			
	switch(simType) {
		
		case 2: {
			PrintAndLogEx(INFO, "Starting iCLASS sim 2 attack (elite mode)");
			PrintAndLogEx(INFO, "press keyboard to cancel");
			UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType, NUM_CSNS}};
			UsbCommand resp = {0};
			memcpy(c.d.asBytes, csns, 8 * NUM_CSNS);
			clearCommandBuffer();
			SendCommand(&c);
			
			while ( !WaitForResponseTimeout(CMD_ACK, &resp, 2000) ) {
				tries++;
				if (ukbhit()) {
					int gc = getchar(); (void)gc;
					PrintAndLogEx(WARNING, "\naborted via keyboard.");
					return 0;
				}
				if ( tries > 20) {
					PrintAndLogEx(WARNING, "\ntimeout while waiting for reply.");
					return 0;
				}
			}
			uint8_t num_mac  = resp.arg[1];
			bool success = ( NUM_CSNS == num_mac );
			PrintAndLogEx(NORMAL, "[%c] %d out of %d MAC obtained [%s]", (success) ? '+':'!', num_mac, NUM_CSNS, (success) ? "OK" : "FAIL");

			if ( num_mac == 0 )
				break;
			
			size_t datalen = NUM_CSNS * 24;
			void* dump = malloc(datalen);
			if ( !dump ) {
				PrintAndLogEx(WARNING, "Failed to allocate memory");
				return 2;
			}
			
			memset(dump, 0, datalen);//<-- Need zeroes for the EPURSE - field (offical)
			
			uint8_t i = 0;
			for (i = 0 ; i < NUM_CSNS ; i++) {
				//copy CSN 
				memcpy(dump + i*24, csns + i*8, 8);
				//copy epurse
				memcpy(dump + i*24 + 8, resp.d.asBytes + i*16, 8);
				// NR_MAC (eight bytes from the response)  ( 8b csn + 8b epurse == 16)
				memcpy(dump + i*24 + 16, resp.d.asBytes + i*16 + 8, 8);
			}
			/** Now, save to dumpfile **/
			saveFile("iclass_mac_attack", "bin", dump, datalen);
			free(dump);			
			break;
		}
		case 4: {
			// reader in key roll mode,  when it has two keys it alternates when trying to verify.
			PrintAndLogEx(INFO, "Starting iCLASS sim 4 attack (elite mode, reader in key roll mode)");
			PrintAndLogEx(INFO, "press keyboard to cancel");
			UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType, NUM_CSNS}};
			UsbCommand resp = {0};
			memcpy(c.d.asBytes, csns, 8*NUM_CSNS);
			clearCommandBuffer();
			SendCommand(&c);

			while ( !WaitForResponseTimeout(CMD_ACK, &resp, 2000) ) {
				tries++;
				if (ukbhit()) {
					int gc = getchar(); (void)gc;
					PrintAndLogEx(WARNING, "\naborted via keyboard.");
					return 0;
				}
				if ( tries > 20) {
					PrintAndLogEx(WARNING, "\ntimeout while waiting for reply.");
					return 0;
				}
			}
			uint8_t num_mac = resp.arg[1];
			bool success = ( (NUM_CSNS * 2) == num_mac );
			PrintAndLogEx(NORMAL, "[%c] %d out of %d MAC obtained [%s]", (success) ? '+':'!', num_mac, NUM_CSNS*2, (success) ? "OK" : "FAIL");

			if ( num_mac == 0 )
				break;
			
			size_t datalen = NUM_CSNS * 24;
			void* dump = malloc(datalen);
			if ( !dump ) {
				PrintAndLogEx(WARNING, "Failed to allocate memory");
				return 2;
			}
			
			#define MAC_ITEM_SIZE 24
			
			//KEYROLL 1
			//Need zeroes for the CC-field
			memset(dump, 0, datalen);
			for (uint8_t i = 0; i < NUM_CSNS ; i++) {
				// copy CSN
				memcpy(dump + i*MAC_ITEM_SIZE, csns + i*8, 8); //CSN
				// copy EPURSE
				memcpy(dump + i*MAC_ITEM_SIZE + 8, resp.d.asBytes + i * 16, 8);
				// copy NR_MAC (eight bytes from the response)  ( 8b csn + 8b epurse == 16)
				memcpy(dump + i*MAC_ITEM_SIZE + 16, resp.d.asBytes + i * 16 + 8, 8);
			}
			saveFile("iclass_mac_attack_keyroll_A", "bin", dump, datalen);

			//KEYROLL 2
			memset(dump, 0, datalen);
			uint8_t resp_index = 0;
			for (uint8_t i = 0; i < NUM_CSNS; i++) {
				resp_index =  (i + NUM_CSNS) * 16;
				// Copy CSN
				memcpy(dump + i*MAC_ITEM_SIZE, csns + i*8, 8); 
				// copy EPURSE
				memcpy(dump + i*MAC_ITEM_SIZE + 8, resp.d.asBytes + resp_index, 8);
				// copy NR_MAC (eight bytes from the response)  ( 8b csn + 8 epurse == 16)
				memcpy(dump + i*MAC_ITEM_SIZE + 16, resp.d.asBytes + resp_index + 8, 8);
				resp_index++;
			}						
			saveFile("iclass_mac_attack_keyroll_B", "bin", dump, datalen);			
			free(dump);			
			break;
		}		
		case 1:
		case 3:
		default: {
			UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType, numberOfCSNs}};
			memcpy(c.d.asBytes, CSN, 8);
			clearCommandBuffer();
			SendCommand(&c);
			break;
		}		
	}
	return 0;
}

int HFiClassReader(const char *Cmd, bool loop, bool verbose) {
	bool tagFound = false;

	uint32_t flags = FLAG_ICLASS_READER_CSN | FLAG_ICLASS_READER_CC |  FLAG_ICLASS_READER_AIA |
					FLAG_ICLASS_READER_CONF | FLAG_ICLASS_READER_ONLY_ONCE |
					FLAG_ICLASS_READER_ONE_TRY;
					
	UsbCommand c = {CMD_READER_ICLASS, {flags, 0, 0}};
	// loop in client not device - else on windows have a communication error
	UsbCommand resp;
	while (!ukbhit()){
	
		clearCommandBuffer();
		SendCommand(&c);
		if (WaitForResponseTimeout(CMD_ACK,&resp, 4500)) {
			uint8_t readStatus = resp.arg[0] & 0xff;
			uint8_t *data = resp.d.asBytes;

			if (verbose) PrintAndLogEx(NORMAL, "Readstatus:%02x", readStatus);
			// no tag found or button pressed
			if ( (readStatus == 0 && !loop) || readStatus == 0xFF) {
				// abort
				if (verbose) {
					PrintAndLogEx(FAILED, "Quitting..."); 
					DropField();
					return 0;
				}
			}
			if( readStatus & FLAG_ICLASS_READER_CSN){
				PrintAndLogEx(NORMAL, "CSN: %s", sprint_hex(data, 8));
				tagFound = true;
			}
			if (readStatus & FLAG_ICLASS_READER_CC) { 
				PrintAndLogEx(NORMAL, "    CC: %s", sprint_hex(data+16, 8));
			}
			if (readStatus & FLAG_ICLASS_READER_CONF) {
				printIclassDumpInfo(data);
			}
			if (readStatus & FLAG_ICLASS_READER_AIA) {
				bool legacy = ( memcmp( (uint8_t *)(data + 8*5), "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0 );
				PrintAndLogEx(NORMAL, " App IA: %s", sprint_hex(data+8*5, 8));
				PrintAndLogEx(NORMAL, "      : Possible iClass %s", (legacy) ? "(legacy tag)" : "(NOT legacy tag)");
			}

			if (tagFound && !loop) {
				DropField();
				return 1;
			}
		} else {
			if (verbose) 
				PrintAndLogEx(WARNING, "command execute timeout");
		}
		if (!loop) break;
	}
	DropField();
	return 0;
}

int CmdHFiClassReader(const char *Cmd) {	
	char cmdp = param_getchar(Cmd, 0);
	if (cmdp == 'h' || cmdp == 'H') return usage_hf_iclass_reader();
	bool findone = (cmdp == '1') ? false : true;
	return HFiClassReader(Cmd, findone, true);
}

int CmdHFiClassReader_Replay(const char *Cmd) {
	
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd)<1 || cmdp == 'H' || cmdp == 'h') return usage_hf_iclass_replay();
	
	uint8_t readerType = 0;
	uint8_t MAC[4] = {0x00, 0x00, 0x00, 0x00};
	
	if (param_gethex(Cmd, 0, MAC, 8)) {
		PrintAndLogEx(FAILED, "MAC must include 8 HEX symbols");
		return 1;
	}

	UsbCommand c = {CMD_READER_ICLASS_REPLAY, {readerType}};
	memcpy(c.d.asBytes, MAC, 4);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int iclassEmlSetMem(uint8_t *data, int blockNum, int blocksCount) {
	UsbCommand c = {CMD_MIFARE_EML_MEMSET, {blockNum, blocksCount, 0}};
	memcpy(c.d.asBytes, data, blocksCount * 16);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdHFiClassELoad(const char *Cmd) {

	char ctmp = param_getchar(Cmd, 0);
	if (strlen(Cmd)< 1 || ctmp == 'h' || ctmp == 'H') return usage_hf_iclass_eload();
	
	if ( ctmp != 'f' && ctmp != 'F') return usage_hf_iclass_eload();
	
	//File handling and reading
	FILE *f;
	char filename[FILE_PATH_SIZE];
	
	if ( param_getstr(Cmd, 1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE ) {
		PrintAndLogEx(FAILED, "Filename too long");
		return 1;
	}
	
	f = fopen(filename, "rb");
	if ( !f ){
		PrintAndLogEx(FAILED, "File: %s: not found or locked.", filename);
		return 1;
	}
	
	// get filesize in order to malloc memory
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (fsize < 0) 	{
		PrintAndLogDevice(WARNING, "error, when getting filesize");
		fclose(f);
		return 1;
	}

	uint8_t *dump = calloc(fsize, sizeof(uint8_t));
	if (!dump) {
		PrintAndLogDevice(WARNING, "error, cannot allocate memory ");
		fclose(f);
		return 1;
	}
	
	size_t bytes_read = fread(dump, 1, fsize, f);
	fclose(f);

	printIclassDumpInfo(dump);
	//Validate

	if (bytes_read < fsize)	{
		PrintAndLogDevice(WARNING, "error, could only read %d bytes (should be %d)", bytes_read, fsize );
		free(dump);
		return 1;
	}
	//Send to device
	uint32_t bytes_sent = 0;
	uint32_t bytes_remaining  = bytes_read;

	while (bytes_remaining > 0){
		uint32_t bytes_in_packet = MIN(USB_CMD_DATA_SIZE, bytes_remaining);
		UsbCommand c = {CMD_ICLASS_EML_MEMSET, {bytes_sent, bytes_in_packet, 0}};
		memcpy(c.d.asBytes, dump + bytes_sent, bytes_in_packet);
		clearCommandBuffer();
		SendCommand(&c);
		bytes_remaining -= bytes_in_packet;
		bytes_sent += bytes_in_packet;
	}
	free(dump);
	PrintAndLogEx(SUCCESS, "sent %d bytes of data to device emulator memory", bytes_sent);
	return 0;
}

static int readKeyfile(const char *filename, size_t len, uint8_t* buffer) {
	FILE *f = fopen(filename, "rb");
	if (!f) {
		PrintAndLogEx(WARNING, "Failed to read from file '%s'", filename);
		return 1;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);
	size_t bytes_read = fread(buffer, 1, len, f);
	fclose(f);
	
	if (fsize != len) {
		PrintAndLogEx(WARNING, "Warning, file size is %d, expected %d", fsize, len);
		return 1;
	}
	
	if (bytes_read != len) {
		PrintAndLogEx(WARNING, "Warning, could only read %d bytes, expected %d" ,bytes_read, len);
		return 1;
	}
	return 0;
}

int CmdHFiClassDecrypt(const char *Cmd) {

	char opt = param_getchar(Cmd, 0);
	if (strlen(Cmd)<1 || opt == 'h' || opt == 'H') return usage_hf_iclass_decrypt();
	
	uint8_t key[16] = { 0 };
	if (readKeyfile("iclass_decryptionkey.bin", 16, key)) return usage_hf_iclass_decrypt();
	
	PrintAndLogEx(SUCCESS, "decryption key loaded from file");

	//Open the tagdump-file
	FILE *f;
	char filename[FILE_PATH_SIZE];
	if(opt == 'f' && param_getstr(Cmd, 1, filename, sizeof(filename)) > 0) {
		f = fopen(filename, "rb");
		if (!f) {
			PrintAndLogEx(WARNING, "could not find file %s", filename);
			return 1;
		}		
	} else {
		return usage_hf_iclass_decrypt();
	}	

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);
		
	if ( fsize < 0 ) {
		PrintAndLogEx(WARNING, "error, when getting filesize");
		fclose(f);
		return 2;
	}
	
	uint8_t *decrypted = calloc(fsize, sizeof(uint8_t));
	if ( !decrypted ) {
		PrintAndLogEx(WARNING, "Failed to allocate memory");
		fclose(f);
		return 1;
	}
	
	size_t bytes_read = fread(decrypted, 1, fsize, f);
	fclose(f);
	if ( bytes_read == 0) {
		PrintAndLogEx(WARNING, "file reading error");
		free(decrypted);
		return 3;
	}

	picopass_hdr *hdr = (picopass_hdr *)decrypted;
		
	uint8_t mem = hdr->conf.mem_config;
	uint8_t chip = hdr->conf.chip_config;
	uint8_t applimit = hdr->conf.app_limit;
	uint8_t kb = 2;
	uint8_t app_areas = 2;
	uint8_t max_blk = 31;
	getMemConfig(mem, chip, &max_blk, &app_areas, &kb);	
	
	//Use the first block (CSN) for filename
	char outfilename[FILE_PATH_SIZE] = {0};
	snprintf(outfilename, FILE_PATH_SIZE, "iclass_tagdump-%02x%02x%02x%02x%02x%02x%02x%02x-decrypted",
			 hdr->csn[0],hdr->csn[1],hdr->csn[2],hdr->csn[3],
			 hdr->csn[4],hdr->csn[5],hdr->csn[6],hdr->csn[7]);

	// tripledes
	des3_context ctx = { DES_DECRYPT ,{ 0 } };
	des3_set2key_dec( &ctx, key);

	uint8_t enc_dump[8] = {0};
	uint8_t empty[8] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	for(uint16_t blocknum=0; blocknum < applimit; ++blocknum) {
		
		uint8_t idx = blocknum*8;
		memcpy(enc_dump, decrypted + idx, 8);
		
		// block 7 or higher,  and not empty 0xFF
		if(blocknum > 6 &&  memcmp(enc_dump, empty, 8) != 0 ) {
			des3_crypt_ecb(&ctx, enc_dump, decrypted + idx );
		}
	}
	
	saveFile(outfilename, "bin", decrypted, fsize);
	free(decrypted);	
	printIclassDumpContents(decrypted, 1, (fsize/8), fsize);
	return 0;
}

static int iClassEncryptBlkData(uint8_t *blkData) {
	uint8_t key[16] = { 0 };
	if (readKeyfile("iclass_decryptionkey.bin", 16, key)) {
		usage_hf_iclass_encrypt();
		return 1;
	}
	PrintAndLogEx(SUCCESS, "decryption file found");
	uint8_t encryptedData[16];
	uint8_t *encrypted = encryptedData;
	des3_context ctx = { DES_DECRYPT ,{ 0 } };
	des3_set2key_enc( &ctx, key);
	
	des3_crypt_ecb(&ctx, blkData,encrypted);
	memcpy(blkData,encrypted,8);
	return 1;
}

int CmdHFiClassEncryptBlk(const char *Cmd) {
	uint8_t blkData[8] = {0};
	char opt = param_getchar(Cmd, 0);
	if (strlen(Cmd)<1 || opt == 'h' || opt == 'H') return usage_hf_iclass_encrypt();

	//get the bytes to encrypt
	if (param_gethex(Cmd, 0, blkData, 16)) {
		PrintAndLogEx(NORMAL, "BlockData must include 16 HEX symbols");
		return 0;
	}
	if (!iClassEncryptBlkData(blkData)) return 0;

	printvar("encrypted block", blkData, 8);
	return 1;
}

void Calc_wb_mac(uint8_t blockno, uint8_t *data, uint8_t *div_key, uint8_t MAC[4]) {
	uint8_t wb[9];
	wb[0] = blockno;
	memcpy(wb + 1,data,8);
	doMAC_N(wb, sizeof(wb), div_key, MAC);
}

static bool select_only(uint8_t *CSN, uint8_t *CCNR, bool use_credit_key, bool verbose) {
	UsbCommand resp;
	UsbCommand c = {CMD_READER_ICLASS, {0}};
	c.arg[0] = FLAG_ICLASS_READER_ONLY_ONCE | FLAG_ICLASS_READER_CC | FLAG_ICLASS_READER_ONE_TRY;
	
	if (use_credit_key)
		c.arg[0] |= FLAG_ICLASS_READER_CEDITKEY;

	clearCommandBuffer();
	SendCommand(&c);
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 4000)) {
		PrintAndLogEx(WARNING, "command execute timeout");
		return false;
	}

	uint8_t isOK = resp.arg[0] & 0xff;
	uint8_t *data = resp.d.asBytes;

	memcpy(CSN, data, 8);
	
	if (CCNR != NULL) 
		memcpy(CCNR, data+16, 8);
	
	if (isOK > 0 && verbose) {
		PrintAndLogEx(SUCCESS, "CSN  | %s", sprint_hex(CSN, 8));
		PrintAndLogEx(SUCCESS, "CCNR | %s", sprint_hex(CCNR, 8));
	}
	
	if (isOK <= 1){
		PrintAndLogEx(FAILED, "failed to obtain CC! Tag-select is aborting...  (%d)", isOK);
		return false;
	}
	return true;	
}

static bool select_and_auth(uint8_t *KEY, uint8_t *MAC, uint8_t *div_key, bool use_credit_key, bool elite, bool rawkey, bool verbose) {
	uint8_t CSN[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CCNR[12] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	if (!select_only(CSN, CCNR, use_credit_key, verbose)) {
		if (verbose) PrintAndLogEx(FAILED, "selecting tag failed");
		return false;
	}
	//get div_key
	if (rawkey)
		memcpy(div_key, KEY, 8);
	else
		HFiClassCalcDivKey(CSN, KEY, div_key, elite);
	
	if (verbose) PrintAndLogEx(SUCCESS, "authing with %s: %s", rawkey ? "raw key" : "diversified key", sprint_hex(div_key, 8) );

	doMAC(CCNR, div_key, MAC);
	UsbCommand resp;
	UsbCommand d = {CMD_ICLASS_AUTHENTICATION, {0,0,0}};
	memcpy(d.d.asBytes, MAC, 4);
	clearCommandBuffer();
	SendCommand(&d);
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 4000)) {
		if (verbose) PrintAndLogEx(FAILED, "auth command execute timeout");
		return false;
	}
	uint8_t isOK = resp.arg[0] & 0xFF;
	if (!isOK) {
		if (verbose) PrintAndLogEx(FAILED, "authentication error");
		return false;
	}
	return true;
}

int CmdHFiClassReader_Dump(const char *Cmd) {

	uint8_t MAC[4] = {0x00,0x00,0x00,0x00};
	uint8_t div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t c_div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t blockno = 0;
	uint8_t numblks = 0;
	uint8_t maxBlk = 31;
	uint8_t app_areas = 1;
	uint8_t kb = 2;
	uint8_t KEY[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CreditKEY[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t keyNbr = 0;
	uint8_t dataLen = 0;
	uint8_t fileNameLen = 0;
	char filename[FILE_PATH_SIZE] = {0};
	char tempStr[50] = {0};
	bool have_debit_key = false;
	bool have_credit_key = false;
	bool use_credit_key = false;
	bool elite = false;
	bool rawkey = false;
	bool errors = false;
	bool verbose = false;
	uint8_t cmdp = 0;

	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (param_getchar(Cmd, cmdp)) {
		case 'h':
		case 'H':
			return usage_hf_iclass_dump();
		case 'c':
		case 'C':
			have_credit_key = true;
			dataLen = param_getstr(Cmd, cmdp+1, tempStr, sizeof(tempStr));
			if (dataLen == 16) {
				errors = param_gethex(tempStr, 0, CreditKEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(CreditKEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'e':
		case 'E':
			elite = true;
			cmdp++;
			break;
		case 'f':
		case 'F':
			fileNameLen = param_getstr(Cmd, cmdp+1, filename, sizeof(filename)); 
			if (fileNameLen < 1) {
				PrintAndLogEx(WARNING, "no filename found after f");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'k':
		case 'K':
			have_debit_key = true;
			dataLen = param_getstr(Cmd, cmdp+1, tempStr, sizeof(tempStr));
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, KEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(KEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'r':
		case 'R':
			rawkey = true;
			cmdp++;
			break;
		case 'v':
		case 'V':
			verbose = true;
			cmdp++;
			break;				
		default:
			PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	if (errors || cmdp < 2) return usage_hf_iclass_dump();
	
	// if no debit key given try credit key on AA1 (not for iclass but for some picopass this will work)
	if (!have_debit_key && have_credit_key) use_credit_key = true;

	uint32_t flags = FLAG_ICLASS_READER_CSN | FLAG_ICLASS_READER_CC |
					FLAG_ICLASS_READER_CONF | FLAG_ICLASS_READER_ONLY_ONCE |
					FLAG_ICLASS_READER_ONE_TRY;
	
	//get config and first 3 blocks
	UsbCommand c = {CMD_READER_ICLASS, {flags, 0, 0}};					
	UsbCommand resp;
	uint8_t tag_data[255*8];

	clearCommandBuffer();
	SendCommand(&c);
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
		PrintAndLogEx(WARNING, "command execute timeout");
		DropField();
		return 0;
	}
	DropField();
	
	uint8_t readStatus = resp.arg[0] & 0xff;
	uint8_t *data  = resp.d.asBytes;

	if (readStatus == 0){
		PrintAndLogEx(FAILED, "no tag found");
		return 0;
	}
	
	if( readStatus & (FLAG_ICLASS_READER_CSN | FLAG_ICLASS_READER_CONF | FLAG_ICLASS_READER_CC)){
		memcpy(tag_data, data, 8*3);
		blockno += 2; // 2 to force re-read of block 2 later. (seems to respond differently..)
		numblks = data[8];
		getMemConfig(data[13], data[12], &maxBlk, &app_areas, &kb);
		// large memory - not able to dump pages currently
		if (numblks > maxBlk) numblks = maxBlk;
	}
	
	// authenticate debit key and get div_key - later store in dump block 3
	if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose)){
		//try twice - for some reason it sometimes fails the first time...
		PrintAndLogEx(SUCCESS, "retry to select card");
		if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose)){
			PrintAndLogEx(WARNING, "failed authenticating with debit key");
			DropField();
			return 0;
		}
	}
	
	// begin dump
	UsbCommand w = {CMD_ICLASS_DUMP, {blockno, numblks-blockno+1}};
	clearCommandBuffer();
	SendCommand(&w);
	while (true) {
		printf("."); fflush(stdout);
		if (ukbhit()) {
			int gc = getchar(); (void)gc;
			PrintAndLogEx(NORMAL, "\n[!] aborted via keyboard!\n");
			DropField();
			return 0;
		}
		
		if (WaitForResponseTimeout(CMD_ACK, &resp, 2000) )
			break;
	}
	// dump cmd switch off at device when finised.
	
	uint32_t blocksRead = resp.arg[1];
	uint8_t isOK = resp.arg[0] & 0xff;
	if (!isOK && !blocksRead) {
		PrintAndLogEx(WARNING, "read block failed");
		return 0;
	}
	
	uint32_t startindex = resp.arg[2];
	if (blocksRead*8 > sizeof(tag_data) - (blockno*8)) {
		PrintAndLogEx(FAILED, "data exceeded buffer size!");
		blocksRead = (sizeof(tag_data)/8) - blockno;
	}
	
	// response ok - now get bigbuf content of the dump
	if ( !GetFromDevice(BIG_BUF, tag_data+(blockno*8), blocksRead*8, startindex, NULL, 2500, false) ) {
		PrintAndLogEx(WARNING, "command execution time out");
		return 0;
	}
	
	size_t gotBytes = blocksRead*8 + blockno*8;

	// try AA2
	if (have_credit_key) {
		//turn off hf field before authenticating with different key
		DropField();
		memset(MAC,0,4);
		// AA2 authenticate credit key and git c_div_key - later store in dump block 4
		if (!select_and_auth(CreditKEY, MAC, c_div_key, true, elite, rawkey, verbose)){
			//try twice - for some reason it sometimes fails the first time...
			if (!select_and_auth(CreditKEY, MAC, c_div_key, true, elite, rawkey, verbose)){
				PrintAndLogEx(WARNING, "failed authenticating with credit key");
				DropField();
				return 0;
			}
		}
		// do we still need to read more block?  (aa2 enabled?)
		if (maxBlk > blockno+numblks+1) {
			// setup dump and start
			w.arg[0] = blockno + blocksRead;
			w.arg[1] = maxBlk - (blockno + blocksRead);
			clearCommandBuffer();
			SendCommand(&w);
			if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
				PrintAndLogEx(WARNING, "command execute timeout 2");
				return 0;
			}
			uint8_t isOK = resp.arg[0] & 0xff;
			blocksRead = resp.arg[1];
			if (!isOK && !blocksRead) {
				PrintAndLogEx(WARNING, "read block failed 2");
				return 0;
			}		

			startindex = resp.arg[2];
			if (blocksRead * 8 > sizeof(tag_data) - gotBytes) {
				PrintAndLogEx(FAILED, "data exceeded buffer size!");
				blocksRead = (sizeof(tag_data) - gotBytes)/8;
			}
			// get dumped data from bigbuf
			if ( !GetFromDevice(BIG_BUF, tag_data + gotBytes, blocksRead * 8, startindex, NULL, 2500, false)) {
				PrintAndLogEx(WARNING, "command execution time out");
				return 0;
			}

			gotBytes += blocksRead * 8;			
		}
	}

	DropField();
	
	// add diversified keys to dump
	if (have_debit_key) memcpy(tag_data+(3*8),div_key,8);
	if (have_credit_key) memcpy(tag_data+(4*8),c_div_key,8);

	// print the dump
	PrintAndLogEx(NORMAL, "------+--+-------------------------+\n");
	PrintAndLogEx(NORMAL, "CSN   |00| %s|\n", sprint_hex(tag_data, 8));	
	printIclassDumpContents(tag_data, 1, (gotBytes/8), gotBytes);

	if (filename[0] == 0){
		snprintf(filename, FILE_PATH_SIZE,"iclass_tagdump-%02x%02x%02x%02x%02x%02x%02x%02x",
		    tag_data[0],tag_data[1],tag_data[2],tag_data[3],
		    tag_data[4],tag_data[5],tag_data[6],tag_data[7]);
	}

	// save the dump to .bin file
	PrintAndLogEx(SUCCESS, "saving dump file - %d blocks read", gotBytes/8);
	saveFile(filename, "bin", tag_data, gotBytes);
	return 1;
}

static int WriteBlock(uint8_t blockno, uint8_t *bldata, uint8_t *KEY, bool use_credit_key, bool elite, bool rawkey, bool verbose) {
	uint8_t MAC[4] = {0x00,0x00,0x00,0x00};
	uint8_t div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose))
		return 0;

	UsbCommand resp;

	Calc_wb_mac(blockno,bldata,div_key,MAC);
	UsbCommand w = {CMD_ICLASS_WRITEBLOCK, {blockno}};
	memcpy(w.d.asBytes, bldata, 8);
	memcpy(w.d.asBytes + 8, MAC, 4);
	
	clearCommandBuffer();
	SendCommand(&w);
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
		if ( verbose ) PrintAndLogEx(WARNING, "Write Command execute timeout");
		return 0;
	}
	uint8_t isOK = resp.arg[0] & 0xff;
	if (isOK)
		PrintAndLogEx(SUCCESS, "Write block successful");
	else
		PrintAndLogEx(WARNING, "Write block failed");
	return isOK;
}

int CmdHFiClass_WriteBlock(const char *Cmd) {
	uint8_t blockno = 0;
	uint8_t bldata[8] = {0,0,0,0,0,0,0,0};
	uint8_t KEY[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t keyNbr = 0;
	uint8_t dataLen = 0;
	char tempStr[50] = {0};
	bool use_credit_key = false;
	bool elite = false;
	bool rawkey = false;
	bool errors = false;
	bool verbose = false;
	uint8_t cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'h':
		case 'H':
			return usage_hf_iclass_writeblock();
		case 'b':
		case 'B':
			if (param_gethex(Cmd, cmdp+1, &blockno, 2)) {
				PrintAndLogEx(WARNING, "Block No must include 2 HEX symbols\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'c':
		case 'C':
			use_credit_key = true;
			cmdp++;
			break;
		case 'd':
		case 'D':
			if (param_gethex(Cmd, cmdp+1, bldata, 16)) {
				PrintAndLogEx(WARNING, "Data must include 16 HEX symbols\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'e':
		case 'E':
			elite = true;
			cmdp++;
			break;
		case 'k':
		case 'K':
			dataLen = param_getstr(Cmd, cmdp+1, tempStr, sizeof(tempStr));
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, KEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(KEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'r':
		case 'R':
			rawkey = true;
			cmdp++;
			break;
		case 'v':
		case 'V':
			verbose = true;
			cmdp++;
			break;				
		default:
			PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	if (errors || cmdp < 6) return usage_hf_iclass_writeblock();

	int ans = WriteBlock(blockno, bldata, KEY, use_credit_key, elite, rawkey, verbose);
	DropField();
	return ans;
}

int CmdHFiClassCloneTag(const char *Cmd) {
	char filename[FILE_PATH_SIZE] = { 0x00 };
	char tempStr[50] = {0};
	uint8_t KEY[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t keyNbr = 0;
	uint8_t fileNameLen = 0;
	uint8_t startblock = 0;
	uint8_t endblock = 0;
	uint8_t dataLen = 0;
	bool use_credit_key = false;
	bool elite = false;
	bool rawkey = false;
	bool errors = false;
	bool verbose = false;
	uint8_t cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'h':
		case 'H':
			return usage_hf_iclass_clone();
		case 'b':
		case 'B':
			if (param_gethex(Cmd, cmdp+1, &startblock, 2)) {
				PrintAndLogEx(WARNING, "start block No must include 2 HEX symbols\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'c':
		case 'C':
			use_credit_key = true;
			cmdp++;
			break;
		case 'e':
		case 'E':
			elite = true;
			cmdp++;
			break;
		case 'f':
		case 'F':
			fileNameLen = param_getstr(Cmd, cmdp+1, filename, sizeof(filename)); 
			if (fileNameLen < 1) {
				PrintAndLogEx(WARNING, "No filename found after f");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'k':
		case 'K':
			dataLen = param_getstr(Cmd, cmdp+1, tempStr, sizeof(tempStr));
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, KEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(KEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'l':
		case 'L':
			if (param_gethex(Cmd, cmdp+1, &endblock, 2)) {
				PrintAndLogEx(WARNING, "start Block No must include 2 HEX symbols\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'r':
		case 'R':
			rawkey = true;
			cmdp++;
			break;
		case 'v':
		case 'V':
			verbose = true;
			cmdp++;
			break;	
		default:
			PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}

	if (errors || cmdp < 8) return usage_hf_iclass_clone();

	FILE *f;

	iclass_block_t tag_data[USB_CMD_DATA_SIZE/12];

	if ((endblock-startblock+1)*12 > USB_CMD_DATA_SIZE) {
		PrintAndLogEx(NORMAL, "Trying to write too many blocks at once.  Max: %d", USB_CMD_DATA_SIZE/8);
	}
	// file handling and reading
	f = fopen(filename,"rb");
	if(!f) {
		PrintAndLogEx(WARNING, "failed to read file '%s'", filename);
		return 1;
	}

	if (startblock<5) {
		PrintAndLogEx(WARNING, "you cannot write key blocks this way. yet... make your start block > 4");
		fclose(f);	
		return 0;
	}
	// now read data from the file from block 6 --- 19
	// ok we will use this struct [data 8 bytes][MAC 4 bytes] for each block calculate all mac number for each data
	// then copy to usbcommand->asbytes; the max is 32 - 6 = 24 block 12 bytes each block 288 bytes then we can only accept to clone 21 blocks at the time,
	// else we have to create a share memory
	int i;
	fseek(f, startblock*8, SEEK_SET);
	size_t bytes_read = fread(tag_data, sizeof(iclass_block_t),endblock - startblock + 1, f);
	if ( bytes_read == 0){
		PrintAndLogEx(WARNING, "file reading error.");
		fclose(f);
		return 2;
	}

	uint8_t MAC[4] = {0x00,0x00,0x00,0x00};
	uint8_t div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose))
		return 0;

	UsbCommand w = {CMD_ICLASS_CLONE,{startblock,endblock}};
	uint8_t *ptr;
	// calculate all mac for every the block we will write
	for (i = startblock; i <= endblock; i++){
	    Calc_wb_mac(i,tag_data[i - startblock].d,div_key,MAC);
	    // usb command d start pointer = d + (i - 6) * 12
	    // memcpy(pointer,tag_data[i - 6],8) 8 bytes
	    // memcpy(pointer + 8,mac,sizoof(mac) 4 bytes;
	    // next one
	    ptr = w.d.asBytes + (i - startblock) * 12;
	    memcpy(ptr, &(tag_data[i - startblock].d[0]), 8);
	    memcpy(ptr + 8,MAC, 4);
	}
	uint8_t p[12];
	for (i = 0; i <= endblock - startblock;i++){
	    memcpy(p,w.d.asBytes + (i * 12),12);
	    PrintAndLogEx(NORMAL, "Block |%02x|",i + startblock);
	    PrintAndLogEx(NORMAL, " %02x%02x%02x%02x%02x%02x%02x%02x |",p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
	    PrintAndLogEx(NORMAL, " MAC |%02x%02x%02x%02x|\n",p[8],p[9],p[10],p[11]);
	}
	UsbCommand resp;
	clearCommandBuffer();
	SendCommand(&w);
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
		PrintAndLogEx(WARNING, "command execute timeout");
		return 0;
	}
	return 1;
}

static int ReadBlock(uint8_t *KEY, uint8_t blockno, uint8_t keyType, bool elite, bool rawkey, bool verbose, bool auth) {
	uint8_t MAC[4] = {0x00,0x00,0x00,0x00};
	uint8_t div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	// block 0,1 should always be able to read,  and block 5 on some cards.
	if (auth || blockno >= 2) {
		if (!select_and_auth(KEY, MAC, div_key, (keyType == 0x18), elite, rawkey, verbose))
			return 0;
	} else {
		uint8_t CSN[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		uint8_t CCNR[12] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		if (!select_only(CSN, CCNR, (keyType == 0x18), verbose))
			return 0;
	}

	UsbCommand resp;
	UsbCommand c = {CMD_ICLASS_READBLOCK, {blockno}};
	clearCommandBuffer();
	SendCommand(&c);
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
		PrintAndLogEx(WARNING, "Command execute timeout");
		return 0;
	}
	
	uint8_t isOK = resp.arg[0] & 0xff;
	if (!isOK) {
		PrintAndLogEx(WARNING, "read block failed");
		return 0;
	}
	//data read is stored in: resp.d.asBytes[0-15]
	PrintAndLogEx(NORMAL, "block %02X: %s\n", blockno, sprint_hex(resp.d.asBytes, 8));
	return 1;
}

int CmdHFiClass_ReadBlock(const char *Cmd) {
	uint8_t blockno = 0;
	uint8_t keyType = 0x88; //debit key
	uint8_t KEY[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t keyNbr = 0;
	uint8_t dataLen = 0;
	char tempStr[50] = {0};
	bool elite = false;
	bool rawkey = false;
	bool errors = false;
	bool auth = false;
	bool verbose = false;
	uint8_t cmdp = 0;
	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (param_getchar(Cmd, cmdp)) {
		case 'h':
		case 'H':
			return usage_hf_iclass_readblock();
		case 'b':
		case 'B':
			if (param_gethex(Cmd, cmdp+1, &blockno, 2)) {
				PrintAndLogEx(WARNING, "Block No must include 2 HEX symbols\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'c':
		case 'C':
			keyType = 0x18;
			cmdp++;
			break;
		case 'e':
		case 'E':
			elite = true;
			cmdp++;
			break;
		case 'k':
		case 'K':
			auth = true;
			dataLen = param_getstr(Cmd, cmdp+1, tempStr, sizeof(tempStr));
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, KEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(KEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'r':
		case 'R':
			rawkey = true;
			cmdp++;
			break;
		case 'v':
		case 'V':
			verbose = true;
			cmdp++;
			break;			
		default:
			PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	if (errors || cmdp < 4) return usage_hf_iclass_readblock();

	if (!auth)
		PrintAndLogEx(FAILED, "warning: no authentication used with read, only a few specific blocks can be read accurately without authentication.");
	return ReadBlock(KEY, blockno, keyType, elite, rawkey, verbose, auth);
}

int CmdHFiClass_loclass(const char *Cmd) {
	char opt = param_getchar(Cmd, 0);

	if (strlen(Cmd)<1 || opt == 'h')
		usage_hf_iclass_loclass();
	
	char fileName[FILE_PATH_SIZE] = {0};
	if (opt == 'f') {
		if (param_getstr(Cmd, 1, fileName, sizeof(fileName)) > 0) {
			return bruteforceFileNoKeys(fileName);
		} else {
			PrintAndLogEx(WARNING, "You must specify a filename");
			return 0;
		}
	}
	else if (opt == 't') {
		int errors = testCipherUtils();
		errors += testMAC();
		errors += doKeyTests(0);
		errors += testElite();
		if (errors) PrintAndLogDevice(WARNING, "There were errors!!!");
		return errors;
	}
	return 0;
}

void printIclassDumpContents(uint8_t *iclass_dump, uint8_t startblock, uint8_t endblock, size_t filesize) {
	uint8_t mem_config;
	memcpy(&mem_config, iclass_dump + 13,1);
	uint8_t maxmemcount;
	
	uint8_t filemaxblock = filesize / 8;

	if (mem_config & 0x80)
		maxmemcount = 255;
	else
		maxmemcount = 31;

	if (startblock == 0)
		startblock = 6;
	
	if ((endblock > maxmemcount) || (endblock == 0))
		endblock = maxmemcount;
	
	// remember endblock needs to relate to zero-index arrays.
	if (endblock > filemaxblock-1)
		endblock = filemaxblock-1;

	//PrintAndLog	("startblock: %d, endblock: %d, filesize: %d, maxmemcount: %d, filemaxblock: %d",startblock, endblock,filesize, maxmemcount, filemaxblock);
	
	int i = startblock;
	PrintAndLogEx(NORMAL, "------+--+-------------------------+\n");
	while (i <= endblock){
		uint8_t *blk = iclass_dump + (i * 8);
		PrintAndLogEx(NORMAL, "      |%02X| %s\n", i, sprint_hex_ascii(blk, 8) );	
		i++;
	}
	PrintAndLogEx(NORMAL, "------+--+-------------------------+\n");
}

int CmdHFiClassReadTagFile(const char *Cmd) {
	int startblock = 0;
	int endblock = 0;
	char tempnum[5];
	FILE *f;
	char filename[FILE_PATH_SIZE];
	if (param_getstr(Cmd, 0, filename, sizeof(filename)) < 1)
		return usage_hf_iclass_readtagfile();
	
	if (param_getstr(Cmd, 1, tempnum, sizeof(tempnum)) < 1)
		startblock = 0;
	else
		sscanf(tempnum,"%d",&startblock);

	if (param_getstr(Cmd,2, tempnum, sizeof(tempnum)) < 1)
		endblock = 0;
	else
		sscanf(tempnum,"%d",&endblock);
	
	// file handling and reading
	f = fopen(filename,"rb");
	if(!f) {
		PrintAndLogEx(WARNING, "Failed to read from file '%s'", filename);
		return 1;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if ( fsize < 0 ) {
		PrintAndLogEx(WARNING, "Error, when getting filesize");
		fclose(f);
		return 1;
	}

	uint8_t *dump = calloc(fsize, sizeof(uint8_t));
	if ( !dump ) {
		PrintAndLogEx(WARNING, "Failed to allocate memory");
		fclose(f);
		return 1;
	}
	size_t bytes_read = fread(dump, 1, fsize, f);
	fclose(f);
	
	uint8_t *csn = dump;
	PrintAndLogEx(NORMAL, "------+--+-------------------------+\n");
	PrintAndLogEx(NORMAL, "CSN   |00| %s|\n", sprint_hex(csn, 8) );
	printIclassDumpContents(dump, startblock, endblock, bytes_read);
	free(dump);
	return 0;
}

void HFiClassCalcDivKey(uint8_t	*CSN, uint8_t *KEY, uint8_t *div_key, bool elite){
	uint8_t keytable[128] = {0};
	uint8_t key_index[8] = {0};
	if (elite) {
		uint8_t key_sel[8] = { 0 };
		uint8_t key_sel_p[8] = { 0 };
		hash2(KEY, keytable);
		hash1(CSN, key_index);
		for(uint8_t i = 0; i < 8 ; i++)
			key_sel[i] = keytable[key_index[i]] & 0xFF;

		//Permute from iclass format to standard format
		permutekey_rev(key_sel, key_sel_p);
		diversifyKey(CSN, key_sel_p, div_key);	
	} else {
		diversifyKey(CSN, KEY, div_key);
	}		
}

//when told CSN, oldkey, newkey, if new key is elite (elite), and if old key was elite (oldElite)
//calculate and return xor_div_key (ready for a key write command)
//print all div_keys if verbose
static void HFiClassCalcNewKey(uint8_t *CSN, uint8_t *OLDKEY, uint8_t *NEWKEY, uint8_t *xor_div_key, bool elite, bool oldElite, bool verbose){
	uint8_t old_div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t new_div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	//get old div key
	HFiClassCalcDivKey(CSN, OLDKEY, old_div_key, oldElite);
	//get new div key
	HFiClassCalcDivKey(CSN, NEWKEY, new_div_key, elite);
	
	for (uint8_t i = 0; i < sizeof(old_div_key); i++){
		xor_div_key[i] = old_div_key[i] ^ new_div_key[i];
	}
	if (verbose) {
		PrintAndLogEx(SUCCESS, "Old div key : %s\n",sprint_hex(old_div_key,8));
		PrintAndLogEx(SUCCESS, "New div key : %s\n",sprint_hex(new_div_key,8));
		PrintAndLogEx(SUCCESS, "Xor div key : %s\n",sprint_hex(xor_div_key,8));		
	}
}

int CmdHFiClassCalcNewKey(const char *Cmd) {
	uint8_t OLDKEY[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t NEWKEY[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t xor_div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CSN[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CCNR[12] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t keyNbr = 0;
	uint8_t dataLen = 0;
	char tempStr[50] = {0};
	bool givenCSN = false;
	bool oldElite = false;
	bool elite = false;
	bool errors = false;
	uint8_t cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'h':
		case 'H':
			return usage_hf_iclass_calc_newkey();
		case 'e':
		case 'E':
			dataLen = param_getstr(Cmd, cmdp, tempStr, sizeof(tempStr));
			if (dataLen==2)
				oldElite = true;
			elite = true;
			cmdp++;
			break;
		case 'n':
		case 'N':
			dataLen = param_getstr(Cmd, cmdp+1, tempStr, sizeof(tempStr));
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, NEWKEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(NEWKEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLogEx(WARNING, "\nERROR: NewKey Nbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLogEx(WARNING, "\nERROR: NewKey is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'o':
		case 'O':
			dataLen = param_getstr(Cmd, cmdp+1, tempStr, sizeof(tempStr));
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, OLDKEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(OLDKEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 's':
		case 'S':
			givenCSN = true;
			if (param_gethex(Cmd, cmdp+1, CSN, 16))
				return usage_hf_iclass_calc_newkey();
			cmdp += 2;
			break;
		default:
			PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	if (errors || cmdp < 4) return usage_hf_iclass_calc_newkey();
		
	if (!givenCSN)
		if (!select_only(CSN, CCNR, false, true))
			return 0;
	
	HFiClassCalcNewKey(CSN, OLDKEY, NEWKEY, xor_div_key, elite, oldElite, true);
	return 0;
}

static int loadKeys(char *filename) {
	FILE *f;
	f = fopen(filename,"rb");
	if(!f) {
		PrintAndLogEx(WARNING, "Failed to read from file '%s'", filename);
		return 0;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if ( fsize < 0 ) {
		PrintAndLogEx(WARNING, "Error, when getting filesize");
		fclose(f);
		return 1;
	}

	uint8_t *dump = calloc(fsize, sizeof(uint8_t));
	if ( !dump ) {
		PrintAndLogEx(WARNING, "Failed to allocate memory");
		fclose(f);
		return 1;
	}
	size_t bytes_read = fread(dump, 1, fsize, f);
	fclose(f);
	if (bytes_read > ICLASS_KEYS_MAX * 8){
		PrintAndLogEx(WARNING, "File is too long to load - bytes: %u", bytes_read);
		free(dump);
		return 0;
	}
	uint8_t i = 0;
	for (; i < bytes_read/8; i++)
		memcpy(iClass_Key_Table[i],dump+(i*8),8);
	
	free(dump);
	PrintAndLogEx(SUCCESS, "%u keys loaded", i);
	return 1;
}

static int saveKeys(char *filename) {
	FILE *f;
	f = fopen(filename,"wb");
	if (!f) {
		PrintAndLogEx(NORMAL, "[!] error opening file %s\n",filename);
		return 0;
	}
	for (uint8_t i = 0; i < ICLASS_KEYS_MAX; i++){
		if (fwrite(iClass_Key_Table[i],8,1,f) != 1){
			PrintAndLogEx(WARNING, "save key failed to write to file: %s", filename);
			break;
		}
	}
	fclose(f);
	return 0;
}

static int printKeys(void) {
	PrintAndLogEx(NORMAL, "");
	for (uint8_t i = 0; i < ICLASS_KEYS_MAX; i++)
		PrintAndLogEx(NORMAL, "%u: %s", i, sprint_hex(iClass_Key_Table[i],8));
	PrintAndLogEx(NORMAL, "");	
	return 0;
}

int CmdHFiClassManageKeys(const char *Cmd) {
	uint8_t keyNbr = 0;
	uint8_t dataLen = 0;
	uint8_t KEY[8] = {0};
	char filename[FILE_PATH_SIZE];
	uint8_t fileNameLen = 0;
	bool errors = false;
	uint8_t operation = 0;
	char tempStr[20];
	uint8_t cmdp = 0;

	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'h':
		case 'H':
			return usage_hf_iclass_managekeys();
		case 'f':
		case 'F':
			fileNameLen = param_getstr(Cmd, cmdp+1, filename, sizeof(filename)); 
			if (fileNameLen < 1) {
				PrintAndLogEx(WARNING, "No filename found after f");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'n':
		case 'N':
			keyNbr = param_get8(Cmd, cmdp+1);
			if (keyNbr >= ICLASS_KEYS_MAX) {
				PrintAndLogEx(WARNING, "Invalid block number");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'k':
		case 'K':
			operation += 3; //set key 
			dataLen = param_getstr(Cmd, cmdp+1, tempStr, sizeof(tempStr));
			if (dataLen == 16) { //ul-c or ev1/ntag key length
				errors = param_gethex(tempStr, 0, KEY, dataLen);
			} else {
				PrintAndLogEx(WARNING, "\nERROR: Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'p':
		case 'P':
			operation += 4; //print keys in memory
			cmdp++;
			break;
		case 'l':
		case 'L':
			operation += 5; //load keys from file
			cmdp++;
			break;
		case 's':
		case 'S':
			operation += 6; //save keys to file
			cmdp++;
			break;
		default:
			PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	if (errors) return usage_hf_iclass_managekeys();
		
	if (operation == 0){
		PrintAndLogEx(WARNING, "no operation specified (load, save, or print)\n");
		return usage_hf_iclass_managekeys();
	}
	if (operation > 6){
		PrintAndLogEx(WARNING, "Too many operations specified\n");
		return usage_hf_iclass_managekeys();
	}
	if (operation > 4 && fileNameLen == 0){
		PrintAndLogEx(WARNING, "You must enter a filename when loading or saving\n");
		return usage_hf_iclass_managekeys();
	}

	switch (operation){
		case 3: memcpy(iClass_Key_Table[keyNbr], KEY, 8); return 1;
		case 4: return printKeys();
		case 5: return loadKeys(filename);
		case 6: return saveKeys(filename);
		break;
	}
	return 0;
}

int CmdHFiClassCheckKeys(const char *Cmd) {

	uint8_t CSN[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CCNR[12] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		
	// elite key,  raw key, standard key
	bool use_elite = false;
	bool use_raw = false;	
	bool found_debit = false;
	//bool found_credit = false;
	bool got_csn = false;
	bool errors = false;
	uint8_t cmdp = 0x00;

	char filename[FILE_PATH_SIZE] = {0};
	uint8_t fileNameLen = 0;

	uint8_t *keyBlock = NULL;	
	iclass_premac_t *pre = NULL;
	int keycnt = 0;

	// if empty string
	if (strlen(Cmd) == 0) errors = true;

	
	// time
	uint64_t t1 = msclock();
	
	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (param_getchar(Cmd, cmdp)) {
		case 'h':
		case 'H':
			return usage_hf_iclass_chk();
		case 'f':
		case 'F':
			fileNameLen = param_getstr(Cmd, cmdp+1, filename, sizeof(filename)); 
			if (fileNameLen < 1) {
				PrintAndLogEx(WARNING, "no filename found after f");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'e':
		case 'E':
			use_elite = true;
			cmdp++;
			break;
		case 'r':
		case 'R':
			use_raw = true;
			cmdp++;
			break;
		default:
			PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	if (errors) return usage_hf_iclass_chk();	

	
	// Get CSN / UID and CCNR
	PrintAndLogEx(SUCCESS, "Reading tag CSN");
	for (uint8_t i=0; i<10 && !got_csn; i++) {
		if (select_only(CSN, CCNR, false, false)) {
			got_csn = true;
		} else {
			PrintAndLogEx(WARNING, "one more try\n");
		}
	}
	
	if ( !got_csn ) {
		PrintAndLogEx(WARNING, "can't select card, aborting...");
		return 1;
	}

	// load keys into keyblock
	int res = LoadDictionaryKeyFile( filename, &keyBlock, &keycnt);
	if ( res > 0) {
		free(keyBlock);
		return 1;
	}
		
	pre = calloc(keycnt, sizeof(iclass_premac_t));
	if ( !pre ) {
		free(keyBlock);
		return 1;
	}
	
	PrintAndLogEx(SUCCESS, "Generating diversified keys, MAC");
	PrintAndLogEx(SUCCESS, "CSN     | %s", sprint_hex( CSN, sizeof(CSN) ));
	PrintAndLogEx(SUCCESS, "CCNR    | %s", sprint_hex( CCNR, sizeof(CCNR) ));
	res = GenerateMacFromKeyFile( CSN, CCNR, use_raw, use_elite, keyBlock, keycnt, pre );
	if ( res > 0) {
		free(keyBlock);
		free(pre);
		return 1;
	}
	
	PrintPreCalcMac(keyBlock, keycnt, pre);

	// max 42 keys inside USB_COMMAND.  512/4 = 103 mac
	uint32_t chunksize = keycnt > (USB_CMD_DATA_SIZE/4) ? (USB_CMD_DATA_SIZE/4) : keycnt;
	bool lastChunk = false;

	// main keychunk loop	
	for (uint32_t i = 0; i < keycnt; i += chunksize) {
		
		uint64_t t2 = msclock();
		uint8_t timeout = 0;
		
		if (ukbhit()) {
			int gc = getchar(); (void)gc;
			PrintAndLogEx(NORMAL, "\n[!] aborted via keyboard!\n");
			goto out;
		}
		
		uint32_t keys = ((keycnt - i)  > chunksize) ? chunksize : keycnt - i;
		
		// last chunk?
		if ( keys == keycnt - i)
			lastChunk = true;
		
		UsbCommand c = {CMD_ICLASS_CHECK_KEYS, { (lastChunk << 8), keys, 0}};
		memcpy(c.d.asBytes, pre + i, 4 * keys);
		clearCommandBuffer();
		SendCommand(&c);
		UsbCommand resp;
		
		while ( !WaitForResponseTimeout(CMD_ACK, &resp, 2000) ) {
			timeout++;
			printf("."); fflush(stdout);
			if (timeout > 120) {
				PrintAndLogEx(WARNING, "\nno response from Proxmark. Aborting...");
				goto out;
			}
		}

		uint8_t found = resp.arg[1] & 0xFF;			
		uint8_t isOK = resp.arg[0] & 0xFF;
		
		t2 = msclock() - t2;
		switch ( isOK ) {
			case 1: {
				found_debit = true;
				
				PrintAndLogEx(NORMAL, "\n[-] Chunk [%d/%d]: %.1fs [debit]  found key  %s (index %u)"
						, i
						, keycnt						
						, (float)(t2/1000.0)
						, sprint_hex(keyBlock + (i+found)*8, 8)
						, found
					);
				break;
			}
			case 0: {
				PrintAndLogEx(NORMAL, "\n[-] Chunk [%d/%d] : %.1fs [debit]", i, keycnt, (float)(t2/1000.0));
				break;
			}
			case 99: {
			}
			default: break;
		}

		// both keys found.
		if ( found_debit ) {
			PrintAndLogEx(SUCCESS, "All keys found, exiting");
			break;
		}

	} // end chunks of keys	
	
out:	
	t1 = msclock() - t1;

	PrintAndLogEx(SUCCESS, "\nTime in iclass checkkeys: %.0f seconds\n", (float)t1/1000.0);
	
	DropField();
	free(pre);
	free(keyBlock);
	return 0;
}

static int cmp_uint32( const void *a, const void *b) {
	
	const iclass_prekey_t* x = (const iclass_prekey_t *)a;
	const iclass_prekey_t* y = (const iclass_prekey_t *)b;
	
	uint32_t mx = bytes_to_num( (uint8_t*)x->mac, 4);
	uint32_t my = bytes_to_num( (uint8_t*)y->mac, 4);
	
    if (mx < my)
		return -1;
    else 
		return mx > my;
}

// this method tries to identify in which configuration mode a iClass / iClass SE reader is in.
// Standard or Elite / HighSecurity mode.  It uses a default key dictionary list in order to work.
int CmdHFiClassLookUp(const char *Cmd) {
	
	uint8_t CSN[8];
	uint8_t EPURSE[8];
	uint8_t MACS[8];
	uint8_t CCNR[12];
	uint8_t MAC_TAG[4] = {0x00,0x00,0x00,0x00};
	
	// elite key,  raw key, standard key
	bool use_elite = false;
	bool use_raw = false;
	bool errors = false;
	uint8_t cmdp = 0x00;

	char filename[FILE_PATH_SIZE] = {0};
	uint8_t fileNameLen = 0;

	uint8_t *keyBlock = NULL;	
	iclass_prekey_t *prekey = NULL;
	int keycnt = 0, len = 0;

	// if empty string
	if (strlen(Cmd) == 0) errors = true;
	// time
	uint64_t t1 = msclock();
	
	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (param_getchar(Cmd, cmdp)) {
		case 'h':
		case 'H':
			return usage_hf_iclass_lookup();
		case 'f':
		case 'F':
			fileNameLen = param_getstr(Cmd, cmdp+1, filename, sizeof(filename)); 
			if (fileNameLen < 1) {
				PrintAndLogEx(WARNING, "No filename found after f");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'u':
		case 'U':
			param_gethex_ex(Cmd, cmdp+1, CSN, &len);
			if ( len>>1 != sizeof(CSN) ) {
				PrintAndLogEx(WARNING, "Wrong CSN length, expected %d got [%d]", sizeof(CSN), len>>1);
				errors = true;
			}
			cmdp += 2;			
			break;
		case 'm':
		case 'M':
			param_gethex_ex(Cmd, cmdp+1, MACS, &len);
			if ( len>>1 != sizeof(MACS) ) {
				PrintAndLogEx(WARNING, "Wrong MACS length, expected %d got [%d]  ", sizeof(MACS), len>>1);
				errors = true;
			} else {
				memcpy(MAC_TAG, MACS+4, 4);
			}
			cmdp += 2;			
			break;
		case 'p':
		case 'P':
			param_gethex_ex(Cmd, cmdp+1, EPURSE, &len);
			if ( len>>1 != sizeof(EPURSE) ) {
				PrintAndLogEx(WARNING, "Wrong EPURSE length, expected %d got [%d]  ", sizeof(EPURSE), len>>1);
				errors = true;
			}
			cmdp += 2;			
			break;
		break;
		case 'e':
		case 'E':
			use_elite = true;
			cmdp++;
			break;
		case 'r':
		case 'R':
			use_raw = true;
			cmdp++;
			break;
		default:
			PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}

	if (errors) return usage_hf_iclass_lookup();	

	// stupid copy.. CCNR is a combo of epurse and reader nonce
	memcpy(CCNR, EPURSE, 8);
	memcpy(CCNR+8, MACS, 4);
	
	PrintAndLogEx(SUCCESS, "CSN     | %s", sprint_hex( CSN, sizeof(CSN) ));
	PrintAndLogEx(SUCCESS, "Epurse  | %s", sprint_hex( EPURSE, sizeof(EPURSE) ));
	PrintAndLogEx(SUCCESS, "MACS    | %s", sprint_hex( MACS, sizeof(MACS) ));
	PrintAndLogEx(SUCCESS, "CCNR    | %s", sprint_hex( CCNR, sizeof(CCNR) ));
	PrintAndLogEx(SUCCESS, "MAC_TAG | %s", sprint_hex( MAC_TAG, sizeof(MAC_TAG) ));
	
	int res = LoadDictionaryKeyFile( filename, &keyBlock, &keycnt);
	if ( res > 0) {
		free(keyBlock);
		return 1;
	}
	//iclass_prekey_t	
	prekey = calloc(keycnt, sizeof(iclass_prekey_t));
	if ( !prekey ) {
		free(keyBlock);
		return 1;
	}

	PrintAndLogEx(FAILED, "Generating diversified keys and MAC");
	res = GenerateFromKeyFile( CSN, CCNR, use_raw, use_elite, keyBlock, keycnt, prekey );
	if ( res > 0) {
		free(keyBlock);
		free(prekey);
		return 1;
	}	

	PrintAndLogEx(FAILED, "Sorting");
			
	// sort mac list.
	qsort( prekey, keycnt, sizeof(iclass_prekey_t), cmp_uint32);

	//PrintPreCalc(prekey, keycnt);
	
	PrintAndLogEx(FAILED, "Searching");	
	iclass_prekey_t *item;
	iclass_prekey_t lookup;
	memcpy(lookup.mac, MAC_TAG, 4);
	
	// using find
	item = (iclass_prekey_t*) bsearch(&lookup, prekey, keycnt, sizeof(iclass_prekey_t), cmp_uint32);	
	if( item != NULL ) {
		PrintAndLogEx(SUCCESS, "\n[debit] found key %s", sprint_hex(item->key, 8));
	}

	t1 = msclock() - t1;
	PrintAndLogEx(NORMAL, "\nTime in iclass : %.0f seconds\n", (float)t1/1000.0);
	DropField();
	free(prekey);
	free(keyBlock);
	PrintAndLogEx(NORMAL, "");		
	return 0;
}	

int LoadDictionaryKeyFile( char* filename, uint8_t **keys, int *keycnt) {

	char buf[17];
	FILE * f;
	uint8_t *p;
	int keyitems = 0;
	
	if ( !(f = fopen( filename , "r")) ) {
		PrintAndLogEx(ERR, "file: %s: not found or locked.", filename);
		return 1;
	}

	while( fgets(buf, sizeof(buf), f) ){
		if (strlen(buf) < 16 || buf[15] == '\n')
			continue;
	
		//goto next line
		while (fgetc(f) != '\n' && !feof(f)) {}; 
		
		//The line start with # is comment, skip		
		if( buf[0]=='#' ) continue;

		// doesn't this only test first char only?
		if (!isxdigit(buf[0])){
			PrintAndLogEx(ERR, "file content error. '%s' must include 16 HEX symbols", buf);
			continue;
		}
		
		// null terminator (skip the rest of the line)
		buf[16] = 0;

		p = realloc(*keys, 8 * (keyitems += 64));
		if (!p) {
			PrintAndLogEx(NORMAL, _RED_([!])" cannot allocate memory for default keys");
			fclose(f);
			return 2;
		}
		*keys = p;

		memset(*keys + 8 * (*keycnt), 0, 8);
		num_to_bytes(strtoull(buf, NULL, 16), 8, *keys + 8 * (*keycnt));
		(*keycnt)++;
		memset(buf, 0, sizeof(buf));
	}
	fclose(f);
	PrintAndLogEx(NORMAL, _BLUE_([+]) " loaded " _GREEN_(%2d) " keys from %s", *keycnt, filename);	
	return 0;
}

// precalc diversified keys and their MAC
int GenerateMacFromKeyFile( uint8_t* CSN, uint8_t* CCNR, bool use_raw, bool use_elite, uint8_t* keys, int keycnt, iclass_premac_t* list ) {
	uint8_t key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	for ( int i=0; i < keycnt; i++) {

		memcpy(key, keys + 8 * i , 8); 
		
		if (use_raw)
			memcpy(div_key, key, 8);
		else
			HFiClassCalcDivKey(CSN, key, div_key, use_elite);

		doMAC(CCNR, div_key, list[i].mac);
	}	
	return 0;
}

int GenerateFromKeyFile( uint8_t* CSN, uint8_t* CCNR, bool use_raw, bool use_elite, uint8_t* keys, int keycnt, iclass_prekey_t* list ) {

	uint8_t div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	for ( int i=0; i < keycnt; i++) {
				
		memcpy(list[i].key, keys + 8 * i , 8); 
		
		// generate diversifed key
		if (use_raw)
			memcpy(div_key, list[i].key, 8);
		else
			HFiClassCalcDivKey(CSN, list[i].key, div_key, use_elite);

		// generate MAC
		doMAC(CCNR, div_key, list[i].mac);
	}	
	return 0;
}

// print diversified keys
void PrintPreCalcMac(uint8_t* keys, int keycnt, iclass_premac_t* pre_list) {

	iclass_prekey_t* b =  calloc(keycnt, sizeof(iclass_prekey_t));
	if ( !b )
		return;
		
	for ( int i=0; i < keycnt; i++) {		
		memcpy(b[i].key, keys + 8 * i , 8); 
		memcpy(b[i].mac, pre_list[i].mac, 4);
	}
	PrintPreCalc(b, keycnt);
	free(b);
}

void PrintPreCalc(iclass_prekey_t* list, int itemcnt) {
	PrintAndLogEx(NORMAL, "-----+------------------+---------");
	PrintAndLogEx(NORMAL, "#key | key              | mac");
	PrintAndLogEx(NORMAL, "-----+------------------+---------");
	for ( int i=0; i < itemcnt; i++) {

		if (i < 10 ) {			
			PrintAndLogEx(NORMAL, "[%2d] | %016" PRIx64 " | %08" PRIx32, i, bytes_to_num(list[i].key, 8), bytes_to_num( list[i].mac, 4) );
		} else if ( i == 10 ) {
			PrintAndLogEx(SUCCESS, "... skip printing the rest");
		}
	}
}

static void permute(uint8_t *data, uint8_t len, uint8_t *output){	
#define KEY_SIZE 8

	if ( len > KEY_SIZE ) {
		for(uint8_t m = 0; m < len; m += KEY_SIZE){
			permute(data+m, KEY_SIZE, output+m);
		}
		return;
	}
	if ( len != KEY_SIZE ) {
		PrintAndLogEx(NORMAL, "[!] wrong key size\n");
		return;
	}
	uint8_t i,j,p, mask;
	for( i=0; i < KEY_SIZE; ++i){
		p = 0;
		mask = 0x80 >> i;
		for( j=0; j < KEY_SIZE; ++j){
			p >>= 1;
			if (data[j] & mask) 
				p |= 0x80;
		}
		output[i] = p;
	}
}
static void permute_rev(uint8_t *data, uint8_t len, uint8_t *output){
	permute(data, len, output);
	permute(output, len, data);
	permute(data, len, output);
}
static void simple_crc(uint8_t *data, uint8_t len, uint8_t *output){
	uint8_t crc = 0;
	for( uint8_t i=0; i < len; ++i){
		// seventh byte contains the crc.
		if ( (i & 0x7) == 0x7 ) {
			output[i] = crc ^ 0xFF;
			crc = 0;
		} else {
			output[i] = data[i];
			crc ^= data[i];
		}
	}
}
// DES doesn't use the MSB.
static void shave(uint8_t *data, uint8_t len){
	for (uint8_t i=0; i<len; ++i)
		data[i] &= 0xFE;
}
static void generate_rev(uint8_t *data, uint8_t len) {
	uint8_t *key = calloc(len,1);	
	PrintAndLogEx(SUCCESS, "input permuted key | %s \n", sprint_hex(data, len));
	permute_rev(data, len, key);
	PrintAndLogEx(SUCCESS, "    unpermuted key | %s \n", sprint_hex(key, len));
	shave(key, len);
	PrintAndLogEx(SUCCESS, "               key | %s \n", sprint_hex(key, len));
	free(key);	
}
static void generate(uint8_t *data, uint8_t len) {
	uint8_t *key = calloc(len,1);
	uint8_t *pkey = calloc(len,1);	
	PrintAndLogEx(SUCCESS, "   input key | %s \n", sprint_hex(data, len));
	permute(data, len, pkey);
	PrintAndLogEx(SUCCESS, "permuted key | %s \n", sprint_hex(pkey, len));
	simple_crc(pkey, len, key );
	PrintAndLogEx(SUCCESS, "  CRC'ed key | %s \n", sprint_hex(key, len));
	free(key);
	free(pkey);
}

int CmdHFiClassPermuteKey(const char *Cmd) { 

	uint8_t key[8] = {0};	
	uint8_t key_std_format[8] = {0};
	uint8_t key_iclass_format[8] = {0};
	uint8_t data[16] = {0};
	bool isReverse = false;
	int len = 0;
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0|| cmdp == 'h' || cmdp == 'H') return usage_hf_iclass_permutekey();
		
	isReverse = ( cmdp == 'r' || cmdp == 'R' );
	
	param_gethex_ex(Cmd, 1, data, &len);
	if ( len%2 ) return usage_hf_iclass_permutekey();

	len >>= 1;	

	memcpy(key, data, 8);

	if ( isReverse ) {
		generate_rev(data, len);
		permutekey_rev(key, key_std_format);
		PrintAndLogEx(SUCCESS, "holiman iclass key | %s \n", sprint_hex(key_std_format, 8));
	}
	else {
		generate(data, len);
		permutekey(key, key_iclass_format);		
		PrintAndLogEx(SUCCESS, "holiman std key | %s \n", sprint_hex(key_iclass_format, 8));
	}
	return 0;
}

static command_t CommandTable[] = {
	{"help",		CmdHelp,					1,	"This help"},
	{"calcnewkey",  CmdHFiClassCalcNewKey,     	1,	"[options..] Calc Diversified keys (blocks 3 & 4) to write new keys"},
	{"chk",         CmdHFiClassCheckKeys,      	1,	"            Check keys"},
	{"clone",       CmdHFiClassCloneTag,       	0,	"[options..] Authenticate and Clone from iClass bin file"},
	{"decrypt",     CmdHFiClassDecrypt,        	1,	"[f <fname>] Decrypt tagdump" },
	{"dump",        CmdHFiClassReader_Dump,    	0,	"[options..] Authenticate and Dump iClass tag's AA1"},
	{"eload",       CmdHFiClassELoad,          	0,	"[f <fname>] (experimental) Load data into iClass emulator memory"},
	{"encryptblk",  CmdHFiClassEncryptBlk,     	1,	"<BlockData> Encrypt given block data"},
	{"list",        CmdHFiClassList,           	0,	"            (Deprecated) List iClass history"},
	{"loclass",     CmdHFiClass_loclass,       	1,	"[options..] Use loclass to perform bruteforce of reader attack dump"},
	{"lookup",		CmdHFiClassLookUp,     		0,	"[options..] Uses authentication trace to check for key in dictionary file"},
	{"managekeys",  CmdHFiClassManageKeys,     	1,	"[options..] Manage the keys to use with iClass"},
	{"permutekey",  CmdHFiClassPermuteKey,		0,	"            Permute function from 'heart of darkness' paper"},
	{"readblk",     CmdHFiClass_ReadBlock,      0,	"[options..] Authenticate and Read iClass block"},
	{"reader",		CmdHFiClassReader,			0,	"            Act like an iClass reader"},
	{"readtagfile", CmdHFiClassReadTagFile,     1,	"[options..] Display Content from tagfile"},
	{"replay",      CmdHFiClassReader_Replay,   0,	"<mac>       Read an iClass tag via Reply Attack"},
	{"sim",         CmdHFiClassSim,             0,	"[options..] Simulate iClass tag"},
	{"sniff",       CmdHFiClassSniff,           0,	"            Eavesdrop iClass communication"},
	{"writeblk",    CmdHFiClass_WriteBlock,     0,	"[options..] Authenticate and Write iClass block"},
	{NULL, NULL, 0, NULL}
};

int CmdHFiClass(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
