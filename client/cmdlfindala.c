//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Indala commands
// PSK1, rf/32, 64 or 224 bits (known)
//-----------------------------------------------------------------------------

#include "cmdlfindala.h"

static int CmdHelp(const char *Cmd);

int usage_lf_indala_demod(void) {
	PrintAndLogEx(NORMAL, "Enables Indala compatible reader mode printing details of scanned tags.");
	PrintAndLogEx(NORMAL, "By default, values are printed and logged until the button is pressed or another USB command is issued.");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Usage:  lf indala demod [h]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h :  This help");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        lf indala demod");
	return 0;
}

int usage_lf_indala_sim(void) {
	PrintAndLogEx(NORMAL, "Enables simulation of Indala card with specified uid.");
	PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Usage:  lf indala sim [h] <uid>");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "            h :  This help");	
	PrintAndLogEx(NORMAL, "        <uid> :  64/224 UID");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "       lf indala sim deadc0de");
	return 0;
}

int usage_lf_indala_clone(void) {
	PrintAndLogEx(NORMAL, "Enables cloning of Indala card with specified uid onto T55x7.");
	PrintAndLogEx(NORMAL, "The T55x7 must be on the antenna when issuing this command.  T55x7 blocks are calculated and printed in the process.");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Usage:  lf indala clone [h] <uid> [Q5]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "            h :  This help");	
	PrintAndLogEx(NORMAL, "        <uid> :  64/224 UID");
	PrintAndLogEx(NORMAL, "           Q5 :  optional - clone to Q5 (T5555) instead of T55x7 chip");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "       lf indala clone 112233");
	return 0;
}

// redesigned by marshmellow adjusted from existing decode functions
// indala id decoding
int indala64decode(uint8_t *dest, size_t *size, uint8_t *invert) {
	//standard 64 bit indala formats including 26 bit 40134 format
	uint8_t   preamble64[] = {1,0,1,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 1};
	uint8_t preamble64_i[] = {0,1,0,1, 1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1, 0};
	size_t idx = 0;
	size_t found_size = *size;
	if (!preambleSearch(dest, preamble64, sizeof(preamble64), &found_size, &idx) ) {
		// if didn't find preamble try again inverting
		if (!preambleSearch(dest, preamble64_i, sizeof(preamble64_i), &found_size, &idx)) return -1;
		*invert ^= 1;
	}
	if (found_size != 64) return -2;

	if (*invert == 1)
		for (size_t i = idx; i < found_size + idx; i++) 
			dest[i] ^= 1;

	// note: don't change *size until we are sure we got it... 
	*size = found_size;
	return (int) idx;
}

int indala224decode(uint8_t *dest, size_t *size, uint8_t *invert) {
	//large 224 bit indala formats (different preamble too...)
	uint8_t   preamble224[] = {1,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 1};
	uint8_t preamble224_i[] = {0,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1, 0};
	size_t idx = 0;
	size_t found_size = *size;
	if (!preambleSearch(dest, preamble224, sizeof(preamble224), &found_size, &idx) ) {
		// if didn't find preamble try again inverting
		if (!preambleSearch(dest, preamble224_i, sizeof(preamble224_i), &found_size, &idx)) return -1;
		*invert ^= 1;
	}
	if (found_size != 224) return -2;
	
	if (*invert==1 && idx > 0)
		for (size_t i = idx-1; i < found_size + idx + 2; i++) 
			dest[i] ^= 1;

	// 224 formats are typically PSK2 (afaik 2017 Marshmellow)
	// note loses 1 bit at beginning of transformation...
	// don't need to verify array is big enough as to get here there has to be a full preamble after all of our data
	psk1TOpsk2(dest + (idx-1), found_size+2);
	idx++;

	*size = found_size;
	return (int) idx;
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
int CmdIndalaRead(const char *Cmd) {
	lf_read(true, 30000);
	return CmdIndalaDemod(Cmd);
}

// Indala 26 bit decode
// by marshmellow
// optional arguments - same as PSKDemod (clock & invert & maxerr)
int CmdIndalaDemod(const char *Cmd) {
	int ans;
	if (strlen(Cmd) > 0)
		ans = PSKDemod(Cmd, 0);
	else //default to RF/32
		ans = PSKDemod("32", 0);

	if (!ans){
		PrintAndLogEx(DEBUG, "DEBUG: Error - Indala can't demod signal: %d",ans);
		return 0;
	}

	uint8_t invert = 0;
	size_t size = DemodBufferLen;
	int idx = indala64decode(DemodBuffer, &size, &invert);
	if (idx < 0 || size != 64) {
		// try 224 indala
		invert = 0;
		size = DemodBufferLen;
		idx = indala224decode(DemodBuffer, &size, &invert);
		if (idx < 0 || size != 224) {
			PrintAndLogEx(DEBUG, "DEBUG: Error - Indala wrong size, expected [64|224] got: %d (startindex %i)", size, idx);
			return -1;
		}
	}
	
	setDemodBuf(DemodBuffer, size, (size_t)idx);
	setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));
	if (invert) {
		PrintAndLogEx(DEBUG, "DEBUG: Error - Indala had to invert bits");		
		for (size_t i = 0; i < size; i++) 
			DemodBuffer[i] ^= 1;
	}	

	//convert UID to HEX
	uint32_t uid1, uid2, uid3, uid4, uid5, uid6, uid7;
	uid1 = bytebits_to_byte(DemodBuffer,32);
	uid2 = bytebits_to_byte(DemodBuffer+32,32);
	if (DemodBufferLen == 64){
		PrintAndLogEx(SUCCESS, "Indala Found - bitlength %d, UID = (0x%x%08x)\n%s",
			DemodBufferLen, uid1, uid2, sprint_bin_break(DemodBuffer,DemodBufferLen,32)
		);
	} else {
		uid3 = bytebits_to_byte(DemodBuffer+64,32);
		uid4 = bytebits_to_byte(DemodBuffer+96,32);
		uid5 = bytebits_to_byte(DemodBuffer+128,32);
		uid6 = bytebits_to_byte(DemodBuffer+160,32);
		uid7 = bytebits_to_byte(DemodBuffer+192,32);
		PrintAndLogEx(SUCCESS, "Indala Found - bitlength %d, UID = (0x%x%08x%08x%08x%08x%08x%08x)\n%s", 
			DemodBufferLen,
		    uid1, uid2, uid3, uid4, uid5, uid6, uid7, sprint_bin_break(DemodBuffer, DemodBufferLen, 32)
		);
	}
	if (g_debugMode){
		PrintAndLogEx(DEBUG, "DEBUG: Indala - printing demodbuffer:");
		printDemodBuff();
	}
	return 1;
}

// older alternative indala demodulate (has some positives and negatives)
// returns false positives more often - but runs against more sets of samples
// poor psk signal can be difficult to demod this approach might succeed when the other fails
// but the other appears to currently be more accurate than this approach most of the time.
int CmdIndalaDemodAlt(const char *Cmd) {
	// Usage: recover 64bit UID by default, specify "224" as arg to recover a 224bit UID
	int state = -1;
	int count = 0;
	int i, j;

	// worst case with GraphTraceLen=64000 is < 4096
	// under normal conditions it's < 2048

	uint8_t rawbits[4096];
	int rawbit = 0;
	int worst = 0, worstPos = 0;

	//clear clock grid and demod plot
	setClockGrid(0, 0);
	DemodBufferLen = 0;
	
	// PrintAndLogEx(NORMAL, "Expecting a bit less than %d raw bits", GraphTraceLen / 32);
	// loop through raw signal - since we know it is psk1 rf/32 fc/2 skip every other value (+=2)
	for (i = 0; i < GraphTraceLen-1; i += 2) {
		count += 1;
		if ((GraphBuffer[i] > GraphBuffer[i + 1]) && (state != 1)) {
			// appears redundant - marshmellow
			if (state == 0) {
				for (j = 0; j <  count - 8; j += 16) {
					rawbits[rawbit++] = 0;
				}
				if ((abs(count - j)) > worst) {
					worst = abs(count - j);
					worstPos = i;
				}
			}
			state = 1;
			count = 0;
		} else if ((GraphBuffer[i] < GraphBuffer[i + 1]) && (state != 0)) {
			//appears redundant
			if (state == 1) {
				for (j = 0; j <  count - 8; j += 16) {
					rawbits[rawbit++] = 1;
				}
				if ((abs(count - j)) > worst) {
					worst = abs(count - j);
					worstPos = i;
				}
			}
			state = 0;
			count = 0;
		}
	}
	
	if (rawbit>0){
		PrintAndLogEx(NORMAL, "Recovered %d raw bits, expected: %d", rawbit, GraphTraceLen/32);
		PrintAndLogEx(NORMAL, "worst metric (0=best..7=worst): %d at pos %d", worst, worstPos);
	} else {
		return 0;
	}

	// Finding the start of a UID
	int uidlen, long_wait;
	if (strcmp(Cmd, "224") == 0) {
		uidlen = 224;
		long_wait = 30;
	} else {
		uidlen = 64;
		long_wait = 29;
	}

	int start;
	int first = 0;
	for (start = 0; start <= rawbit - uidlen; start++) {
		first = rawbits[start];
		for (i = start; i < start + long_wait; i++) {
			if (rawbits[i] != first) {
				break;
			}
		}
		if (i == (start + long_wait)) {
			break;
		}
	}
	
	if (start == rawbit - uidlen + 1) {
		PrintAndLogEx(NORMAL, "nothing to wait for");
		return 0;
	}

	// Inverting signal if needed
	if (first == 1) {
		for (i = start; i < rawbit; i++) {
			rawbits[i] = !rawbits[i];
		}
	}

	// Dumping UID
	uint8_t bits[224] = {0x00};
	char showbits[225] = {0x00};
	int bit;
	i = start;
	int times = 0;
	
	if (uidlen > rawbit) {
		PrintAndLogEx(WARNING, "Warning: not enough raw bits to get a full UID");
		for (bit = 0; bit < rawbit; bit++) {
			bits[bit] = rawbits[i++];
			// As we cannot know the parity, let's use "." and "/"
			showbits[bit] = '.' + bits[bit];
		}
		showbits[bit+1]='\0';
		PrintAndLogEx(NORMAL, "Partial UID=%s", showbits);
		return 0;
	} else {
		for (bit = 0; bit < uidlen; bit++) {
			bits[bit] = rawbits[i++];
			showbits[bit] = '0' + bits[bit];
		}
		times = 1;
	}
	
	//convert UID to HEX
	uint32_t uid1, uid2, uid3, uid4, uid5, uid6, uid7;
	int idx;
	uid1 = uid2 = 0;
	
	if (uidlen==64){
		for( idx=0; idx<64; idx++) {
				if (showbits[idx] == '0') {
				uid1=(uid1<<1)|(uid2>>31);
				uid2=(uid2<<1)|0;
				} else {
				uid1=(uid1<<1)|(uid2>>31);
				uid2=(uid2<<1)|1;
				} 
			}
		PrintAndLogEx(NORMAL, "UID=%s (%x%08x)", showbits, uid1, uid2);
	}
	else {
		uid3 = uid4 = uid5 = uid6 = uid7 = 0;

		for( idx=0; idx<224; idx++) {
				uid1=(uid1<<1)|(uid2>>31);
				uid2=(uid2<<1)|(uid3>>31);
				uid3=(uid3<<1)|(uid4>>31);
				uid4=(uid4<<1)|(uid5>>31);
				uid5=(uid5<<1)|(uid6>>31);
				uid6=(uid6<<1)|(uid7>>31);
			
			if (showbits[idx] == '0') 
				uid7 = (uid7<<1) | 0;
			else 
				uid7 = (uid7<<1) | 1;
			}
		PrintAndLogEx(NORMAL, "UID=%s (%x%08x%08x%08x%08x%08x%08x)", showbits, uid1, uid2, uid3, uid4, uid5, uid6, uid7);
	}

	// Checking UID against next occurrences
		int failed = 0;
	for (; i + uidlen <= rawbit;) {
		failed = 0;
		for (bit = 0; bit < uidlen; bit++) {
			if (bits[bit] != rawbits[i++]) {
				failed = 1;
				break;
			}
		}
		if (failed == 1) {
			break;
		}
		times += 1;
	}

	PrintAndLogEx(NORMAL, "Occurrences: %d (expected %d)", times, (rawbit - start) / uidlen);

	// Remodulating for tag cloning
	// HACK: 2015-01-04 this will have an impact on our new way of seening lf commands (demod) 
	// since this changes graphbuffer data.
	GraphTraceLen = 32*uidlen;
	i = 0;
	int phase = 0;
	for (bit = 0; bit < uidlen; bit++) {
		if (bits[bit] == 0) {
			phase = 0;
		} else {
			phase = 1;
		}
		int j;
		for (j = 0; j < 32; j++) {
			GraphBuffer[i++] = phase;
			phase = !phase;
		}
	}

	RepaintGraphWindow();
	return 1;
}

int CmdIndalaSim(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_indala_sim();

	uint8_t bits[224];
	size_t size = sizeof(bits);
	memset(bits, 0x00, size);

	// uid
	uint8_t hexuid[100];
	int len = 0;
	param_gethex_ex(Cmd, 0, hexuid, &len);
	if ( len > 28 ) 
		return usage_lf_indala_sim();
	
	// convert to binarray
	uint8_t counter = 224;
	for (uint8_t i=0; i< len; i++) {
		for(uint8_t j=0; j<8; j++) {
			bits[counter--] = hexuid[i] & 1;
			hexuid[i] >>= 1;
		}
	}
	
	// indala PSK 
	uint8_t clk = 32, carrier = 2, invert = 0;
	uint16_t arg1, arg2;
	arg1 = clk << 8 | carrier;
	arg2 = invert;
	
	// It has to send either 64bits (8bytes) or 224bits (28bytes).  Zero padding needed if not.
	// lf simpsk 1 c 32 r 2 d 0102030405060708
	
//	PrintAndLogEx(NORMAL, "Emulating Indala UID: %u \n", cn);
//	PrintAndLogEx(NORMAL, "Press pm3-button to abort simulation or run another command");
	
	UsbCommand c = {CMD_PSK_SIM_TAG, {arg1, arg2, size}};  
	memcpy(c.d.asBytes, bits, size);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

// iceman - needs refactoring 
int CmdIndalaClone(const char *Cmd) {
	UsbCommand c;
	uint32_t uid1, uid2, uid3, uid4, uid5, uid6, uid7;
	uid1 =  uid2 = uid3 = uid4 = uid5 = uid6 = uid7 = 0;
	uint32_t n = 0, i = 0;

	if (strchr(Cmd,'l') != 0) {
		while (sscanf(&Cmd[i++], "%1x", &n ) == 1) {
			uid1 = (uid1 << 4) | (uid2 >> 28);
			uid2 = (uid2 << 4) | (uid3 >> 28);
			uid3 = (uid3 << 4) | (uid4 >> 28);
			uid4 = (uid4 << 4) | (uid5 >> 28);
			uid5 = (uid5 << 4) | (uid6 >> 28);
			uid6 = (uid6 << 4) | (uid7 >> 28);
			uid7 = (uid7 << 4) | (n & 0xf);
		}
		PrintAndLogEx(NORMAL, "Cloning 224bit tag with UID %x%08x%08x%08x%08x%08x%08x", uid1, uid2, uid3, uid4, uid5, uid6, uid7);
		c.cmd = CMD_INDALA_CLONE_TAG_L;
		c.d.asDwords[0] = uid1;
		c.d.asDwords[1] = uid2;
		c.d.asDwords[2] = uid3;
		c.d.asDwords[3] = uid4;
		c.d.asDwords[4] = uid5;
		c.d.asDwords[5] = uid6;
		c.d.asDwords[6] = uid7;
	} else {
		while (sscanf(&Cmd[i++], "%1x", &n ) == 1) {
			uid1 = (uid1 << 4) | (uid2 >> 28);
			uid2 = (uid2 << 4) | (n & 0xf);
		}
		PrintAndLogEx(NORMAL, "Cloning 64bit tag with UID %x%08x", uid1, uid2);
		c.cmd = CMD_INDALA_CLONE_TAG;
		c.arg[0] = uid1;
		c.arg[1] = uid2;
	}

	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
	{"help",	CmdHelp,			1, "this help"},
	{"demod",	CmdIndalaDemod,		1, "demodulate an indala tag (PSK1) from GraphBuffer"},
	{"altdemod", CmdIndalaDemodAlt,	1, "alternative method to Demodulate samples for Indala 64 bit UID (option '224' for 224 bit)"},
	{"read",	CmdIndalaRead,		0, "read an Indala Prox tag from the antenna"},
	{"clone",	CmdIndalaClone,		0, "clone Indala to T55x7"},
	{"sim",		CmdIndalaSim,		0, "simulate Indala tag"},
	{NULL, NULL, 0, NULL}
};

int CmdLFINDALA(const char *Cmd){
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0; 
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
