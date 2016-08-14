//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency commands
//-----------------------------------------------------------------------------
#include "cmdlf.h"
static int CmdHelp(const char *Cmd);

int usage_lf_cmdread(void) {
	PrintAndLog("Usage: lf cmdread d <delay period> z <zero period> o <one period> c <cmdbytes> [H]");
	PrintAndLog("Options:");
	PrintAndLog("       h             This help");
	PrintAndLog("       L             Low frequency (125 KHz)");
	PrintAndLog("       H             High frequency (134 KHz)");
	PrintAndLog("       d <delay>     delay OFF period, (decimal)");
	PrintAndLog("       z <zero>      time period ZERO, (decimal)");
	PrintAndLog("       o <one>       time period ONE, (decimal)");
	PrintAndLog("       c <cmd>       Command bytes  (in ones and zeros)");
	PrintAndLog("       ************* All periods in microseconds (ms)");
	PrintAndLog("Examples:");
	PrintAndLog("      lf cmdread d 80 z 100 o 200 c 11000");
	PrintAndLog("      lf cmdread d 80 z 100 o 100 c 11000 H");
	return 0;
}
int usage_lf_read(void){
	PrintAndLog("Usage: lf read [h] [s]");
	PrintAndLog("Options:");
	PrintAndLog("       h            This help");
	PrintAndLog("       s            silent run no printout");
	PrintAndLog("This function takes no arguments. ");
	PrintAndLog("Use 'lf config' to set parameters.");
	return 0;
}
int usage_lf_snoop(void) {
	PrintAndLog("Usage: lf snoop");
	PrintAndLog("Options:");
	PrintAndLog("       h            This help");
	PrintAndLog("This function takes no arguments. ");
	PrintAndLog("Use 'lf config' to set parameters.");
	return 0;
}
int usage_lf_config(void) {
	PrintAndLog("Usage: lf config [h] [H|<divisor>] [b <bps>] [d <decim>] [a 0|1]");
	PrintAndLog("Options:");
	PrintAndLog("       h             This help");
	PrintAndLog("       L             Low frequency (125 KHz)");
	PrintAndLog("       H             High frequency (134 KHz)");
	PrintAndLog("       q <divisor>   Manually set divisor. 88-> 134KHz, 95-> 125 Hz");
	PrintAndLog("       b <bps>       Sets resolution of bits per sample. Default (max): 8");
	PrintAndLog("       d <decim>     Sets decimation. A value of N saves only 1 in N samples. Default: 1");
	PrintAndLog("       a [0|1]       Averaging - if set, will average the stored sample value when decimating. Default: 1");
	PrintAndLog("       t <threshold> Sets trigger threshold. 0 means no threshold (range: 0-128)");
	PrintAndLog("Examples:");
	PrintAndLog("      lf config b 8 L");
	PrintAndLog("                    Samples at 125KHz, 8bps.");
	PrintAndLog("      lf config H b 4 d 3");
	PrintAndLog("                    Samples at 134KHz, averages three samples into one, stored with ");
	PrintAndLog("                    a resolution of 4 bits per sample.");
	PrintAndLog("      lf read");
	PrintAndLog("                    Performs a read (active field)");
	PrintAndLog("      lf snoop");
	PrintAndLog("                    Performs a snoop (no active field)");
	return 0;
}
int usage_lf_simfsk(void) {
	PrintAndLog("Usage: lf simfsk [c <clock>] [i] [H <fcHigh>] [L <fcLow>] [d <hexdata>]");
	PrintAndLog("Options:");
	PrintAndLog("       h              This help");
	PrintAndLog("       c <clock>      Manually set clock - can autodetect if using DemodBuffer");
	PrintAndLog("       i              invert data");
	PrintAndLog("       H <fcHigh>     Manually set the larger Field Clock");
	PrintAndLog("       L <fcLow>      Manually set the smaller Field Clock");
	//PrintAndLog("       s              TBD- -to enable a gap between playback repetitions - default: no gap");
	PrintAndLog("       d <hexdata>    Data to sim as hex - omit to sim from DemodBuffer");
	PrintAndLog("\n  NOTE: if you set one clock manually set them all manually");
	return 0;
}
int usage_lf_simask(void) {
	PrintAndLog("Usage: lf simask [c <clock>] [i] [b|m|r] [s] [d <raw hex to sim>]");
	PrintAndLog("Options:");
	PrintAndLog("       h              This help");
	PrintAndLog("       c <clock>      Manually set clock - can autodetect if using DemodBuffer");
	PrintAndLog("       i              invert data");
	PrintAndLog("       b              sim ask/biphase");
	PrintAndLog("       m              sim ask/manchester - Default");
	PrintAndLog("       r              sim ask/raw");
	PrintAndLog("       s              add t55xx Sequence Terminator gap - default: no gaps (only manchester)");
	PrintAndLog("       d <hexdata>    Data to sim as hex - omit to sim from DemodBuffer");
	return 0;
}
int usage_lf_simpsk(void) {
	PrintAndLog("Usage: lf simpsk [1|2|3] [c <clock>] [i] [r <carrier>] [d <raw hex to sim>]");
	PrintAndLog("Options:");
	PrintAndLog("       h              This help");
	PrintAndLog("       c <clock>      Manually set clock - can autodetect if using DemodBuffer");
	PrintAndLog("       i              invert data");
	PrintAndLog("       1              set PSK1 (default)");
	PrintAndLog("       2              set PSK2");
	PrintAndLog("       3              set PSK3");
	PrintAndLog("       r <carrier>    2|4|8 are valid carriers: default = 2");
	PrintAndLog("       d <hexdata>    Data to sim as hex - omit to sim from DemodBuffer");
	return 0;
}
int usage_lf_find(void){
    PrintAndLog("Usage:  lf search [h] <0|1> [u]");
    PrintAndLog("");
	PrintAndLog("Options:");
	PrintAndLog("       h             This help");
	PrintAndLog("       <0|1>         Use data from Graphbuffer, if not set, try reading data from tag.");
    PrintAndLog("       u             Search for Unknown tags, if not set, reads only known tags.");
	PrintAndLog("Examples:");
    PrintAndLog("      lf search     = try reading data from tag & search for known tags");
    PrintAndLog("      lf search 1   = use data from GraphBuffer & search for known tags");
    PrintAndLog("      lf search u   = try reading data from tag & search for known and unknown tags");
    PrintAndLog("      lf search 1 u = use data from GraphBuffer & search for known and unknown tags");
	return 0;
}


/* send a LF command before reading */
int CmdLFCommandRead(const char *Cmd) {

	bool errors = FALSE;
	bool useHighFreq = FALSE;
	uint16_t one = 0, zero = 0;
  	uint8_t cmdp = 0;
	UsbCommand c = {CMD_MOD_THEN_ACQUIRE_RAW_ADC_SAMPLES_125K, {0,0,0}};
	
	while(param_getchar(Cmd, cmdp) != 0x00) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'h':
			return usage_lf_cmdread();
		case 'H':
			useHighFreq = TRUE;
			cmdp++;
			break;
		case 'L':
			cmdp++;
			break;
		case 'c':
			param_getstr(Cmd, cmdp+1, (char *)&c.d.asBytes);
			cmdp+=2;
			break;
		case 'd':
			c.arg[0] = param_get32ex(Cmd, cmdp+1, 0, 10);
			cmdp+=2;
			break;
		case 'z':
			zero = param_get32ex(Cmd, cmdp+1, 0, 10) & 0xFFFF;
			cmdp+=2;
			break;
		case 'o':
			one = param_get32ex(Cmd, cmdp+1, 0, 10) & 0xFFFF;
			cmdp+=2;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = 1;
			break;
		}
		if(errors) break;
	}
	// No args
	if (cmdp == 0) errors = TRUE;

	//Validations
	if (errors) return usage_lf_cmdread();
	
	// zero and one lengths
	c.arg[1] = (uint32_t)(zero << 16 | one);
	
	// add frequency 125 or 134
	c.arg[2] = useHighFreq;

	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdFlexdemod(const char *Cmd)
{
#define LONG_WAIT 100	
	int i, j, start, bit, sum;
	int phase = 0;

	for (i = 0; i < GraphTraceLen; ++i)
		GraphBuffer[i] = (GraphBuffer[i] < 0) ? -1 : 1;

	for (start = 0; start < GraphTraceLen - LONG_WAIT; start++) {
		int first = GraphBuffer[start];
		for (i = start; i < start + LONG_WAIT; i++) {
			if (GraphBuffer[i] != first) {
				break;
			}
		}
		if (i == (start + LONG_WAIT))
			break;
	}
	
	if (start == GraphTraceLen - LONG_WAIT) {
		PrintAndLog("nothing to wait for");
		return 0;
	}

	GraphBuffer[start] = 2;
	GraphBuffer[start+1] = -2;
	uint8_t bits[64] = {0x00};

	i = start;
	for (bit = 0; bit < 64; bit++) {
		sum = 0;
		for (int j = 0; j < 16; j++) {
			sum += GraphBuffer[i++];
		}
		bits[bit] = (sum > 0) ? 1 : 0;
		PrintAndLog("bit %d sum %d", bit, sum);
	}

	for (bit = 0; bit < 64; bit++) {
		sum = 0;
		for (j = 0; j < 16; j++)
			sum += GraphBuffer[i++];

		if (sum > 0 && bits[bit] != 1) PrintAndLog("oops1 at %d", bit);

		if (sum < 0 && bits[bit] != 0) PrintAndLog("oops2 at %d", bit);

	}

	// HACK writing back to graphbuffer.
	GraphTraceLen = 32*64;
	i = 0;
	for (bit = 0; bit < 64; bit++) {
		
		phase = (bits[bit] == 0) ? 0 : 1;
		
		for (j = 0; j < 32; j++) {
			GraphBuffer[i++] = phase;
			phase = !phase;
		}
	}
	RepaintGraphWindow();
	return 0;
}
  
int CmdIndalaDemod(const char *Cmd)
{
	// Usage: recover 64bit UID by default, specify "224" as arg to recover a 224bit UID

	int state = -1;
	int count = 0;
	int i, j;

	// worst case with GraphTraceLen=64000 is < 4096
	// under normal conditions it's < 2048
	uint8_t rawbits[4096];

	int rawbit = 0, worst = 0, worstPos = 0;
	// PrintAndLog("Expecting a bit less than %d raw bits", GraphTraceLen / 32);
	
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

	if ( rawbit>0 ){
		PrintAndLog("Recovered %d raw bits, expected: %d", rawbit, GraphTraceLen/32);
		PrintAndLog("worst metric (0=best..7=worst): %d at pos %d", worst, worstPos);
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
		PrintAndLog("nothing to wait for");
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
		PrintAndLog("Warning: not enough raw bits to get a full UID");
		for (bit = 0; bit < rawbit; bit++) {
			bits[bit] = rawbits[i++];
			// As we cannot know the parity, let's use "." and "/"
			showbits[bit] = '.' + bits[bit];
		}
		showbits[bit+1]='\0';
		PrintAndLog("Partial UID=%s", showbits);
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
				uid1 = (uid1<<1) | (uid2>>31);
				uid2 = (uid2<<1) | 0;
			} else {
				uid1 = (uid1<<1) | (uid2>>31);
				uid2 = (uid2<<1) | 1;
			} 
		}
		PrintAndLog("UID=%s (%x%08x)", showbits, uid1, uid2);
	} else {
		uid3 = uid4 = uid5 = uid6 = uid7 = 0;

		for( idx=0; idx<224; idx++) {
			uid1 = (uid1<<1) | (uid2>>31);
			uid2 = (uid2<<1) | (uid3>>31);
			uid3 = (uid3<<1) | (uid4>>31);
			uid4 = (uid4<<1) | (uid5>>31);
			uid5 = (uid5<<1) | (uid6>>31);
			uid6 = (uid6<<1) | (uid7>>31);

			if (showbits[idx] == '0') 
				uid7 = (uid7<<1) | 0;
			else 
				uid7 = (uid7<<1) | 1;
		}
		PrintAndLog("UID=%s (%x%08x%08x%08x%08x%08x%08x)", showbits, uid1, uid2, uid3, uid4, uid5, uid6, uid7);
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

	PrintAndLog("Occurrences: %d (expected %d)", times, (rawbit - start) / uidlen);

	// Remodulating for tag cloning
	// HACK: 2015-01-04 this will have an impact on our new way of seening lf commands (demod) 
	// since this changes graphbuffer data.
	GraphTraceLen = 32 * uidlen;
	i = 0;
	int phase = 0;
	for (bit = 0; bit < uidlen; bit++) {
		phase = (bits[bit] == 0) ? 0 : 1;
		int j;
		for (j = 0; j < 32; j++) {
			GraphBuffer[i++] = phase;
			phase = !phase;
		}
	}

	RepaintGraphWindow();
	return 1;
}

int CmdIndalaClone(const char *Cmd){
	UsbCommand c;
	unsigned int uid1, uid2, uid3, uid4, uid5, uid6, uid7;

	uid1 =  uid2 = uid3 = uid4 = uid5 = uid6 = uid7 = 0;
	int n = 0, i = 0;

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
		PrintAndLog("Cloning 224bit tag with UID %x%08x%08x%08x%08x%08x%08x", uid1, uid2, uid3, uid4, uid5, uid6, uid7);
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
		PrintAndLog("Cloning 64bit tag with UID %x%08x", uid1, uid2);
		c.cmd = CMD_INDALA_CLONE_TAG;
		c.arg[0] = uid1;
		c.arg[1] = uid2;
	}

	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdLFSetConfig(const char *Cmd) {
	uint8_t divisor =  0;//Frequency divisor
	uint8_t bps = 0; // Bits per sample
	uint8_t decimation = 0; //How many to keep
	bool averaging = 1; // Defaults to true
	bool errors = FALSE;
	int trigger_threshold = -1;//Means no change
	uint8_t unsigned_trigg = 0;

	uint8_t cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'h':
			return usage_lf_config();
		case 'H':
			divisor = 88;
			cmdp++;
			break;
		case 'L':
			divisor = 95;
			cmdp++;
			break;
		case 'q':
			errors |= param_getdec(Cmd,cmdp+1,&divisor);
			cmdp+=2;
			break;
		case 't':
			errors |= param_getdec(Cmd,cmdp+1,&unsigned_trigg);
			cmdp+=2;
			if(!errors) trigger_threshold = unsigned_trigg;
			break;
		case 'b':
			errors |= param_getdec(Cmd,cmdp+1,&bps);
			cmdp+=2;
			break;
		case 'd':
			errors |= param_getdec(Cmd,cmdp+1,&decimation);
			cmdp+=2;
			break;
		case 'a':
			averaging = param_getchar(Cmd,cmdp+1) == '1';
			cmdp+=2;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = 1;
			break;
		}
		if(errors) break;
	}

	// No args
	if (cmdp == 0) errors = 1;

	//Validations
	if (errors) return usage_lf_config();
	
	//Bps is limited to 8, so fits in lower half of arg1
	if (bps >> 4) bps = 8;

	sample_config config = { decimation, bps, averaging, divisor, trigger_threshold };

	//Averaging is a flag on high-bit of arg[1]
	UsbCommand c = {CMD_SET_LF_SAMPLING_CONFIG};
	memcpy(c.d.asBytes,&config,sizeof(sample_config));
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdLFRead(const char *Cmd) {
	bool arg1 = false;
	uint8_t cmdp =  param_getchar(Cmd, 0);
	
	if ( cmdp == 'h' || cmdp == 'H') return usage_lf_read();
	
	 //suppress print
	if ( cmdp == 's' || cmdp == 'S') arg1 = true;

	UsbCommand c = {CMD_ACQUIRE_RAW_ADC_SAMPLES_125K, {arg1,0,0}};
	clearCommandBuffer();
	SendCommand(&c);
	if ( !WaitForResponseTimeout(CMD_ACK,NULL,2500) ) {
		PrintAndLog("command execution time out");
		return 1;
	}
	return 0;
}

int CmdLFSnoop(const char *Cmd) {
	uint8_t cmdp = param_getchar(Cmd, 0);
	if(cmdp == 'h' || cmdp == 'H') return usage_lf_snoop();
	
	UsbCommand c = {CMD_LF_SNOOP_RAW_ADC_SAMPLES};
	clearCommandBuffer();	
	SendCommand(&c);
	WaitForResponse(CMD_ACK,NULL);
	return 0;
}

static void ChkBitstream(const char *str) {
	// convert to bitstream if necessary
	for (int i = 0; i < (int)(GraphTraceLen / 2); i++){
		if (GraphBuffer[i] > 1 || GraphBuffer[i] < 0) {
			CmdGetBitStream("");
			break;
		}
	}
}
//Attempt to simulate any wave in buffer (one bit per output sample)
// converts GraphBuffer to bitstream (based on zero crossings) if needed.
int CmdLFSim(const char *Cmd) {
	int i,j;
	static int gap;

	sscanf(Cmd, "%i", &gap);

	// convert to bitstream if necessary 
	ChkBitstream(Cmd);

	//can send only 512 bits at a time (1 byte sent per bit...)
	printf("Sending [%d bytes]", GraphTraceLen);
	for (i = 0; i < GraphTraceLen; i += USB_CMD_DATA_SIZE) {
		UsbCommand c = {CMD_DOWNLOADED_SIM_SAMPLES_125K, {i, 0, 0}};

		for (j = 0; j < USB_CMD_DATA_SIZE; j++) {
			c.d.asBytes[j] = GraphBuffer[i+j];
		}
		clearCommandBuffer();
		SendCommand(&c);
		WaitForResponse(CMD_ACK,NULL);
		printf(".");
	}

	PrintAndLog("\nStarting to simulate");
	UsbCommand c = {CMD_SIMULATE_TAG_125K, {GraphTraceLen, gap, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

// by marshmellow - sim fsk data given clock, fcHigh, fcLow, invert 
// - allow pull data from DemodBuffer
int CmdLFfskSim(const char *Cmd)
{
	//might be able to autodetect FCs and clock from Graphbuffer if using demod buffer
	// otherwise will need FChigh, FClow, Clock, and bitstream
	uint8_t fcHigh = 0, fcLow = 0, clk = 0;
	uint8_t invert = 0;
	bool errors = FALSE;
	char hexData[32] = {0x00}; // store entered hex data
	uint8_t data[255] = {0x00}; 
	int dataLen = 0;
	uint8_t cmdp = 0;
	
	while(param_getchar(Cmd, cmdp) != 0x00) {
		switch(param_getchar(Cmd, cmdp)){
			case 'h':
				return usage_lf_simfsk();
			case 'i':
				invert = 1;
				cmdp++;
				break;
			case 'c':
				errors |= param_getdec(Cmd, cmdp+1, &clk);
				cmdp += 2;
				break;
			case 'H':
				errors |= param_getdec(Cmd, cmdp+1, &fcHigh);
				cmdp += 2;
				break;
			case 'L':
				errors |= param_getdec(Cmd, cmdp+1, &fcLow);
				cmdp += 2;
				break;
			//case 's':
			//  separator = 1;
			//  cmdp++;
			//  break;
			case 'd':
				dataLen = param_getstr(Cmd, cmdp+1, hexData);
				if (dataLen == 0)
					errors = TRUE; 
				else
					dataLen = hextobinarray((char *)data, hexData);
				   
				if (dataLen == 0) errors = TRUE; 
				if (errors) PrintAndLog ("Error getting hex data");
				cmdp+=2;
				break;
			default:
				PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = TRUE;
				break;
		}
		if(errors) break;
	}
	
	// No args
	if(cmdp == 0 && DemodBufferLen == 0)
		errors = TRUE;

	//Validations
	if(errors) return usage_lf_simfsk();

	if (dataLen == 0){ //using DemodBuffer 
		if (clk == 0 || fcHigh == 0 || fcLow == 0){ //manual settings must set them all
			uint8_t ans = fskClocks(&fcHigh, &fcLow, &clk, 0);
			if (ans==0){
				if (!fcHigh) fcHigh = 10;
				if (!fcLow) fcLow = 8;
				if (!clk) clk = 50;
			}
		}
	} else {
		setDemodBuf(data, dataLen, 0);
	}

	//default if not found
	if (clk == 0) clk = 50;
	if (fcHigh == 0) fcHigh = 10;
	if (fcLow == 0) fcLow = 8;

	uint16_t arg1, arg2;
	arg1 = fcHigh << 8 | fcLow;
	arg2 = invert << 8 | clk;
	size_t size = DemodBufferLen;
	if (size > USB_CMD_DATA_SIZE) {
		PrintAndLog("DemodBuffer too long for current implementation - length: %d - max: %d", size, USB_CMD_DATA_SIZE);
		size = USB_CMD_DATA_SIZE;
	} 
	UsbCommand c = {CMD_FSK_SIM_TAG, {arg1, arg2, size}};

	memcpy(c.d.asBytes, DemodBuffer, size);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

// by marshmellow - sim ask data given clock, invert, manchester or raw, separator 
// - allow pull data from DemodBuffer
int CmdLFaskSim(const char *Cmd)
{
	// autodetect clock from Graphbuffer if using demod buffer
	// needs clock, invert, manchester/raw as m or r, separator as s, and bitstream
	uint8_t encoding = 1, separator = 0, clk = 0, invert = 0;
	bool errors = FALSE;
	char hexData[32] = {0x00}; 
	uint8_t data[255]= {0x00}; // store entered hex data
	int dataLen = 0;
	uint8_t cmdp = 0;
	
	while(param_getchar(Cmd, cmdp) != 0x00) {
		switch(param_getchar(Cmd, cmdp)) {
			case 'h': return usage_lf_simask();
			case 'i':
				invert = 1;
				cmdp++;
				break;
			case 'c':
				errors |= param_getdec(Cmd, cmdp+1, &clk);
				cmdp += 2;
				break;
			case 'b':
				encoding = 2; //biphase
				cmdp++;
				break;
			case 'm':
				encoding = 1; //manchester
				cmdp++;
				break;
			case 'r':
				encoding = 0; //raw
				cmdp++;
				break;
			case 's':
				separator = 1;
				cmdp++;
				break;
			case 'd':
				dataLen = param_getstr(Cmd, cmdp+1, hexData);
				if (dataLen == 0)
					errors = TRUE; 
				else
					dataLen = hextobinarray((char *)data, hexData);
				
				if (dataLen == 0) errors = TRUE; 
				if (errors) PrintAndLog ("Error getting hex data, datalen: %d", dataLen);
				cmdp += 2;
				break;
			default:
				PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = TRUE;
				break;
		}
		if(errors) break;
	}

	// No args
	if(cmdp == 0 && DemodBufferLen == 0)
		errors = TRUE;

	//Validations
	if(errors) return usage_lf_simask();
	
	if (dataLen == 0){ //using DemodBuffer
		if (clk == 0) 
			clk = GetAskClock("0", false, false);
	} else {
		setDemodBuf(data, dataLen, 0);
	}
	if (clk == 0) clk = 64;
	if (encoding == 0) clk = clk/2; //askraw needs to double the clock speed
	
	size_t size = DemodBufferLen;

	if (size > USB_CMD_DATA_SIZE) {
		PrintAndLog("DemodBuffer too long for current implementation - length: %d - max: %d", size, USB_CMD_DATA_SIZE);
		size = USB_CMD_DATA_SIZE;
	}
	
	PrintAndLog("preparing to sim ask data: %d bits", size);	

	uint16_t arg1, arg2;	
	arg1 = clk << 8 | encoding;
	arg2 = invert << 8 | separator;

	UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};
	memcpy(c.d.asBytes, DemodBuffer, size);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

// by marshmellow - sim psk data given carrier, clock, invert 
// - allow pull data from DemodBuffer or parameters
int CmdLFpskSim(const char *Cmd) {
	//might be able to autodetect FC and clock from Graphbuffer if using demod buffer
	//will need carrier, Clock, and bitstream
	uint8_t carrier=0, clk=0;
	uint8_t invert=0;
	bool errors = FALSE;
	char hexData[32] = {0x00}; // store entered hex data
	uint8_t data[255] = {0x00}; 
	int dataLen = 0;
	uint8_t cmdp = 0;
	uint8_t pskType = 1;
	
	while(param_getchar(Cmd, cmdp) != 0x00)	{
		switch(param_getchar(Cmd, cmdp)) {
			case 'h':
				return usage_lf_simpsk();
			case 'i':
				invert = 1;
				cmdp++;
				break;
			case 'c':
				errors |= param_getdec(Cmd,cmdp+1,&clk);
				cmdp +=2;
				break;
			case 'r':
				errors |= param_getdec(Cmd,cmdp+1,&carrier);
				cmdp += 2;
				break;
			case '1':
				pskType = 1;
				cmdp++;
				break;
			case '2':
				pskType = 2;
				cmdp++;
				break;
			case '3':
				pskType = 3;
				cmdp++;
				break;
			case 'd':
				dataLen = param_getstr(Cmd, cmdp+1, hexData);
				if (dataLen == 0)
					errors = TRUE; 
				else
					dataLen = hextobinarray((char *)data, hexData);
				    
				if (dataLen == 0) errors = TRUE; 
				if (errors) PrintAndLog ("Error getting hex data");
				cmdp+=2;
				break;
			default:
				PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = TRUE;
				break;
			}
		if (errors) break;
	}
	// No args
	if (cmdp == 0 && DemodBufferLen == 0)
		errors = TRUE;

	//Validations
	if (errors) return usage_lf_simpsk();

	if (dataLen == 0){ //using DemodBuffer
		PrintAndLog("Getting Clocks");
		
		if (clk==0) clk = GetPskClock("", FALSE, FALSE);
		PrintAndLog("clk: %d",clk);
		
		if (!carrier) carrier = GetPskCarrier("", FALSE, FALSE); 
		PrintAndLog("carrier: %d", carrier);
		
	} else {
		setDemodBuf(data, dataLen, 0);
	}

	if (clk <= 0) clk = 32;

	if (carrier == 0) carrier = 2;
  
	if (pskType != 1){
		if (pskType == 2){
			//need to convert psk2 to psk1 data before sim
			psk2TOpsk1(DemodBuffer, DemodBufferLen);
		} else {
			PrintAndLog("Sorry, PSK3 not yet available");
		}
	}
	uint16_t arg1, arg2;
	arg1 = clk << 8 | carrier;
	arg2 = invert;
	size_t size = DemodBufferLen;
	if (size > USB_CMD_DATA_SIZE) {
		PrintAndLog("DemodBuffer too long for current implementation - length: %d - max: %d", size, USB_CMD_DATA_SIZE);
		size = USB_CMD_DATA_SIZE;
	}
	UsbCommand c = {CMD_PSK_SIM_TAG, {arg1, arg2, size}};
	PrintAndLog("DEBUG: Sending DemodBuffer Length: %d", size);
	memcpy(c.d.asBytes, DemodBuffer, size);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdLFSimBidir(const char *Cmd) {
	// Set ADC to twice the carrier for a slight supersampling
	// HACK: not implemented in ARMSRC.
	PrintAndLog("Not implemented yet.");
	UsbCommand c = {CMD_LF_SIMULATE_BIDIR, {47, 384, 0}};
	SendCommand(&c);
	return 0;
}

int CmdVchDemod(const char *Cmd) {
	// Is this the entire sync pattern, or does this also include some
	// data bits that happen to be the same everywhere? That would be
	// lovely to know.
	static const int SyncPattern[] = {
		1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	};

	// So first, we correlate for the sync pattern, and mark that.
	int bestCorrel = 0, bestPos = 0;
	int i, j, sum = 0;

	// It does us no good to find the sync pattern, with fewer than 2048 samples after it.

	for (i = 0; i < (GraphTraceLen - 2048); i++) {
		for (j = 0; j < ARRAYLEN(SyncPattern); j++) {
			sum += GraphBuffer[i+j] * SyncPattern[j];
		}
		if (sum > bestCorrel) {
			bestCorrel = sum;
			bestPos = i;
		}
	}
	PrintAndLog("best sync at %d [metric %d]", bestPos, bestCorrel);

	char bits[257];
	bits[256] = '\0';

	int worst = INT_MAX, worstPos = 0;

	for (i = 0; i < 2048; i += 8) {
		sum = 0;
		for (j = 0; j < 8; j++) 
			sum += GraphBuffer[bestPos+i+j];
		
		if (sum < 0)
			bits[i/8] = '.';
		else
			bits[i/8] = '1';
		
		if(abs(sum) < worst) {
			worst = abs(sum);
			worstPos = i;
		}
	}
	PrintAndLog("bits:");
	PrintAndLog("%s", bits);
	PrintAndLog("worst metric: %d at pos %d", worst, worstPos);

	// clone
	if (strcmp(Cmd, "clone")==0) {
		GraphTraceLen = 0;
		char *s;
			for(s = bits; *s; s++) {
				for(j = 0; j < 16; j++) {
					GraphBuffer[GraphTraceLen++] = (*s == '1') ? 1 : 0;
				}
			}
		RepaintGraphWindow();
	}
	return 0;
}

//by marshmellow
int CmdLFfind(const char *Cmd) {
	int ans = 0;
	char cmdp = param_getchar(Cmd, 0);
	char testRaw = param_getchar(Cmd, 1);
	if (strlen(Cmd) > 3 || cmdp == 'h' || cmdp == 'H') return usage_lf_find();

	if (!offline && (cmdp != '1')){
		CmdLFRead("s");
		getSamples("30000",false);
	} else if (GraphTraceLen < 1000) {
		PrintAndLog("Data in Graphbuffer was too small.");
		return 0;
	}
	if (cmdp == 'u' || cmdp == 'U') testRaw = 'u';

	PrintAndLog("NOTE: some demods output possible binary\n  if it finds something that looks like a tag");
	PrintAndLog("False Positives ARE possible\n");  
	PrintAndLog("\nChecking for known tags:\n");

	ans=CmdFSKdemodIO("");
	if (ans>0) {
		PrintAndLog("\nValid IO Prox ID Found!");
		return 1;
	}
	ans=CmdFSKdemodPyramid("");
	if (ans>0) {
		PrintAndLog("\nValid Pyramid ID Found!");
		return 1;
	}
	ans=CmdFSKdemodParadox("");
	if (ans>0) {
		PrintAndLog("\nValid Paradox ID Found!");
		return 1;
	}
	ans=CmdFSKdemodAWID("");
	if (ans>0) {
		PrintAndLog("\nValid AWID ID Found!");
		return 1;
	}
	ans=CmdFSKdemodHID("");
	if (ans>0) {
		PrintAndLog("\nValid HID Prox ID Found!");
		return 1;
	}
	ans=CmdAskEM410xDemod("");
	if (ans>0) {
		PrintAndLog("\nValid EM410x ID Found!");
		return 1;
	}
	ans=CmdG_Prox_II_Demod("");
	if (ans>0) {
		PrintAndLog("\nValid Guardall G-Prox II ID Found!");
		return 1;
	}
	ans=CmdFDXBdemodBI("");
	if (ans>0) {
		PrintAndLog("\nValid FDX-B ID Found!");
		return 1;
	}
	ans=EM4x50Read("", false);
	if (ans>0) {
		PrintAndLog("\nValid EM4x50 ID Found!");
		return 1;
	}	
	ans=CmdVikingDemod("");
	if (ans>0) {
		PrintAndLog("\nValid Viking ID Found!");
		return 1;
	}	
	ans=CmdIndalaDecode("");
	if (ans>0) {
		PrintAndLog("\nValid Indala ID Found!");
		return 1;
	}
	ans=CmdPSKNexWatch("");
	if (ans>0) {
		PrintAndLog("\nValid NexWatch ID Found!");
		return 1;
	}
	ans=CmdJablotronDemod("");
	if (ans>0) {
		PrintAndLog("\nValid Jablotron ID Found!");
		return 1;
	}
	ans=CmdLFNedapDemod("");
	if (ans>0) {
		PrintAndLog("\nValid NEDAP ID Found!");
		return 1;
	}
	// TIdemod?
	

	PrintAndLog("\nNo Known Tags Found!\n");
	if (testRaw=='u' || testRaw=='U'){
		//test unknown tag formats (raw mode)
		PrintAndLog("\nChecking for Unknown tags:\n");
		ans=AutoCorrelate(4000, FALSE, FALSE);
	
		if (ans > 0) {

			PrintAndLog("Possible Auto Correlation of %d repeating samples",ans);

			if ( ans % 8 == 0)  {
				int bytes = (ans / 8);
				PrintAndLog("Possible %d bytes", bytes);
				int blocks = 0;
				if ( bytes % 2 == 0) {
					blocks = (bytes / 2);	
					PrintAndLog("Possible  2 blocks, width %d", blocks);
				}
				if ( bytes % 4 == 0) {
					blocks = (bytes / 4);	
					PrintAndLog("Possible  4 blocks, width %d", blocks);
				}
				if ( bytes % 8 == 0) {
					blocks = (bytes / 8);	
					PrintAndLog("Possible  8 blocks, width %d", blocks);
				}
				if ( bytes % 16 == 0) {
					blocks = (bytes / 16);	
					PrintAndLog("Possible 16 blocks, width %d", blocks);
				}
			}
		}

		ans=GetFskClock("",FALSE,FALSE); 
		if (ans != 0){ //fsk
			ans=FSKrawDemod("",TRUE);
			if (ans>0) {
				PrintAndLog("\nUnknown FSK Modulated Tag Found!");
				return 1;
			}
		}
		bool st = TRUE;
		ans=ASKDemod_ext("0 0 0",TRUE,FALSE,1,&st);
		if (ans>0) {
		  PrintAndLog("\nUnknown ASK Modulated and Manchester encoded Tag Found!");
		  PrintAndLog("\nif it does not look right it could instead be ASK/Biphase - try 'data rawdemod ab'");
		  return 1;
		}
		
		ans=CmdPSK1rawDemod("");
		if (ans>0) {
			PrintAndLog("Possible unknown PSK1 Modulated Tag Found above!\n\nCould also be PSK2 - try 'data rawdemod p2'");
			PrintAndLog("\nCould also be PSK3 - [currently not supported]");
			PrintAndLog("\nCould also be NRZ - try 'data nrzrawdemod");
			return 1;
		}
		PrintAndLog("\nNo Data Found!\n");
	}
	return 0;
}

static command_t CommandTable[] = 
{
	{"help",        CmdHelp,            1, "This help"},
	{"awid",        CmdLFAWID,          1, "{ AWID RFIDs... }"},
	{"em4x",        CmdLFEM4X,          1, "{ EM4X RFIDs... }"},
	{"guard",       CmdLFGuard,         1, "{ Guardall RFIDs... }"},
	{"hid",         CmdLFHID,           1, "{ HID RFIDs... }"},
	{"hitag",       CmdLFHitag,         1, "{ HITAG RFIDs... }"},
	{"io",			CmdLFIO,			1, "{ IOPROX RFIDs... }"},
	{"jablotron",	CmdLFJablotron,		1, "{ JABLOTRON RFIDs... }"},
	{"nedap",		CmdLFNedap,			1, "{ NEDAP RFIDs... }"},
	{"pcf7931",     CmdLFPCF7931,       1, "{ PCF7931 RFIDs... }"},
	{"presco",      CmdLFPresco,        1, "{ Presco RFIDs... }"},
	{"pyramid",		CmdLFPyramid,       1, "{ Farpointe/Pyramid RFIDs... }"},	
	{"ti",          CmdLFTI,            1, "{ TI RFIDs... }"},
	{"t55xx",       CmdLFT55XX,         1, "{ T55xx RFIDs... }"},
	{"viking",      CmdLFViking,        1, "{ Viking RFIDs... }"},
	{"config",      CmdLFSetConfig,     0, "Set config for LF sampling, bit/sample, decimation, frequency"},
	{"cmdread",     CmdLFCommandRead,   0, "<off period> <'0' period> <'1' period> <command> ['h' 134] \n\t\t-- Modulate LF reader field to send command before read (all periods in microseconds)"},
	{"flexdemod",   CmdFlexdemod,       1, "Demodulate samples for FlexPass"},
	{"indalademod", CmdIndalaDemod,     1, "['224'] -- Demodulate samples for Indala 64 bit UID (option '224' for 224 bit)"},
	{"indalaclone", CmdIndalaClone,     0, "<UID> ['l']-- Clone Indala to T55x7 (tag must be in antenna)(UID in HEX)(option 'l' for 224 UID"},
	{"read",        CmdLFRead,          0, "['s' silent] Read 125/134 kHz LF ID-only tag. Do 'lf read h' for help"},
	{"search",      CmdLFfind,          1, "[offline] ['u'] Read and Search for valid known tag (in offline mode it you can load first then search) \n\t\t-- 'u' to search for unknown tags"},
	{"sim",         CmdLFSim,           0, "[GAP] -- Simulate LF tag from buffer with optional GAP (in microseconds)"},
	{"simask",      CmdLFaskSim,        0, "[clock] [invert <1|0>] [biphase/manchester/raw <'b'|'m'|'r'>] [msg separator 's'] [d <hexdata>] \n\t\t-- Simulate LF ASK tag from demodbuffer or input"},
	{"simfsk",      CmdLFfskSim,        0, "[c <clock>] [i] [H <fcHigh>] [L <fcLow>] [d <hexdata>] \n\t\t-- Simulate LF FSK tag from demodbuffer or input"},
	{"simpsk",      CmdLFpskSim,        0, "[1|2|3] [c <clock>] [i] [r <carrier>] [d <raw hex to sim>] \n\t\t-- Simulate LF PSK tag from demodbuffer or input"},
	{"simbidir",    CmdLFSimBidir,      0, "Simulate LF tag (with bidirectional data transmission between reader and tag)"},
	{"snoop",       CmdLFSnoop,         0, "['l'|'h'|<divisor>] [trigger threshold]-- Snoop LF (l:125khz, h:134khz)"},
	{"vchdemod",    CmdVchDemod,        1, "['clone'] -- Demodulate samples for VeriChip"},
	{NULL, NULL, 0, NULL}
};

int CmdLF(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0; 
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
