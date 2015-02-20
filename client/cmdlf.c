//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "proxmark3.h"
#include "data.h"
#include "graph.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "cmddata.h"
#include "util.h"
#include "cmdlf.h"
#include "cmdlfhid.h"
#include "cmdlfti.h"
#include "cmdlfem4x.h"
#include "cmdlfhitag.h"
#include "cmdlft55xx.h"
#include "cmdlfpcf7931.h"
#include "cmdlfio.h"

static int CmdHelp(const char *Cmd);

/* send a command before reading */
int CmdLFCommandRead(const char *Cmd)
{
  static char dummy[3];

  dummy[0]= ' ';

  UsbCommand c = {CMD_MOD_THEN_ACQUIRE_RAW_ADC_SAMPLES_125K};
  sscanf(Cmd, "%"lli" %"lli" %"lli" %s %s", &c.arg[0], &c.arg[1], &c.arg[2],(char*)(&c.d.asBytes),(char*)(&dummy+1));
  // in case they specified 'h'
  strcpy((char *)&c.d.asBytes + strlen((char *)c.d.asBytes), dummy);
  SendCommand(&c);
  return 0;
}

int CmdFlexdemod(const char *Cmd)
{
  int i;
  for (i = 0; i < GraphTraceLen; ++i) {
    if (GraphBuffer[i] < 0) {
      GraphBuffer[i] = -1;
    } else {
      GraphBuffer[i] = 1;
    }
  }

#define LONG_WAIT 100
  int start;
  for (start = 0; start < GraphTraceLen - LONG_WAIT; start++) {
    int first = GraphBuffer[start];
    for (i = start; i < start + LONG_WAIT; i++) {
      if (GraphBuffer[i] != first) {
        break;
      }
    }
    if (i == (start + LONG_WAIT)) {
      break;
    }
  }
  if (start == GraphTraceLen - LONG_WAIT) {
    PrintAndLog("nothing to wait for");
    return 0;
  }

  GraphBuffer[start] = 2;
  GraphBuffer[start+1] = -2;
	uint8_t bits[64] = {0x00};

	int bit, sum;
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
    int j;
    int sum = 0;
    for (j = 0; j < 16; j++) {
      sum += GraphBuffer[i++];
    }
    if (sum > 0 && bits[bit] != 1) {
      PrintAndLog("oops1 at %d", bit);
    }
    if (sum < 0 && bits[bit] != 0) {
      PrintAndLog("oops2 at %d", bit);
    }
  }

	// HACK writing back to graphbuffer.
  GraphTraceLen = 32*64;
  i = 0;
  int phase = 0;
  for (bit = 0; bit < 64; bit++) {
	
		phase = (bits[bit] == 0) ? 0 : 1;
		
    int j;
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
  int rawbit = 0;
  int worst = 0, worstPos = 0;
 // PrintAndLog("Expecting a bit less than %d raw bits", GraphTraceLen / 32);
  for (i = 0; i < GraphTraceLen-1; i += 2) {
    count += 1;
    if ((GraphBuffer[i] > GraphBuffer[i + 1]) && (state != 1)) {
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
        uid1=(uid1<<1)|(uid2>>31);
        uid2=(uid2<<1)|0;
        } else {
        uid1=(uid1<<1)|(uid2>>31);
        uid2=(uid2<<1)|1;
        } 
      }
    PrintAndLog("UID=%s (%x%08x)", showbits, uid1, uid2);
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

int CmdIndalaClone(const char *Cmd)
{
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

  SendCommand(&c);
  return 0;
}

int usage_lf_read()
{
	PrintAndLog("Usage: lf read");
	PrintAndLog("Options:        ");
	PrintAndLog("       h            This help");
	PrintAndLog("This function takes no arguments. ");
	PrintAndLog("Use 'lf config' to set parameters.");
	return 0;
}
int usage_lf_snoop()
{
	PrintAndLog("Usage: lf snoop");
	PrintAndLog("Options:        ");
	PrintAndLog("       h            This help");
	PrintAndLog("This function takes no arguments. ");
	PrintAndLog("Use 'lf config' to set parameters.");
	return 0;
}

int usage_lf_config()
{
	PrintAndLog("Usage: lf config [H|<divisor>] [b <bps>] [d <decim>] [a 0|1]");
	PrintAndLog("Options:        ");
	PrintAndLog("       h             This help");
	PrintAndLog("       L             Low frequency (125 KHz)");
	PrintAndLog("       H             High frequency (134 KHz)");
	PrintAndLog("       q <divisor>   Manually set divisor. 88-> 134KHz, 95-> 125 Hz");
	PrintAndLog("       b <bps>       Sets resolution of bits per sample. Default (max): 8");
	PrintAndLog("       d <decim>     Sets decimation. A value of N saves only 1 in N samples. Default: 1");
	PrintAndLog("       a [0|1]       Averaging - if set, will average the stored sample value when decimating. Default: 1");
	PrintAndLog("       t <threshold> Sets trigger threshold. 0 means no threshold");
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

int CmdLFSetConfig(const char *Cmd)
{

	uint8_t divisor =  0;//Frequency divisor
	uint8_t bps = 0; // Bits per sample
	uint8_t decimation = 0; //How many to keep
	bool averaging = 1; // Defaults to true
	bool errors = FALSE;
	int trigger_threshold =-1;//Means no change
	uint8_t unsigned_trigg = 0;

	uint8_t cmdp =0;
	while(param_getchar(Cmd, cmdp) != 0x00)
	{
		switch(param_getchar(Cmd, cmdp))
		{
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
	if(cmdp == 0)
	{
		errors = 1;// No args
	}

	//Validations
	if(errors)
	{
		return usage_lf_config();
	}
	//Bps is limited to 8, so fits in lower half of arg1
	if(bps >> 8) bps = 8;

	sample_config config = {
		decimation,bps,averaging,divisor,trigger_threshold
	};
	//Averaging is a flag on high-bit of arg[1]
	UsbCommand c = {CMD_SET_LF_SAMPLING_CONFIG};
	memcpy(c.d.asBytes,&config,sizeof(sample_config));
	SendCommand(&c);
	return 0;
}

int CmdLFRead(const char *Cmd)
{

	uint8_t cmdp =0;
	if(param_getchar(Cmd, cmdp) == 'h')
	{
		return usage_lf_read();
	}
	//And ship it to device
	UsbCommand c = {CMD_ACQUIRE_RAW_ADC_SAMPLES_125K};
	SendCommand(&c);
	WaitForResponse(CMD_ACK,NULL);
	return 0;
}

int CmdLFSnoop(const char *Cmd)
{
	uint8_t cmdp =0;
	if(param_getchar(Cmd, cmdp) == 'h')
	{
		return usage_lf_snoop();
	}

	UsbCommand c = {CMD_LF_SNOOP_RAW_ADC_SAMPLES};
	SendCommand(&c);
	WaitForResponse(CMD_ACK,NULL);
	return 0;
}

static void ChkBitstream(const char *str)
{
  int i;

  /* convert to bitstream if necessary */
	for (i = 0; i < (int)(GraphTraceLen / 2); i++){
		if (GraphBuffer[i] > 1 || GraphBuffer[i] < 0) {
      CmdBitstream(str);
      break;
    }
  }
}
//appears to attempt to simulate manchester
int CmdLFSim(const char *Cmd)
{
	int i,j;
  static int gap;

  sscanf(Cmd, "%i", &gap);

  /* convert to bitstream if necessary */
  ChkBitstream(Cmd);

  //can send 512 bits at a time (1 byte sent per bit...)
	printf("Sending [%d bytes]", GraphTraceLen);
	for (i = 0; i < GraphTraceLen; i += USB_CMD_DATA_SIZE) {
    UsbCommand c={CMD_DOWNLOADED_SIM_SAMPLES_125K, {i, 0, 0}};

		for (j = 0; j < USB_CMD_DATA_SIZE; j++) {
      c.d.asBytes[j] = GraphBuffer[i+j];
    }
    SendCommand(&c);
    WaitForResponse(CMD_ACK,NULL);
		printf(".");
  }

	printf("\n");
	PrintAndLog("Starting to simulate");
  UsbCommand c = {CMD_SIMULATE_TAG_125K, {GraphTraceLen, gap, 0}};
  SendCommand(&c);
  return 0;
}

int usage_lf_simfsk(void)
{
  //print help
  PrintAndLog("Usage: lf simfsk [c <clock>] [i] [H <fcHigh>] [L <fcLow>] [d <hexdata>]");
  PrintAndLog("Options:        ");
  PrintAndLog("       h              This help");
  PrintAndLog("       c <clock>      Manually set clock - can autodetect if using DemodBuffer");
  PrintAndLog("       i              invert data");
  PrintAndLog("       H <fcHigh>     Manually set the larger Field Clock");
  PrintAndLog("       L <fcLow>      Manually set the smaller Field Clock");
  //PrintAndLog("       s              TBD- -to enable a gap between playback repetitions - default: no gap");
  PrintAndLog("       d <hexdata>    Data to sim as hex - omit to sim from DemodBuffer");
  return 0;
}

int usage_lf_simask(void)
{
  //print help
  PrintAndLog("Usage: lf simask [c <clock>] [i] [m|r] [s] [d <raw hex to sim>]");
  PrintAndLog("Options:        ");
  PrintAndLog("       h              This help");
  PrintAndLog("       c <clock>      Manually set clock - can autodetect if using DemodBuffer");
  PrintAndLog("       i              invert data");
  PrintAndLog("       m              sim ask/manchester");
  PrintAndLog("       r              sim ask/raw");
  PrintAndLog("       s              TBD- -to enable a gap between playback repetitions - default: no gap");
  PrintAndLog("       d <hexdata>    Data to sim as hex - omit to sim from DemodBuffer");
  return 0;
}

// by marshmellow - sim ask data given clock, fcHigh, fcLow, invert 
// - allow pull data from DemodBuffer
int CmdLFfskSim(const char *Cmd)
{
  //todo - allow data from demodbuffer or parameters
  //might be able to autodetect FC and clock from Graphbuffer if using demod buffer
  //will need FChigh, FClow, Clock, and bitstream
  uint8_t fcHigh=0, fcLow=0, clk=0;
  uint8_t invert=0;
  bool errors = FALSE;
  char hexData[32] = {0x00}; // store entered hex data
  uint8_t data[255] = {0x00}; 
  int dataLen = 0;
  uint8_t cmdp = 0;
  while(param_getchar(Cmd, cmdp) != 0x00)
  {
    switch(param_getchar(Cmd, cmdp))
    {
    case 'h':
      return usage_lf_simfsk();
    case 'i':
      invert = 1;
      cmdp++;
      break;
    case 'c':
      errors |= param_getdec(Cmd,cmdp+1,&clk);
      cmdp+=2;
      break;
    case 'H':
      errors |= param_getdec(Cmd,cmdp+1,&fcHigh);
      cmdp+=2;
      break;
    case 'L':
      errors |= param_getdec(Cmd,cmdp+1,&fcLow);
      cmdp+=2;
      break;
    //case 's':
    //  separator=1;
    //  cmdp++;
    //  break;
    case 'd':
      dataLen = param_getstr(Cmd, cmdp+1, hexData);
      if (dataLen==0) {
        errors=TRUE; 
      } else {
        dataLen = hextobinarray((char *)data, hexData);
      }    if (dataLen==0) errors=TRUE; 
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
  if(cmdp == 0 && DemodBufferLen == 0)
  {
    errors = TRUE;// No args
  }

  //Validations
  if(errors)
  {
    return usage_lf_simfsk();
  }
  if (dataLen == 0){ //using DemodBuffer
    if (clk==0 || fcHigh==0 || fcLow==0){
      uint8_t ans = fskClocks(&fcHigh, &fcLow, &clk, 0);
      if (ans==0){
        fcHigh=10;
        fcLow=8;
        clk=50;
      }
    }
  } else {
    setDemodBuf(data, dataLen, 0);
  }
  if (clk == 0) clk = 50;
  if (fcHigh == 0) fcHigh = 10;
  if (fcLow == 0) fcLow = 8;

  uint16_t arg1, arg2;
  arg1 = fcHigh << 8 | fcLow;
  arg2 = invert << 8 | clk;
  UsbCommand c = {CMD_FSK_SIM_TAG, {arg1, arg2, DemodBufferLen}};
  if (DemodBufferLen > USB_CMD_DATA_SIZE) {
    PrintAndLog("DemodBuffer too long for current implementation - length: %d - max: %d", DemodBufferLen, USB_CMD_DATA_SIZE);
  }
  memcpy(c.d.asBytes, DemodBuffer, DemodBufferLen);
  SendCommand(&c);
  return 0;
}

// by marshmellow - sim ask data given clock, invert, manchester or raw, separator 
// - allow pull data from DemodBuffer
int CmdLFaskSim(const char *Cmd)
{
  //todo - allow data from demodbuffer or parameters
  //autodetect clock from Graphbuffer if using demod buffer
  //will need clock, invert, manchester/raw as m or r, separator as s, and bitstream
  uint8_t manchester = 1, separator = 0;
  //char cmdp = Cmd[0], par3='m', par4=0;
  uint8_t clk=0, invert=0;
  bool errors = FALSE;
  char hexData[32] = {0x00}; 
  uint8_t data[255]= {0x00}; // store entered hex data
  int dataLen = 0;
  uint8_t cmdp = 0;
  while(param_getchar(Cmd, cmdp) != 0x00)
  {
    switch(param_getchar(Cmd, cmdp))
    {
    case 'h':
      return usage_lf_simask();
    case 'i':
      invert = 1;
      cmdp++;
      break;
    case 'c':
      errors |= param_getdec(Cmd,cmdp+1,&clk);
      cmdp+=2;
      break;
    case 'm':
      manchester=1;
      cmdp++;
      break;
    case 'r':
      manchester=0;
      cmdp++;
      break;
    case 's':
      separator=1;
      cmdp++;
      break;
    case 'd':
      dataLen = param_getstr(Cmd, cmdp+1, hexData);
      if (dataLen==0) {
        errors=TRUE; 
      } else {
        dataLen = hextobinarray((char *)data, hexData);
      }
      if (dataLen==0) errors=TRUE; 
      if (errors) PrintAndLog ("Error getting hex data, datalen: %d",dataLen);
        cmdp+=2;
      break;
    default:
      PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
      errors = TRUE;
      break;
    }
    if(errors) break;
  }
  if(cmdp == 0 && DemodBufferLen == 0)
  {
    errors = TRUE;// No args
  }

  //Validations
  if(errors)
  {
    return usage_lf_simask();
  }
  if (dataLen == 0){ //using DemodBuffer
    if (clk == 0) clk = GetAskClock("0", false, false);
  } else {
    setDemodBuf(data, dataLen, 0);
  }
  if (clk == 0) clk = 64;

  uint16_t arg1, arg2;
  arg1 = clk << 8 | manchester;
  arg2 = invert << 8 | separator;
  UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, DemodBufferLen}};
  if (DemodBufferLen > USB_CMD_DATA_SIZE) {
    PrintAndLog("DemodBuffer too long for current implementation - length: %d - max: %d", DemodBufferLen, USB_CMD_DATA_SIZE);
  }
  PrintAndLog("preparing to sim ask data: %d bits", DemodBufferLen);
  memcpy(c.d.asBytes, DemodBuffer, DemodBufferLen);
  SendCommand(&c);
  return 0;
}


int CmdLFSimBidir(const char *Cmd)
{
  // Set ADC to twice the carrier for a slight supersampling
  // HACK: not implemented in ARMSRC.
  PrintAndLog("Not implemented yet.");
  UsbCommand c = {CMD_LF_SIMULATE_BIDIR, {47, 384, 0}};
  SendCommand(&c);
  return 0;
}

/* simulate an LF Manchester encoded tag with specified bitstream, clock rate and inter-id gap */
int CmdLFSimManchester(const char *Cmd)
{
  static int clock, gap;
  static char data[1024], gapstring[8];

  sscanf(Cmd, "%i %s %i", &clock, &data[0], &gap);

  ClearGraph(0);

  for (int i = 0; i < strlen(data) ; ++i)
    AppendGraph(0, clock, data[i]- '0');

  CmdManchesterMod("");

  RepaintGraphWindow();

  sprintf(&gapstring[0], "%i", gap);
  CmdLFSim(gapstring);
  return 0;
}


int CmdVchDemod(const char *Cmd)
{
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
  int i;
  // It does us no good to find the sync pattern, with fewer than
  // 2048 samples after it...
  for (i = 0; i < (GraphTraceLen-2048); i++) {
    int sum = 0;
    int j;
    for (j = 0; j < arraylen(SyncPattern); j++) {
      sum += GraphBuffer[i+j]*SyncPattern[j];
    }
    if (sum > bestCorrel) {
      bestCorrel = sum;
      bestPos = i;
    }
  }
  PrintAndLog("best sync at %d [metric %d]", bestPos, bestCorrel);

  char bits[257];
  bits[256] = '\0';

  int worst = INT_MAX;
  int worstPos = 0;

  for (i = 0; i < 2048; i += 8) {
    int sum = 0;
    int j;
    for (j = 0; j < 8; j++) {
      sum += GraphBuffer[bestPos+i+j];
    }
    if (sum < 0) {
      bits[i/8] = '.';
    } else {
      bits[i/8] = '1';
    }
    if(abs(sum) < worst) {
      worst = abs(sum);
      worstPos = i;
    }
  }
  PrintAndLog("bits:");
  PrintAndLog("%s", bits);
  PrintAndLog("worst metric: %d at pos %d", worst, worstPos);

  if (strcmp(Cmd, "clone")==0) {
    GraphTraceLen = 0;
    char *s;
    for(s = bits; *s; s++) {
      int j;
      for(j = 0; j < 16; j++) {
        GraphBuffer[GraphTraceLen++] = (*s == '1') ? 1 : 0;
      }
    }
    RepaintGraphWindow();
  }
  return 0;
}

//by marshmellow
int CmdLFfind(const char *Cmd)
{
  int ans=0;
  char cmdp = param_getchar(Cmd, 0);
  char testRaw = param_getchar(Cmd, 1);
  if (strlen(Cmd) > 2 || cmdp == 'h' || cmdp == 'H') {
    PrintAndLog("Usage:  lf search <0|1> [u]");
    PrintAndLog("     <use data from Graphbuffer> , if not set, try reading data from tag.");
    PrintAndLog("     [Search for Unknown tags] , if not set, reads only known tags.");
    PrintAndLog("");
    PrintAndLog("    sample: lf search     = try reading data from tag & search for known tags");
    PrintAndLog("          : lf search 1   = use data from GraphBuffer & search for known tags");
    PrintAndLog("          : lf search u   = try reading data from tag & search for known and unknown tags");
    PrintAndLog("          : lf search 1 u = use data from GraphBuffer & search for known and unknown tags");

    return 0;
  }

  if (!offline && (cmdp != '1')){
    ans=CmdLFRead("");
    ans=CmdSamples("20000");
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
  //add psk and indala
  ans=CmdIndalaDecode("");
  if (ans>0) {
    PrintAndLog("\nValid Indala ID Found!");
    return 1;
  }
  ans=CmdAskEM410xDemod("");
  if (ans>0) {
    PrintAndLog("\nValid EM410x ID Found!");
    return 1;
  }
  PrintAndLog("\nNo Known Tags Found!\n");
  if (testRaw=='u' || testRaw=='U'){
    //test unknown tag formats (raw mode)
    PrintAndLog("\nChecking for Unknown tags:\n");
    ans=CmdDetectClockRate("f");
    if (ans != 0){ //fsk
      ans=CmdFSKrawdemod("");
      if (ans>0) {
        PrintAndLog("\nUnknown FSK Modulated Tag Found!");
        return 1;
      }
    }
    ans=Cmdaskmandemod("");
    if (ans>0) {
      PrintAndLog("\nUnknown ASK Modulated and Manchester encoded Tag Found!");
      return 1;
    }
    ans=CmdPSK1rawDemod("");
    if (ans>0) {
      PrintAndLog("Possible unknown PSK1 Modulated Tag Found above!\n\nCould also be PSK2 - try 'data psk2rawdemod'");
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
  {"cmdread",     CmdLFCommandRead,   0, "<off period> <'0' period> <'1' period> <command> ['h'] -- Modulate LF reader field to send command before read (all periods in microseconds) (option 'h' for 134)"},
  {"em4x",        CmdLFEM4X,          1, "{ EM4X RFIDs... }"},
  {"config",      CmdLFSetConfig,     0, "Set config for LF sampling, bit/sample, decimation, frequency"},
  {"flexdemod",   CmdFlexdemod,       1, "Demodulate samples for FlexPass"},
  {"hid",         CmdLFHID,           1, "{ HID RFIDs... }"},
  {"io",       	  CmdLFIO,	          1, "{ ioProx tags... }"},
  {"indalademod", CmdIndalaDemod,     1, "['224'] -- Demodulate samples for Indala 64 bit UID (option '224' for 224 bit)"},
  {"indalaclone", CmdIndalaClone,     0, "<UID> ['l']-- Clone Indala to T55x7 (tag must be in antenna)(UID in HEX)(option 'l' for 224 UID"},
  {"read",        CmdLFRead,          0, "Read 125/134 kHz LF ID-only tag. Do 'lf read h' for help"},
  {"search",      CmdLFfind,          1, "[offline] ['u'] Read and Search for valid known tag (in offline mode it you can load first then search) - 'u' to search for unknown tags"},
  {"sim",         CmdLFSim,           0, "[GAP] -- Simulate LF tag from buffer with optional GAP (in microseconds)"},
  {"simask",      CmdLFaskSim,        0, "[clock] [invert <1|0>] [manchester/raw <'m'|'r'>] [trs separator 's'] -- Simulate LF ASK tag from demodbuffer"},
  {"simfsk",      CmdLFfskSim,        0, "[invert <1|0>] -- Simulate LF FSK tag from demodbuffer"},
  {"simbidir",    CmdLFSimBidir,      0, "Simulate LF tag (with bidirectional data transmission between reader and tag)"},
  {"simman",      CmdLFSimManchester, 0, "<Clock> <Bitstream> [GAP] Simulate arbitrary Manchester LF tag"},
  {"snoop",       CmdLFSnoop,         0, "['l'|'h'|<divisor>] [trigger threshold]-- Snoop LF (l:125khz, h:134khz)"},
  {"ti",          CmdLFTI,            1, "{ TI RFIDs... }"},
  {"hitag",       CmdLFHitag,         1, "{ Hitag tags and transponders... }"},
  {"vchdemod",    CmdVchDemod,        1, "['clone'] -- Demodulate samples for VeriChip"},
  {"t55xx",       CmdLFT55XX,         1, "{ T55xx RFIDs... }"},
  {"pcf7931",     CmdLFPCF7931,       1, "{PCF7931 RFIDs...}"},
  {NULL, NULL, 0, NULL}
};

int CmdLF(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0; 
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
