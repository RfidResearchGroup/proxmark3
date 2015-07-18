//-----------------------------------------------------------------------------
// Authored by Craig Young <cyoung@tripwire.com> based on cmdlfhid.c structure
//
// cmdlfhid.c is Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency AWID26 commands
//-----------------------------------------------------------------------------

#include <stdio.h>      // sscanf
#include "proxmark3.h"  // Definitions, USB controls, etc
#include "ui.h"         // PrintAndLog
#include "cmdparser.h"  // CmdsParse, CmdsHelp
#include "cmdlfawid.h"  // AWID function declarations
#include "lfdemod.h"    // parityTest

static int CmdHelp(const char *Cmd);


int usage_lf_awid_fskdemod(void) {
  PrintAndLog("Enables AWID26 compatible reader mode printing details of scanned AWID26 tags.");
  PrintAndLog("By default, values are printed and logged until the button is pressed or another USB command is issued.");
  PrintAndLog("If the ['1'] option is provided, reader mode is exited after reading a single AWID26 card.");
  PrintAndLog("");
  PrintAndLog("Usage:  lf awid fskdemod ['1']");
  PrintAndLog("  Options : ");
  PrintAndLog("  1 : (optional) stop after reading a single card");
  PrintAndLog("");
  PrintAndLog("   sample : lf awid fskdemod");
  PrintAndLog("          : lf awid fskdemod 1");
  return 0;
}

int usage_lf_awid_sim(void) {
  PrintAndLog("Enables simulation of AWID26 card with specified facility-code and card number.");
  PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
  PrintAndLog("Per AWID26 format, the facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
  PrintAndLog("");
  PrintAndLog("Usage:  lf awid sim <Facility-Code> <Card-Number>");
  PrintAndLog("  Options : ");
  PrintAndLog("  <Facility-Code> : 8-bit value representing the AWID facility code");
  PrintAndLog("  <Card Number>   : 16-bit value representing the AWID card number");
  PrintAndLog("");
  PrintAndLog("   sample : lf awid sim 224 1337");
  return 0;
}

int usage_lf_awid_clone(void) {
  PrintAndLog("Enables cloning of AWID26 card with specified facility-code and card number onto T55x7.");
  PrintAndLog("The T55x7 must be on the antenna when issuing this command.  T55x7 blocks are calculated and printed in the process.");
  PrintAndLog("Per AWID26 format, the facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
  PrintAndLog("");
  PrintAndLog("Usage:  lf awid clone <Facility-Code> <Card-Number>");
  PrintAndLog("  Options : ");
  PrintAndLog("  <Facility-Code> : 8-bit value representing the AWID facility code");
  PrintAndLog("  <Card Number>   : 16-bit value representing the AWID card number");
  PrintAndLog("");
  PrintAndLog("   sample : lf awid clone 224 1337");
  return 0;
}

int CmdAWIDDemodFSK(const char *Cmd)
{
  int findone=0;
  if(Cmd[0]=='1') findone=1;
  if (Cmd[0]=='h' || Cmd[0] == 'H') return usage_lf_awid_fskdemod();
  UsbCommand c={CMD_AWID_DEMOD_FSK};
  c.arg[0]=findone;
  SendCommand(&c);
  return 0;   
}

int getAWIDBits(unsigned int fc, unsigned int cn, uint8_t *AWIDBits)
{
  int i;
  uint32_t fcode=(fc & 0x000000FF), cnum=(cn & 0x0000FFFF), uBits=0;
  if (fcode != fc)
    PrintAndLog("NOTE: Facility code truncated for AWID26 format (8-bit facility code)");
  if (cnum!=cn)
    PrintAndLog("NOTE: Card number was truncated for AWID26 format (16-bit card number)");

  AWIDBits[0] = 0x01; // 6-bit Preamble with 2 parity bits
  AWIDBits[1] = 0x1D; // First byte from card format (26-bit) plus parity bits
  AWIDBits[2] = 0x80; // Set the next two bits as 0b10 to finish card format
  uBits = (fcode<<4) + (cnum>>12);
  if (!parityTest(uBits,12,0))
    AWIDBits[2] |= (1<<5); // If not already even parity, set bit to make even
  uBits = AWIDBits[2]>>5;
  if (!parityTest(uBits, 3, 1))
    AWIDBits[2] |= (1<<4);
  uBits = fcode>>5; // first 3 bits of facility-code
  AWIDBits[2] += (uBits<<1);
  if (!parityTest(uBits, 3, 1))
    AWIDBits[2]++; // Set parity bit to make odd parity
  uBits = (fcode & 0x1C)>>2;
  AWIDBits[3] = 0;
  if (!parityTest(uBits,3,1))
    AWIDBits[3] |= (1<<4);
  AWIDBits[3] += (uBits<<5);
  uBits = ((fcode & 0x3)<<1) + ((cnum & 0x8000)>>15); // Grab/shift 2 LSBs from facility code and add shifted MSB from cardnum
  if (!parityTest(uBits,3,1))
    AWIDBits[3]++; // Set LSB for parity
  AWIDBits[3]+= (uBits<<1);
  uBits = (cnum & 0x7000)>>12;
  AWIDBits[4] = uBits<<5;
  if (!parityTest(uBits,3,1))
    AWIDBits[4] |= (1<<4);
  uBits = (cnum & 0x0E00)>>9;
  AWIDBits[4] += (uBits<<1);
  if (!parityTest(uBits,3,1))
    AWIDBits[4]++; // Set LSB for parity
  uBits = (cnum & 0x1C0)>>6; // Next bits from card number
  AWIDBits[5]=(uBits<<5);
  if (!parityTest(uBits,3,1))
    AWIDBits[5] |= (1<<4); // Set odd parity bit as needed
  uBits = (cnum & 0x38)>>3;
  AWIDBits[5]+= (uBits<<1);
  if (!parityTest(uBits,3,1))
    AWIDBits[5]++; // Set odd parity bit as needed
  uBits = (cnum & 0x7); // Last three bits from card number!
  AWIDBits[6] = (uBits<<5);
  if (!parityTest(uBits,3,1))
    AWIDBits[6] |= (1<<4);
  uBits = (cnum & 0x0FFF);
  if (!parityTest(uBits,12,1))
    AWIDBits[6] |= (1<<3);
  else
    AWIDBits[6]++;
  for (i = 7; i<12; i++)
    AWIDBits[i]=0x11;
  return 1;
}

int CmdAWIDSim(const char *Cmd)
{
  uint32_t fcode = 0, cnum = 0, fc=0, cn=0, i=0;
  uint8_t *BS, BitStream[12];
  uint64_t arg1 = (10<<8) + 8; // fcHigh = 10, fcLow = 8
  uint64_t arg2 = 50; // clk RF/50 invert=0
  BS = BitStream;
  if (sscanf(Cmd, "%u %u", &fc, &cn ) != 2) {
    return usage_lf_awid_sim();
  }

  fcode=(fc & 0x000000FF);
  cnum=(cn & 0x0000FFFF);
  if (fc!=fcode)
    PrintAndLog("Facility-Code (%u) truncated to 8-bits: %u",fc,fcode);
  if (cn!=cnum)
    PrintAndLog("Card number (%u) truncated to 16-bits: %u",cn,cnum);
  PrintAndLog("Emulating AWID26 -- FC: %u; CN: %u\n",fcode,cnum);
  PrintAndLog("Press pm3-button to abort simulation or run another command");
  // AWID uses: fcHigh: 10, fcLow: 8, clk: 50, invert: 0
  if (getAWIDBits(fc, cn, BS)) {
      PrintAndLog("Running 'lf simfsk c 50 H 10 L 8 d %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x'", 
                                        BS[0],BS[1],BS[2],BS[3],BS[4],BS[5],BS[6],
                                        BS[7],BS[8],BS[9],BS[10],BS[11]);
    } else
      PrintAndLog("Error with tag bitstream generation.");
  UsbCommand c;
  c.cmd = CMD_FSK_SIM_TAG;
  c.arg[0] = arg1; // fcHigh<<8 + fcLow
  c.arg[1] = arg2; // Inversion and clk setting
  c.arg[2] = 96; // Bitstream length: 96-bits == 12 bytes
  for (i=0; i < 96; i++)
    c.d.asBytes[i] = (BS[i/8] & (1<<(7-(i%8))))?1:0;
  SendCommand(&c);
  return 0;
}

int CmdAWIDClone(const char *Cmd)
{
  uint32_t fc=0,cn=0,blocks[4] = {0x00107060, 0, 0, 0x11111111}, i=0;
  uint8_t BitStream[12];
  uint8_t *BS=BitStream;
  UsbCommand c;
  

  if (sscanf(Cmd, "%u %u", &fc, &cn ) != 2) {
    return usage_lf_awid_clone();
  }

  if ((fc & 0xFF) != fc) {
    fc &= 0xFF;
    PrintAndLog("Facility-Code Truncated to 8-bits (AWID26): %u", fc);
  }
  if ((cn & 0xFFFF) != cn) {
    cn &= 0xFFFF;
    PrintAndLog("Card Number Truncated to 16-bits (AWID26): %u", cn);
  }
  if (getAWIDBits(fc,cn,BS)) {
    PrintAndLog("Preparing to clone AWID26 to T55x7 with FC: %u, CN: %u (Raw: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x)", 
                  fc,cn, BS[0],BS[1],BS[2],BS[3],BS[4],BS[5],BS[6],BS[7],BS[8],BS[9],BS[10],BS[11]);
    blocks[1] = (BS[0]<<24) + (BS[1]<<16) + (BS[2]<<8) + (BS[3]);
    blocks[2] = (BS[4]<<24) + (BS[5]<<16) + (BS[6]<<8) + (BS[7]);
    PrintAndLog("Block 0: 0x%08x", blocks[0]);
    PrintAndLog("Block 1: 0x%08x", blocks[1]);
    PrintAndLog("Block 2: 0x%08x", blocks[2]);
    PrintAndLog("Block 3: 0x%08x", blocks[3]);
    for (i=0; i<4; i++) {
      c.cmd = CMD_T55XX_WRITE_BLOCK;
      c.arg[0] = blocks[i];
      c.arg[1] = i;
      c.arg[2] = 0;
      SendCommand(&c);
    }
  }
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",      CmdHelp,        1, "This help"},
  {"fskdemod",  CmdAWIDDemodFSK, 0, "['1'] Realtime AWID FSK demodulator (option '1' for one tag only)"},
  {"sim",       CmdAWIDSim,      0, "<Facility-Code> <Card Number> -- AWID tag simulator"},
  {"clone",     CmdAWIDClone,    0, "<Facility-Code> <Card Number> -- Clone AWID to T55x7 (tag must be in range of antenna)"},
  {NULL, NULL, 0, NULL}
};

int CmdLFAWID(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
