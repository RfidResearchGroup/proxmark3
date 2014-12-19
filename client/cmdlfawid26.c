//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency AWID26 commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "proxmark3.h"
#include "ui.h"
#include "graph.h"
#include "cmdmain.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "cmdlfawid26.h"
#include "util.h"
#include "data.h"


static int CmdHelp(const char *Cmd);

int CmdClone(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);

	if (strlen(Cmd) < 1 || cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  lf awid26 write  []");
		PrintAndLog("     [], ");
		PrintAndLog("");
		PrintAndLog("     sample: lf awid26 write 26 2233");
		PrintAndLog("           : lf awid26 write 26 15 2233");
		return 0;
	}

	//sscanf(Cmd, "%d %d", &facilitycode, &cardno);

	// char block0 = "00107060";  
	// char block1 = "00107060";  
	// char block2 = "00107060";  
	// char block3 = "00107060";  

	
	
	// PrintAndLog("Writing block %d with data %08X", Block, Data);
	return 0;
}

// int CmdReadTrace(const char *Cmd)
// {

	// uint8_t bits[LF_BITSSTREAM_LEN] = {0x00};
	// uint8_t * bitstream = bits;
	
	// uint8_t si = 5;
	// uint32_t bl0     = PackBits(si, 32, bitstream);
	// uint32_t bl1     = PackBits(si+32, 32, bitstream);
	
	// uint32_t acl     = PackBits(si,  8, bitstream); si += 8;
	// uint32_t mfc     = PackBits(si, 8, bitstream); si += 8;
	// uint32_t cid     = PackBits(si, 5, bitstream); si += 5;
	// uint32_t icr     = PackBits(si, 3, bitstream); si += 3;
	// uint32_t year    = PackBits(si, 4, bitstream); si += 4;
	// uint32_t quarter = PackBits(si, 2, bitstream); si += 2;
	// uint32_t lotid    = PackBits(si, 12, bitstream); si += 12;
	// uint32_t wafer   = PackBits(si, 5, bitstream); si += 5;
	// uint32_t dw      = PackBits(si, 15, bitstream); 
	
	// PrintAndLog("");
	// PrintAndLog("-- T55xx Trace Information ----------------------------------");
	// PrintAndLog("-------------------------------------------------------------");
	// PrintAndLog(" ACL Allocation class (ISO/IEC 15963-1)  : 0x%02X (%d)", acl, acl);
	// PrintAndLog(" MFC Manufacturer ID (ISO/IEC 7816-6)    : 0x%02X (%d)", mfc, mfc);
	// PrintAndLog(" CID                                     : 0x%02X (%d)", cid, cid);
	// PrintAndLog(" ICR IC Revision                         : %d",icr );
	
	
  // return 0;
// }

static command_t CommandTable[] =
{
  {"help",   CmdHelp,        1, "This help"},
  {"clone",  CmdClone,    0, "<facility> <id> -- clone to a t55xx tag"},
  {NULL, NULL, 0, NULL}
};

int CmdLFAWID26(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
