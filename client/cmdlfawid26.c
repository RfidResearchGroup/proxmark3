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
#include <stdbool.h>
#include "proxmark3.h"
#include "ui.h"
//#include "graph.h"
#include "cmdmain.h"
#include "cmdparser.h"
//#include "cmddata.h"
#include "cmdlf.h"
#include "cmdlfawid26.h"
#include "util.h"
//#include "data.h"


static int CmdHelp(const char *Cmd);

int CmdClone(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);

	if (strlen(Cmd) < 1 || cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  lf awid26 clone  <facility> <id>");
		PrintAndLog("     [], ");
		PrintAndLog("");
		PrintAndLog("     sample: lf awid26 clone 15 2233");
		return 0;
	}

	//sscanf(Cmd, "%d %d", &facilitycode, &cardno);

	// char block0 = "00107060";  
	// char block1 = "00107060";  
	// char block2 = "00107060";  
	// char block3 = "00107060";  

	unsigned char buf[10] = {0x00};
	unsigned char *resp = buf;
	
	
	awid26_hex_to_uid(resp, "");
	// PrintAndLog("Writing block %d with data %08X", Block, Data);
	return 0;
}


// convert 96 bit AWID FSK data to 8 digit BCD UID
bool awid26_hex_to_uid(unsigned char *response, char *awid26)
{
	//uint8_t i, tmp[96], tmp1[7];
	//uint8_t tmp[96] = {0x00};
    //int site;
    //int id;
	
    //if(!hextobinarray(tmp, awid26))
        return false;

    // // data is in blocks of 4 bits - every 4th bit is parity, except the first
    // // block which is all zeros
    // for(i= 0 ; i < 4 ; ++i)
        // if(tmp[i] != 0x00)
            // return false;

    // // discard 1st block
    // memcpy(tmp, tmp + 4, 92);

    // // check and strip parity on the rest
    // for(i= 1 ; i < 23 ; ++i)
        // if(tmp[(i * 4) - 1] != GetParity(tmp + (i - 1) * 4, ODD, 3))
            // return false;
        // else
            // memcpy((tmp + (i - 1) * 3), tmp + (i - 1) * 4, 3);

    // // discard the rest of the header - 1 more 3 bit block
    // memcpy(tmp, tmp + 3, 66);

    // // next 8 bits is data length - should be 26: 0x1A
    // binarraytohex(tmp1, tmp, 8);
    // if(strcmp(tmp1, "1A") != 0)
        // return false;
    // memcpy(tmp, tmp +8, 58);

    // // standard wiegand parity check - even for 1st 12 bits, odd for 2nd 12
    // if(tmp[0] != GetParity(tmp + 1, EVEN, 12))
        // return false;
    // if(tmp[25] != GetParity(tmp + 13, ODD, 12))
        // return false;

    // // convert to hex, ignoring parity bits
    // if(!binarraytohex(tmp1, tmp + 1, 24))
        // return false;

    // // convert hex to site/id
    // sscanf(tmp1,"%2X%4X", &site, &id);

    // // final output 8 byte BCD
    // sprintf(response,"%03d%05d", site, id);

    return true;
}

// convert null-terminated BCD UID (8 digits) to 96 bit awid26 encoded binary array
bool bcd_to_awid26_bin(unsigned char *awid26, unsigned char *bcd)
{
    // char i, p, tmp1[8], tmp2[26];
    // int tmpint;

    // if(strlen(bcd) != 8)
        // return false;

    // // convert BCD site code to HEX
    // sscanf(bcd, "%03d", &tmpint);
    // sprintf(tmp2, "%02x", tmpint);
    // memcpy(tmp1, tmp2, 2);

    // // convert BCD ID to HEX
    // sscanf(bcd + 3, "%05d", &tmpint);;
    // sprintf(tmp2, "%04x", tmpint);
	
    // // copy with trailing NULL
    // memcpy(tmp1 + 2, tmp2, 5);

    // // convert full HEX to binary, leaving room for parity prefix
    // hextobinarray(tmp2 + 1, tmp1);
    
    // wiegand_add_parity(tmp2, tmp2 + 1, 24);

    // memset(awid26, '\x0', 96);

    // // magic 18 bit awid26 header (we will overwrite the last two bits)
    // hextobinarray(awid26, "011D8");

    // // copy to target leaving space for parity bits
    // for(i= 0, p= 18 ; i < 26 ; ++i, ++p)
    // {
        // // skip target bit if this is a parity location
        // if(!((p + 1) % 4))
            // p += 1;
        // awid26[p]= tmp2[i];
    // }

    // // add parity bits
    // for(i= 1 ; i < 24 ; ++i)
        // awid26[((i + 1) * 4) - 1]= GetParity(&awid26[i * 4], ODD, 3);

    return false;
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
  {"help",   CmdHelp,     1, "This help"},
  {"clone",  CmdClone,    1, "<facility> <id> -- clone AWID26 to t55xx tag"},
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
