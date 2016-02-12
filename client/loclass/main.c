/*****************************************************************************
 * WARNING
 *
 * THIS CODE IS CREATED FOR EXPERIMENTATION AND EDUCATIONAL USE ONLY. 
 * 
 * USAGE OF THIS CODE IN OTHER WAYS MAY INFRINGE UPON THE INTELLECTUAL 
 * PROPERTY OF OTHER PARTIES, SUCH AS INSIDE SECURE AND HID GLOBAL, 
 * AND MAY EXPOSE YOU TO AN INFRINGEMENT ACTION FROM THOSE PARTIES. 
 * 
 * THIS CODE SHOULD NEVER BE USED TO INFRINGE PATENTS OR INTELLECTUAL PROPERTY RIGHTS. 
 *
 *****************************************************************************
 *
 * This file is part of loclass. It is a reconstructon of the cipher engine
 * used in iClass, and RFID techology.
 *
 * The implementation is based on the work performed by
 * Flavio D. Garcia, Gerhard de Koning Gans, Roel Verdult and
 * Milosch Meriac in the paper "Dismantling IClass".
 *
 * Copyright (C) 2014 Martin Holst Swende
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with loclass.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * 
 * 
 ****************************************************************************/


#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "cipherutils.h"
#include "cipher.h"
#include "ikeys.h"
#include "fileutils.h"
#include "elite_crack.h"

int unitTests()
{
	int errors = testCipherUtils();
	errors += testMAC();
	errors += doKeyTests(0);
	errors += testElite();
    if(errors)
    {
        prnlog("OBS! There were errors!!!");
    }
	return errors;
}
int showHelp()
{
    prnlog("Usage: loclass [options]");
	prnlog("Options:");
	prnlog("-t                 Perform self-test");
	prnlog("-h                 Show this help");
	prnlog("-f <filename>      Bruteforce iclass dumpfile");
	prnlog("                   An iclass dumpfile is assumed to consist of an arbitrary number of malicious CSNs, and their protocol responses");
	prnlog("                   The binary format of the file is expected to be as follows: ");
	prnlog("                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
	prnlog("                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
	prnlog("                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
	prnlog("                  ... totalling N*24 bytes");
	prnlog("                  Check iclass_dump.bin for an example");

	return 0;
}

int main (int argc, char **argv)
{
	prnlog("IClass Cipher version 1.2, Copyright (C) 2014 Martin Holst Swende\n");
	prnlog("Comes with ABSOLUTELY NO WARRANTY");
	prnlog("Released as GPLv2\n");
	prnlog("WARNING");
	prnlog("");
	prnlog("THIS TOOL IS CREATED FOR EXPERIMENTATION AND EDUCATIONAL USE ONLY. ");
	prnlog("");
	prnlog("USAGE OF THIS TOOL IN OTHER WAYS MAY INFRINGE UPON THE INTELLECTUAL ");
	prnlog("PROPERTY OF OTHER PARTIES, SUCH AS INSIDE SECURE AND HID GLOBAL, ");
	prnlog("AND MAY EXPOSE YOU TO AN INFRINGEMENT ACTION FROM THOSE PARTIES. ");
	prnlog("");
	prnlog("THIS TOOL SHOULD NEVER BE USED TO INFRINGE PATENTS OR INTELLECTUAL PROPERTY RIGHTS. ");


	char *fileName = NULL;
	int c;
	while ((c = getopt (argc, argv, "thf:")) != -1)
	  switch (c)
		{
		case 't':
		  return unitTests();
		case 'h':
		  return showHelp();
		case 'f':
		  fileName = optarg;
		  return bruteforceFileNoKeys(fileName);
		case '?':
		  if (optopt == 'f')
			fprintf (stderr, "Option -%c requires an argument.\n", optopt);
		  else if (isprint (optopt))
			fprintf (stderr, "Unknown option `-%c'.\n", optopt);
		  else
			fprintf (stderr,
					 "Unknown option character `\\x%x'.\n",
					 optopt);
		  return 1;
		//default:
		  //showHelp();
		}
	showHelp();
	return 0;
}

