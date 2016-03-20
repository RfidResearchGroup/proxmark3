//------------------------------------------------------------------------------
// Peter Fillmore -2012
// Based off MIFARECMD code
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support EMV Transactions.
//-----------------------------------------------------------------------------

#ifndef __EMVCMD_H
#define __EMVCMD_H

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"

#include "iso14443crc.h"
#include "iso14443a.h"
#include "common.h"
#include "emvutil.h"
#include "emvcard.h"

#define VISA_DCVV           0
#define VISA_CVN17          1
#define VISA_FDDA           2
#define VISA_EMV            3

#define MASTERCARD_MSR      0
#define MASTERCARD_MCHIP    1 
#endif
