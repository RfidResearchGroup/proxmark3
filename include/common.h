//-----------------------------------------------------------------------------
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.

//-----------------------------------------------------------------------------
// Interlib Definitions
//-----------------------------------------------------------------------------

#ifndef __COMMON_H
#define __COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <at91sam7s512.h>
typedef unsigned char byte_t;

// debug
// 0 - no debug messages 1 - error messages 2 - all messages 4 - extended debug mode
#define MF_DBG_NONE          0		
#define MF_DBG_ERROR         1
#define MF_DBG_ALL           2
#define MF_DBG_EXTENDED      4
extern int MF_DBGLEVEL;

// reader voltage field detector
#define MF_MINFIELDV      4000

#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef ABS
# define ABS(a) ( ((a)<0) ? -(a) : (a) )
#endif
#define RAMFUNC __attribute((long_call, section(".ramfunc")))


#ifdef __cplusplus
}
#endif				
#endif