//-----------------------------------------------------------------------------
// Frederik Möllers - August 2012
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support the German eletronic "Personalausweis" (ID card)
//-----------------------------------------------------------------------------

#ifndef __EPA_H
#define __EPA_H

// this struct is used by EPA_Parse_CardAccess and contains info about the
// PACE protocol supported by the chip
typedef struct {
	uint8_t oid[10];
	uint8_t version;
	uint8_t parameter_id;
} pace_version_info_t;

// note: EPA_PACE_Collect_Nonce and EPA_PACE_Replay are declared in apps.h

// general functions
void EPA_Finish();
size_t EPA_Parse_CardAccess(uint8_t *data,
                            size_t length,
                            pace_version_info_t *pace_info);
int EPA_Read_CardAccess(uint8_t *buffer, size_t max_length);
int EPA_Setup();

// PACE related functions
int EPA_PACE_MSE_Set_AT(pace_version_info_t pace_version_info, uint8_t password);
int EPA_PACE_Get_Nonce(uint8_t requested_length, uint8_t *nonce);

#endif /* __EPA_H */
