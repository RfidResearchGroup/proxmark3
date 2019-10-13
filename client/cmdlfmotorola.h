//-----------------------------------------------------------------------------
// Iceman, 2019
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency MOTOROLA tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFMOTOROLA_H__
#define CMDLFMOTOROLA_H__

#include "common.h"

int CmdLFMotorola(const char *Cmd);

int demodMotorola(void);
int detectMotorola(uint8_t *dest, size_t *size);
int readMotorolaUid(void);
#endif

