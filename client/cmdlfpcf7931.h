//-----------------------------------------------------------------------------
// Copyright (C) 2012 Chalk <chalk.secu at gmail.com>
//				 2015 Dake <thomas.cayrou at gmail.com>

// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency PCF7931 commands
//-----------------------------------------------------------------------------

#ifndef CMDLFPCF7931_H__
#define CMDLFPCF7931_H__

struct pcf7931_config{
	uint8_t Pwd[7];
	uint16_t InitDelay;
	int16_t OffsetWidth;
	int16_t OffsetPosition;
};

int pcf7931_resetConfig();
int pcf7931_printConfig();

int usage_pcf7931_read();
int usage_pcf7931_write();
int usage_pcf7931_config();

int CmdLFPCF7931(const char *Cmd);

int CmdLFPCF7931Read(const char *Cmd);
int CmdLFPCF7931Write(const char *Cmd);
int CmdLFPCF7931Config(const char *Cmd);

#endif
