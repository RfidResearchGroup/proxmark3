//-----------------------------------------------------------------------------
// Copyright (C) 2015 Piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Topaz (NFC Type 1) commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cmdmain.h"
#include "cmdparser.h"
#include "cmdhftopaz.h"
#include "cmdhf14a.h"
#include "ui.h"
#include "mifare.h"
#include "proxmark3.h"
#include "iso14443crc.h"
#include "protocols.h"
#include "cmdhf.h"

#define TOPAZ_MAX_MEMORY	2048

static struct {
	uint8_t HR01[2];
	uint8_t uid[7];
	uint8_t size;
	uint8_t data_blocks[TOPAZ_MAX_MEMORY/8][8];
	uint8_t *dynamic_lock_areas;
	uint8_t *dynamic_reserved_areas;
} topaz_tag;

static void topaz_switch_on_field(void)
{
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT | ISO14A_NO_SELECT | ISO14A_NO_DISCONNECT | ISO14A_TOPAZMODE, 0, 0}};
	SendCommand(&c);
}


static void topaz_switch_off_field(void)
{
	UsbCommand c = {CMD_READER_ISO_14443a, {0, 0, 0}};
	SendCommand(&c);
}


static int topaz_send_cmd_raw(uint8_t *cmd, uint8_t len, uint8_t *response)
{
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_TOPAZMODE, len, 0}};
	memcpy(c.d.asBytes, cmd, len);
	SendCommand(&c);

	UsbCommand resp;
	WaitForResponse(CMD_ACK, &resp);

	if (resp.arg[0] > 0) {
		memcpy(response, resp.d.asBytes, resp.arg[0]);
	}
	
	return resp.arg[0];
}


static int topaz_send_cmd(uint8_t *cmd, uint8_t len, uint8_t *response)
{
	if (len > 1) {
        uint8_t first, second;
		ComputeCrc14443(CRC_14443_B, cmd, len-2, &first, &second);
        cmd[len-2] = first;
        cmd[len-1] = second;
	}

	return topaz_send_cmd_raw(cmd, len, response);
}


static int topaz_select(uint8_t *atqa, uint8_t *rid_response)
{
	// ToDo: implement anticollision

	uint8_t wupa_cmd[] = {TOPAZ_WUPA};
	uint8_t rid_cmd[] = {TOPAZ_RID, 0, 0, 0, 0, 0, 0, 0, 0};

	topaz_switch_on_field();

	if (!topaz_send_cmd(wupa_cmd, sizeof(wupa_cmd), atqa)) {
		topaz_switch_off_field();
		return -1;		// WUPA failed
	}

	if (!topaz_send_cmd(rid_cmd, sizeof(rid_cmd), rid_response)) {
		topaz_switch_off_field();
		return -2;		// RID failed
	}
	
	return 0;		// OK
}


static int topaz_rall(uint8_t *uid, uint8_t *response)
{
	uint8_t rall_cmd[] = {TOPAZ_RALL, 0, 0, 0, 0, 0, 0, 0, 0};

	memcpy(&rall_cmd[3], uid, 4);
	if (!topaz_send_cmd(rall_cmd, sizeof(rall_cmd), response)) {
		topaz_switch_off_field();
		return -1;		// RALL failed
	}
	
	return 0;
}


static bool topaz_block_is_locked(uint8_t blockno, uint8_t *lockbits)
{
	if(lockbits[blockno/8] >> (blockno % 8) & 0x01) {
		return true;
	} else {
		return false;
	}
}


static int topaz_print_CC(uint8_t *data)
{
	if(data[0] != 0xe1) {
		return -1;		// no NDEF message
	}

	PrintAndLog("Capability Container: %02x %02x %02x %02x", data[0], data[1], data[2], data[3]);
	PrintAndLog("  %02x: NDEF Magic Number", data[0]); 
	PrintAndLog("  %02x: version %d.%d supported by tag", data[1], (data[1] & 0xF0) >> 4, data[1] & 0x0f);
	PrintAndLog("  %02x: Physical Memory Size of this tag: %d bytes", data[2], (data[2] + 1) * 8);
	PrintAndLog("  %02x: %s / %s", data[3], 
				(data[3] & 0xF0) ? "(RFU)" : "Read access granted without any security", 
				(data[3] & 0x0F)==0 ? "Write access granted without any security" : (data[3] & 0x0F)==0x0F ? "No write access granted at all" : "(RFU)");
	return 0;				
}


static void get_TLV(uint8_t **TLV_ptr, uint8_t *tag, uint16_t *length, uint8_t **value)
{
	*length = 0;
	*value = NULL;

	*tag = **TLV_ptr;
	*TLV_ptr += 1;
	switch (*tag) {
		case 0x00:			// NULL TLV.
		case 0xFE:			// Terminator TLV.
			break;
		case 0x01:			// Lock Control TLV
		case 0x02:			// Reserved Memory TLV
		case 0x03:			// NDEF message TLV
		case 0xFD:			// proprietary TLV
			*length = **TLV_ptr;
			*TLV_ptr += 1;
			if (*length == 0xff) {
				*length = **TLV_ptr << 8;
				*TLV_ptr += 1;
				*length |= **TLV_ptr;
				*TLV_ptr += 1;
			}
			*value = *TLV_ptr;
			*TLV_ptr += *length;
			break;
		default:			// RFU
			break;
	}
}


static bool topaz_print_lock_control_TLVs(uint8_t *memory)
{
	uint8_t *TLV_ptr = memory;
	uint8_t tag = 0;
	uint16_t length;
	uint8_t *value;
	bool lock_TLV_present = false;
	
	while(*TLV_ptr != 0x03 && *TLV_ptr != 0xFD && *TLV_ptr != 0xFE) {	
		// all Lock Control TLVs shall be present before the NDEF message TLV, the proprietary TLV (and the Terminator TLV)
		get_TLV(&TLV_ptr, &tag, &length, &value);
		if (tag == 0x01) {			// the Lock Control TLV
			uint8_t pages_addr = value[0] >> 4;
			uint8_t byte_offset = value[0] & 0x0f;
			uint8_t size_in_bits = value[1] ? value[1] : 255;
			uint8_t bytes_per_page = 1 << (value[2] & 0x0f);
			uint8_t bytes_locked_per_bit = 1 << (value[2] >> 4);
			PrintAndLog("Lock Area of %d bits at byte offset 0x%02x. Each Lock Bit locks %d bytes.", 
						size_in_bits,
						pages_addr * bytes_per_page + byte_offset,
						bytes_locked_per_bit);
			lock_TLV_present = true;
		}
	}
	
	if (!lock_TLV_present) {
		PrintAndLog("(No Lock Control TLV present)");
		return -1;
	} else {
		return 0;
	}
}


static int topaz_print_reserved_memory_control_TLVs(uint8_t *memory)
{
	uint8_t *TLV_ptr = memory;
	uint8_t tag = 0;
	uint16_t length;
	uint8_t *value;
	bool reserved_memory_control_TLV_present = false;
	
	while(*TLV_ptr != 0x03 && *TLV_ptr != 0xFD && *TLV_ptr != 0xFE) {	
		// all Reserved Memory Control TLVs shall be present before the NDEF message TLV, the proprietary TLV (and the Terminator TLV)
		get_TLV(&TLV_ptr, &tag, &length, &value);
		if (tag == 0x02) {			// the Reserved Memory Control TLV
			uint8_t pages_addr = value[0] >> 4;
			uint8_t byte_offset = value[0] & 0x0f;
			uint8_t size_in_bytes = value[1] ? value[1] : 255;
			uint8_t bytes_per_page = 1 << (value[2] & 0x0f);
			PrintAndLog("Reserved Memory of %d bytes at byte offset 0x%02x.", 
						size_in_bytes,
						pages_addr * bytes_per_page + byte_offset);
			reserved_memory_control_TLV_present = true;
		}
	}
	
	if (!reserved_memory_control_TLV_present) {
		PrintAndLog("(No Reserved Memory Control TLV present)");
		return -1;
	} else {
		return 0;
	}
}


static void topaz_print_lifecycle_state(uint8_t *data)
{

}


static void topaz_print_NDEF(uint8_t *data)
{

}

	
int CmdHFTopazReader(const char *Cmd) {
	int status;
	uint8_t atqa[2];
	uint8_t rid_response[8];
	uint8_t *uid_echo = &rid_response[2];
	uint8_t rall_response[130];
	bool verbose = TRUE;

	char ctmp = param_getchar(Cmd, 0);
	if ( ctmp == 'S' || ctmp == 's') verbose = FALSE;
	
	status = topaz_select(atqa, rid_response);

	if (status == -1) {
		if (verbose) PrintAndLog("Error: couldn't receive ATQA");
		return -1;
	}

	PrintAndLog("ATQA : %02x %02x", atqa[1], atqa[0]);
	if (atqa[1] != 0x0c && atqa[0] != 0x00) {
		PrintAndLog("Tag doesn't support the Topaz protocol.");
		topaz_switch_off_field();
		return -1;
	}
	
	if (status == -2) {
		PrintAndLog("Error: tag didn't answer to RID");
		topaz_switch_off_field();
		return -1;
	}

	topaz_tag.HR01[0] = rid_response[0];
	topaz_tag.HR01[1] = rid_response[1];
	
	// ToDo: CRC check
	PrintAndLog("HR0  : %02x (%sa Topaz tag (%scapable of carrying a NDEF message), %s memory map)", rid_response[0], 
						(rid_response[0] & 0xF0) == 0x10 ? "" : "not ",
						(rid_response[0] & 0xF0) == 0x10 ? "" : "not ",
						(rid_response[0] & 0x0F) == 0x01 ? "static" : "dynamic");
	PrintAndLog("HR1  : %02x", rid_response[1]);
	
	status = topaz_rall(uid_echo, rall_response);

	if(status == -1) {
		PrintAndLog("Error: tag didn't answer to RALL");
		topaz_switch_off_field();
		return -1;
	}

	memcpy(topaz_tag.uid, rall_response+2, 7);
	PrintAndLog("UID  : %02x %02x %02x %02x %02x %02x %02x", 
			topaz_tag.uid[6], 
			topaz_tag.uid[5], 
			topaz_tag.uid[4], 
			topaz_tag.uid[3], 
			topaz_tag.uid[2], 
			topaz_tag.uid[1], 
			topaz_tag.uid[0]);
			
	PrintAndLog("       UID[6] (Manufacturer Byte) = %02x, Manufacturer: %s", 
			topaz_tag.uid[6], 
			getTagInfo(topaz_tag.uid[6]));
	
	memcpy(topaz_tag.data_blocks, rall_response+2, 0x10*8);
	PrintAndLog("");
	PrintAndLog("Static Data blocks 00 to 0c:");
	PrintAndLog("block# | offset | Data                    | Locked?");
	char line[80];
	for (uint16_t i = 0; i <= 0x0c; i++) {
		for (uint16_t j = 0; j < 8; j++) {
			sprintf(&line[3*j], "%02x ", topaz_tag.data_blocks[i][j] /*rall_response[2 + 8*i + j]*/);
		}
		PrintAndLog("  0x%02x |  0x%02x  | %s|   %-3s", i, i*8, line, topaz_block_is_locked(i, &topaz_tag.data_blocks[0x0e][0]) ? "yes" : "no");
	}
	
	PrintAndLog("");
	PrintAndLog("Static Reserved block 0d:");
	for (uint16_t j = 0; j < 8; j++) {
		sprintf(&line[3*j], "%02x ", topaz_tag.data_blocks[0x0d][j]);
	}
	PrintAndLog("  0x%02x |  0x%02x  | %s|   %-3s", 0x0d, 0x0d*8, line, "n/a");
	
	PrintAndLog("");
	PrintAndLog("Static Lockbits and OTP Bytes:");
	for (uint16_t j = 0; j < 8; j++) {
		sprintf(&line[3*j], "%02x ", topaz_tag.data_blocks[0x0e][j]);
	}
	PrintAndLog("  0x%02x |  0x%02x  | %s|   %-3s", 0x0e, 0x0e*8, line, "n/a");

	PrintAndLog("");

	status = topaz_print_CC(&topaz_tag.data_blocks[1][0]);
	
	if (status == -1) {
		PrintAndLog("No NDEF message present");
		topaz_switch_off_field();
		return 0;
	}

	PrintAndLog("");
	bool lock_TLV_present = topaz_print_lock_control_TLVs(&topaz_tag.data_blocks[1][4]);
	if ( lock_TLV_present ) {
		PrintAndLog("");	
	}
	
	PrintAndLog("");
	bool reserved_mem_present = topaz_print_reserved_memory_control_TLVs(&topaz_tag.data_blocks[1][4]);
	if (reserved_mem_present) {
		PrintAndLog("");	
	}
	
	topaz_print_lifecycle_state(&topaz_tag.data_blocks[1][0]);

	topaz_print_NDEF(&topaz_tag.data_blocks[1][0]);
	
	topaz_switch_off_field();
	return 0;
}

int CmdHFTopazSim(const char *Cmd) {
	PrintAndLog("not yet implemented");
	return 0;
}

int CmdHFTopazCmdRaw(const char *Cmd) {
	PrintAndLog("not yet implemented");
	return 0;
}

int CmdHFTopazList(const char *Cmd) {
	CmdHFList("topaz");
	return 0;
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = 
{
	{"help",	CmdHelp,			1, "This help"},
	{"reader",	CmdHFTopazReader,	0, "Act like a Topaz reader"},
	{"sim",		CmdHFTopazSim,		0, "<UID> -- Simulate Topaz tag"},
	{"sniff",	CmdHF14ASniff,		0, "Sniff Topaz reader-tag communication"},
	{"raw",		CmdHFTopazCmdRaw,	0, "Send raw hex data to tag"},
	{"list",	CmdHFTopazList,		0, "[Deprecated] List Topaz history"},
	{NULL,		NULL,				0, NULL}
};

int CmdHFTopaz(const char *Cmd) {
	// flush
	//WaitForResponseTimeout(CMD_ACK,NULL,100);
	clearCommandBuffer();
	
	// parse
	CmdsParse(CommandTable, Cmd);
	return 0;
}

static int CmdHelp(const char *Cmd)
{
	CmdsHelp(CommandTable);
	return 0;
}


