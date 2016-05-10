//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Main command parser entry point
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "sleep.h"
#include "cmdparser.h"
#include "proxmark3.h"
#include "data.h"
#include "usb_cmd.h"
#include "ui.h"
#include "cmdhf.h"
#include "cmddata.h"
#include "cmdhw.h"
#include "cmdlf.h"
#include "cmdmain.h"
#include "util.h"
#include "cmdscript.h"
#include "cmdcrc.h"
#include "cmdanalyse.h"

unsigned int current_command = CMD_UNKNOWN;

static int CmdHelp(const char *Cmd);
static int CmdQuit(const char *Cmd);
static int CmdRev(const char *Cmd);

//For storing command that are received from the device
#define CMD_BUFFER_SIZE 50
static UsbCommand cmdBuffer[CMD_BUFFER_SIZE];
//Points to the next empty position to write to
static int cmd_head;//Starts as 0
//Points to the position of the last unread command
static int cmd_tail;//Starts as 0

static command_t CommandTable[] = 
{
	{"help",	CmdHelp,	1, "This help. Use '<command> help' for details of a particular command."},
	{"analyse", CmdAnalyse, 1, "{ Analyse bytes... }"},
	{"data",	CmdData,	1, "{ Plot window / data buffer manipulation... }"},
	{"hf",		CmdHF,		1, "{ High Frequency commands... }"},
	{"hw",		CmdHW,		1, "{ Hardware commands... }"},
	{"lf",		CmdLF,		1, "{ Low Frequency commands... }"},
	{"reveng",	CmdRev, 	1, "Crc calculations from the software reveng 1.40"},
	{"script",	CmdScript,	1, "{ Scripting commands }"},	
	{"quit",	CmdQuit,	1, "Exit program"},
	{"exit",	CmdQuit,	1, "Exit program"},
	{NULL, NULL, 0, NULL}
};

command_t* getTopLevelCommandTable()
{
  return CommandTable;
}
int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}

int CmdQuit(const char *Cmd)
{
  return 99;
}

int CmdRev(const char *Cmd)
{
  CmdCrc(Cmd);
  return 0;
}
/**
 * @brief This method should be called when sending a new command to the pm3. In case any old
 *  responses from previous commands are stored in the buffer, a call to this method should clear them.
 *  A better method could have been to have explicit command-ACKS, so we can know which ACK goes to which
 *  operation. Right now we'll just have to live with this.
 */
void clearCommandBuffer()
{
    //This is a very simple operation
    cmd_tail = cmd_head;
}

/**
 * @brief storeCommand stores a USB command in a circular buffer
 * @param UC
 */
void storeCommand(UsbCommand *command)
{
    if( ( cmd_head+1) % CMD_BUFFER_SIZE == cmd_tail)
    {
        //If these two are equal, we're about to overwrite in the
        // circular buffer.
        PrintAndLog("WARNING: Command buffer about to overwrite command! This needs to be fixed!");
    }
    //Store the command at the 'head' location
    UsbCommand* destination = &cmdBuffer[cmd_head];
    memcpy(destination, command, sizeof(UsbCommand));

    cmd_head = (cmd_head +1) % CMD_BUFFER_SIZE; //increment head and wrap

}
/**
 * @brief getCommand gets a command from an internal circular buffer.
 * @param response location to write command
 * @return 1 if response was returned, 0 if nothing has been received
 */
int getCommand(UsbCommand* response)
{
    //If head == tail, there's nothing to read, or if we just got initialized
    if(cmd_head == cmd_tail)  return 0;

    //Pick out the next unread command
    UsbCommand* last_unread = &cmdBuffer[cmd_tail];
    memcpy(response, last_unread, sizeof(UsbCommand));

    //Increment tail - this is a circular buffer, so modulo buffer size
    cmd_tail = (cmd_tail +1 ) % CMD_BUFFER_SIZE;

    return 1;
}

/**
 * Waits for a certain response type. This method waits for a maximum of
 * ms_timeout milliseconds for a specified response command.
 *@brief WaitForResponseTimeout
 * @param cmd command to wait for
 * @param response struct to copy received command into.
 * @param ms_timeout
 * @return true if command was returned, otherwise false
 */
bool WaitForResponseTimeout(uint32_t cmd, UsbCommand* response, size_t ms_timeout) {
  
	UsbCommand resp;

	if (response == NULL)
		response = &resp;

	// Wait until the command is received
	for ( size_t dm_seconds = 0; dm_seconds < ms_timeout/10; dm_seconds++ ) {

		while( getCommand(response) ) {
			if(response->cmd == cmd)
				return true;			
		}

		msleep(10); // XXX ugh
		if (dm_seconds == 250) { // 2.5 seconds elapsed
			PrintAndLog("Waiting for a response from the proxmark...");
			PrintAndLog("Don't forget to cancel its operation first by pressing on the button");
		}
	}
	return false;
}

bool WaitForResponse(uint32_t cmd, UsbCommand* response) {
	return WaitForResponseTimeout(cmd, response, -1);
}

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever the user types a command and
// then presses Enter, which the full command line that they typed.
//-----------------------------------------------------------------------------
int CommandReceived(char *Cmd) {
	return CmdsParse(CommandTable, Cmd);
}

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever we received a packet over USB
// that we weren't necessarily expecting, for example a debug print.
//-----------------------------------------------------------------------------
void UsbCommandReceived(UsbCommand *UC)
{
	switch(UC->cmd) {
		// First check if we are handling a debug message
		case CMD_DEBUG_PRINT_STRING: {
			char s[USB_CMD_DATA_SIZE+1];
			memset(s, 0x00, sizeof(s)); 
			size_t len = MIN(UC->arg[0],USB_CMD_DATA_SIZE);
			memcpy(s, UC->d.asBytes, len);
			
			// test
			if ( UC->arg[1] == CMD_MEASURE_ANTENNA_TUNING_HF) {
				printf("\r#db# %s", s);
				fflush(stdout);
			}
			else 
				PrintAndLog("#db# %s", s);
			
			return;
		} break;

		case CMD_DEBUG_PRINT_INTEGERS: {
			PrintAndLog("#db# %08x, %08x, %08x", UC->arg[0], UC->arg[1], UC->arg[2]);
			break;
		}
		case CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K:
		case CMD_DOWNLOADED_EML_BIGBUF: {
			memcpy( sample_buf + (UC->arg[0]), UC->d.asBytes, UC->arg[1]);
			break;
		}
		default: {
			storeCommand(UC);
			break;
		}
	}

}

