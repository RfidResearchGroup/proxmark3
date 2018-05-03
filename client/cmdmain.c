//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Main command parser entry point
//-----------------------------------------------------------------------------
#include "cmdmain.h"

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

// to lock cmdBuffer operations from different threads
static pthread_mutex_t cmdBufferMutex = PTHREAD_MUTEX_INITIALIZER;

int CmdQuit(const char *Cmd) {
	return 99;
}

int CmdRev(const char *Cmd) {
	CmdCrc(Cmd);
	return 0;
}

static command_t CommandTable[] = {
	{"help",	CmdHelp,	1, "This help. Use '<command> help' for details of a particular command."},
	{"analyse", CmdAnalyse, 1, "{ Analyse bytes... }"},
	{"data",	CmdData,	1, "{ Plot window / data buffer manipulation... }"},
	{"hf",		CmdHF,		1, "{ High Frequency commands... }"},
	{"hw",		CmdHW,		1, "{ Hardware commands... }"},
	{"lf",		CmdLF,		1, "{ Low Frequency commands... }"},
	{"reveng",	CmdRev, 	1, "Crc calculations from the software reveng 1.44"},
	{"script",	CmdScript,	1, "{ Scripting commands }"},
	{"trace",	CmdTrace,	1, "{ Trace manipulation... }"},
#ifdef WITH_FLASH		
	{"mem",		CmdFlashMem,1, "{ RDV40, Flash Memory manipulation... }"},
#endif	
	{"quit",	CmdQuit,	1, ""},
	{"exit",	CmdQuit,	1, "Exit program"},
	{NULL, NULL, 0, NULL}
};

command_t* getTopLevelCommandTable() {
	return CommandTable;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}

bool dl_it(uint8_t *dest, uint32_t bytes, uint32_t start_index, UsbCommand *response, size_t ms_timeout, bool show_warning, uint32_t rec_cmd);
/**
 * @brief This method should be called when sending a new command to the pm3. In case any old
 *  responses from previous commands are stored in the buffer, a call to this method should clear them.
 *  A better method could have been to have explicit command-ACKS, so we can know which ACK goes to which
 *  operation. Right now we'll just have to live with this.
 */
void clearCommandBuffer() {
    //This is a very simple operation
	pthread_mutex_lock(&cmdBufferMutex);
    cmd_tail = cmd_head;
	pthread_mutex_unlock(&cmdBufferMutex);
}

/**
 * @brief storeCommand stores a USB command in a circular buffer
 * @param UC
 */
void storeCommand(UsbCommand *command) {
	
	pthread_mutex_lock(&cmdBufferMutex);
    if ( ( cmd_head+1) % CMD_BUFFER_SIZE == cmd_tail) {
        //If these two are equal, we're about to overwrite in the
        // circular buffer.
        PrintAndLogEx(FAILED, "WARNING: Command buffer about to overwrite command! This needs to be fixed!");
    }
    //Store the command at the 'head' location
    UsbCommand* destination = &cmdBuffer[cmd_head];
    memcpy(destination, command, sizeof(UsbCommand));

	 //increment head and wrap
    cmd_head = (cmd_head +1) % CMD_BUFFER_SIZE;	
	pthread_mutex_unlock(&cmdBufferMutex);
}
/**
 * @brief getCommand gets a command from an internal circular buffer.
 * @param response location to write command
 * @return 1 if response was returned, 0 if nothing has been received
 */
int getCommand(UsbCommand* response) {
	pthread_mutex_lock(&cmdBufferMutex);
    //If head == tail, there's nothing to read, or if we just got initialized
    if (cmd_head == cmd_tail)  {
		pthread_mutex_unlock(&cmdBufferMutex);
		return 0;
	}
	
    //Pick out the next unread command
    UsbCommand* last_unread = &cmdBuffer[cmd_tail];
    memcpy(response, last_unread, sizeof(UsbCommand));

    //Increment tail - this is a circular buffer, so modulo buffer size
    cmd_tail = (cmd_tail +1 ) % CMD_BUFFER_SIZE;

	pthread_mutex_unlock(&cmdBufferMutex);
    return 1;
}

/**
 * Waits for a certain response type. This method waits for a maximum of
 * ms_timeout milliseconds for a specified response command.
 *@brief WaitForResponseTimeout
 * @param cmd command to wait for, or CMD_UNKNOWN to take any command.
 * @param response struct to copy received command into.
 * @param ms_timeout display message after 2 seconds
 * @return true if command was returned, otherwise false
 */
bool WaitForResponseTimeoutW(uint32_t cmd, UsbCommand* response, size_t ms_timeout, bool show_warning) {
  
	UsbCommand resp;

	if (response == NULL)
		response = &resp;

	uint64_t start_time = msclock();
	
	// Wait until the command is received
	while (true) {

		while ( getCommand(response) ) {
			if (cmd == CMD_UNKNOWN || response->cmd == cmd)
				return true;			
		}

		if (msclock() - start_time > ms_timeout)
			break;
		
		if (msclock() - start_time > 3000 && show_warning) {
			// 3 seconds elapsed (but this doesn't mean the timeout was exceeded)
			PrintAndLogEx(NORMAL, "Waiting for a response from the proxmark...");
			PrintAndLogEx(NORMAL, "You can cancel this operation by pressing the pm3 button");
			show_warning = false;
		}
	}
	return false;
}

bool WaitForResponseTimeout(uint32_t cmd, UsbCommand* response, size_t ms_timeout) {
	return WaitForResponseTimeoutW(cmd, response, ms_timeout, true);
}

bool WaitForResponse(uint32_t cmd, UsbCommand* response) {
	return WaitForResponseTimeoutW(cmd, response, -1, true);
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
void UsbCommandReceived(UsbCommand* _ch) {

	//UsbCommand *c = malloc(sizeof(UsbCommand));
	//memset(cp, 0x00, sizeof(*cp));

	pthread_mutex_lock(&cmdBufferMutex);
	UsbCommand* c = _ch;
	pthread_mutex_unlock(&cmdBufferMutex);	
			
	switch(c->cmd) {
		// First check if we are handling a debug message
		case CMD_DEBUG_PRINT_STRING: {

			char s[USB_CMD_DATA_SIZE+1];
			memset(s, 0x00, sizeof(s)); 
			size_t len = MIN(c->arg[0], USB_CMD_DATA_SIZE);
			memcpy(s, c->d.asBytes, len);
			
			// print debug line on same row. escape seq \r
			if ( c->arg[1] == CMD_MEASURE_ANTENNA_TUNING_HF) {
				printf("\r#db# %s", s);
				fflush(stdout);
			} else {
				PrintAndLogEx(NORMAL, "#db# %s", s);
			}
			break;
		}
		case CMD_DEBUG_PRINT_INTEGERS: {
			PrintAndLogEx(NORMAL, "#db# %08x, %08x, %08x", c->arg[0], c->arg[1], c->arg[2]);
			break;
		}
		// iceman:  hw status - down the path on device, runs printusbspeed which starts sending a lot of
		// CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K packages which is not dealt with. I wonder if simply ignoring them will
		// work. lets try it. 
		default: {
			storeCommand(c);
			break;
		}
	}
}

/**
* Data transfer from Proxmark to client. This method times out after
* ms_timeout milliseconds.
* @brief GetFromDevice
* @param memtype Type of memory to download from proxmark
* @param dest Destination address for transfer
* @param bytes number of bytes to be transferred
* @param start_index offset into Proxmark3 BigBuf[]
* @param response struct to copy last command (CMD_ACK) into
* @param ms_timeout timeout in milliseconds
* @param show_warning display message after 2 seconds
* @return true if command was returned, otherwise false
*/
bool GetFromDevice(DeviceMemType_t memtype, uint8_t *dest, uint32_t bytes, uint32_t start_index, UsbCommand *response, size_t ms_timeout, bool show_warning) {
	
	if (dest == NULL) return false;
	if (bytes == 0) return true;

	UsbCommand resp;
	if (response == NULL)
		response = &resp;

	// clear 
	clearCommandBuffer();
			
	switch (memtype) {
		case BIG_BUF: {
			UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {start_index, bytes, 0}};
			SendCommand(&c);
			return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
		}
		case BIG_BUF_EML: {
			UsbCommand c = {CMD_DOWNLOAD_EML_BIGBUF, {start_index, bytes, 0}};
			SendCommand(&c);			
			return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
		}
		case FLASH_MEM: {			
			UsbCommand c = {CMD_DOWNLOAND_FLASH_MEM, {start_index, bytes, 0}};
			SendCommand(&c);
			return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_FLASHMEM);
		}
		case SIM_MEM: {
			//UsbCommand c = {CMD_DOWNLOAND_SIM_MEM, {start_index, bytes, 0}};
			//SendCommand(&c);
			//return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_SIMMEM);
			return false;
		}
	}
	return false;
}

bool dl_it(uint8_t *dest, uint32_t bytes, uint32_t start_index, UsbCommand *response, size_t ms_timeout, bool show_warning, uint32_t rec_cmd) {
	
	uint32_t bytes_completed = 0;
	uint64_t start_time = msclock();
	
	while (true) {
		
		if (getCommand(response)) {

			// sample_buf is a array pointer, located in data.c
			// arg0 = offset in transfer. Startindex of this chunk
			// arg1 = length bytes to transfer
			// arg2 = bigbuff tracelength (?)			
			if (response->cmd == rec_cmd) {
				
				uint32_t offset = response->arg[0];
				uint32_t copy_bytes = MIN(bytes - bytes_completed, response->arg[1]);
				//uint32_t tracelen = c->arg[2];
				
				// extended bounds check1.  upper limit is USB_CMD_DATA_SIZE
				// shouldn't happen
				copy_bytes = MIN(copy_bytes, USB_CMD_DATA_SIZE);
				
				// extended bounds check2. 
				if ( offset + copy_bytes > bytes ) {
					PrintAndLogEx(FAILED, "ERROR: Out of bounds when downloading from device,  offset %u | len %u | total len %u > buf_size %u", offset, copy_bytes,  offset+copy_bytes,  bytes);
					break;
				}			
		
				memcpy(dest + offset, response->d.asBytes, copy_bytes);
				bytes_completed += copy_bytes;
			} else if (response->cmd == CMD_ACK) {
				return true;
			}
		}
		
		if (msclock() - start_time > ms_timeout) {
			PrintAndLogEx(FAILED, "Timed out while trying to download data from device");
			break;
		}
		
		if (msclock() - start_time > 3000 && show_warning) {
			// 3 seconds elapsed (but this doesn't mean the timeout was exceeded)
			PrintAndLogEx(NORMAL, "Waiting for a response from the proxmark...");
			PrintAndLogEx(NORMAL, "You can cancel this operation by pressing the pm3 button");
			show_warning = false;
		}
	}
	return false;
}
