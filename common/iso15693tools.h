// ISO15693 commons
// Adrian Dabrowski 2010, GPLv2

#ifndef ISO15693_H__
#define ISO15693_H__

// ISO15693 CRC
#define ISO15_CRC_PRESET	(uint16_t)0xFFFF
#define ISO15_CRC_POLY		(uint16_t)0x8408
#define ISO15_CRC_CHECK		((uint16_t)(~0xF0B8 & 0xFFFF)) 	// use this for checking of a correct crc

// REQUEST FLAGS

#define ISO15_REQ_SUBCARRIER_SINGLE	0x00	// Tag should respond using one subcarrier (ASK)
#define ISO15_REQ_SUBCARRIER_TWO		0x01	// Tag should respond using two subcarriers (FSK)
#define ISO15_REQ_DATARATE_LOW		0x00	// Tag should respond using low data rate
#define ISO15_REQ_DATARATE_HIGH		0x02	// Tag should respond using high data rate
#define ISO15_REQ_NONINVENTORY		0x00
#define ISO15_REQ_INVENTORY		0x04	// This is an inventory request - see inventory flags
#define ISO15_REQ_PROTOCOL_NONEXT		0x00
#define ISO15_REQ_PROTOCOL_EXT		0x08	// RFU

// REQUEST FLAGS when INVENTORY is not set

#define ISO15_REQ_SELECT			0x10	// only selected cards response
#define ISO15_REQ_ADDRESS			0x20	// this req contains an address
#define ISO15_REQ_OPTION			0x40	// Command specific option selector

//REQUEST FLAGS when INVENTORY is set

#define ISO15_REQINV_AFI			0x10	// AFI Field is present
#define ISO15_REQINV_SLOT1		0x20	// 1 Slot
#define ISO15_REQINV_SLOT16		0x00	// 16 Slots
#define ISO15_REQINV_OPTION		0x40	// Command specific option selector

//RESPONSE FLAGS
#define ISO15_RES_ERROR			0x01
#define ISO15_RES_EXT			0x08	// Protocol Extention	

// RESPONSE ERROR CODES
#define ISO15_NOERROR			0x00
#define ISO15_ERROR_CMD_NOT_SUP		0x01	// Command not supported
#define ISO15_ERROR_CMD_NOT_REC		0x02	// Command not recognized (eg. parameter error)
#define ISO15_ERROR_CMD_OPTION		0x03	// Command option not supported
#define ISO15_ERROR_GENERIC		0x0F	// No additional Info about this error
#define ISO15_ERROR_BLOCK_UNAVAILABLE	0x10	
#define ISO15_ERROR_BLOCK_LOCKED_ALREADY	0x11	// cannot lock again
#define ISO15_ERROR_BLOCK_LOCKED		0x12	// cannot be changed
#define ISO15_ERROR_BLOCK_WRITE		0x13	// Writing was unsuccessful
#define ISO15_ERROR_BLOCL_WRITELOCK	0x14	// Locking was unsuccessful

// COMMAND CODES
#define ISO15_CMD_INVENTORY			0x01
#define ISO15_CMD_STAYQUIET			0x02
#define ISO15_CMD_READ					0x20
#define ISO15_CMD_WRITE					0x21
#define ISO15_CMD_LOCK					0x22
#define ISO15_CMD_READMULTI			0x23
#define ISO15_CMD_WRITEMULTI			0x24
#define ISO15_CMD_SELECT				0x25
#define ISO15_CMD_RESET					0x26
#define ISO15_CMD_WRITEAFI				0x27
#define ISO15_CMD_LOCKAFI				0x28
#define ISO15_CMD_WRITEDSFID			0x29
#define ISO15_CMD_LOCKDSFID			0x2A
#define ISO15_CMD_SYSINFO				0x2B
#define ISO15_CMD_SECSTATUS			0x2C


uint16_t Iso15693Crc(uint8_t *v, int n);
int Iso15693AddCrc(uint8_t *req, int n);
char* Iso15693sprintUID(char *target,uint8_t *uid);

//-----------------------------------------------------------------------------
// Map a sequence of octets (~layer 2 command) into the set of bits to feed
// to the FPGA, to transmit that command to the tag.
// Mode: highspeed && one subcarrier (ASK)
//-----------------------------------------------------------------------------

	// The sampling rate is 106.353 ksps/s, for T = 18.8 us

	// SOF defined as
	// 1) Unmodulated time of 56.64us
	// 2) 24 pulses of 423.75khz
	// 3) logic '1' (unmodulated for 18.88us followed by 8 pulses of 423.75khz)

	static const int Iso15693FrameSOF[] = {
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		-1, -1, -1, -1,
		-1, -1, -1, -1,
		 1,  1,  1,  1,
		 1,  1,  1,  1
	};
	static const int Iso15693Logic0[] = {
		 1,  1,  1,  1,
		 1,  1,  1,  1,
		-1, -1, -1, -1,
		-1, -1, -1, -1
	};
	static const int Iso15693Logic1[] = {
		-1, -1, -1, -1,
		-1, -1, -1, -1,
		 1,  1,  1,  1,
		 1,  1,  1,  1
	};

	// EOF defined as
	// 1) logic '0' (8 pulses of 423.75khz followed by unmodulated for 18.88us)
	// 2) 24 pulses of 423.75khz
	// 3) Unmodulated time of 56.64us

	static const int Iso15693FrameEOF[] = {
		 1,  1,  1,  1,
		 1,  1,  1,  1,
		-1, -1, -1, -1,
		-1, -1, -1, -1,
		 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
	};


#endif
