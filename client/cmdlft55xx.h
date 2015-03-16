//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency T55xx commands
//-----------------------------------------------------------------------------

#ifndef CMDLFT55XX_H__
#define CMDLFT55XX_H__

typedef struct {
	enum {
		DEMOD_NRZ  = 0x00,    
		DEMOD_PSK1 = 0x01,
		DEMOD_PSK2 = 0x02,
		DEMOD_PSK3 = 0x03,
		DEMOD_FSK  = 0x04,     
		DEMOD_ASK  = 0x08,
		DEMOD_BI   = 0x16,
	}  modulation;
	bool inversed;
	uint8_t offset;
	uint32_t block0;
} t55xx_conf_block_t;

int CmdLFT55XX(const char *Cmd);
int CmdT55xxSetConfig(const char *Cmd);
int CmdT55xxReadBlock(const char *Cmd);
int CmdT55xxWriteBlock(const char *Cmd);
int CmdT55xxReadTrace(const char *Cmd);
int CmdT55xxInfo(const char *Cmd);
int CmdT55xxDetect(const char *Cmd);

char * GetBitRateStr(uint32_t id);
char * GetSaferStr(uint32_t id);
char * GetModulationStr( uint32_t id);
char * GetModelStrFromCID(uint32_t cid);
char * GetSelectedModulationStr( uint8_t id);
uint32_t PackBits(uint8_t start, uint8_t len, uint8_t* bitstream);
void printT55xxBlock(const char *demodStr);
void printConfiguration( t55xx_conf_block_t b);

void DecodeT55xxBlock();
bool tryDetectModulation();
bool test(uint8_t mode, uint8_t *offset);
int special(const char *Cmd);
#endif
