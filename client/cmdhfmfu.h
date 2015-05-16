#include "cmdhfmf.h"
#include "cmdhf14a.h"

#ifndef CMDHFMFU_H__
#define CMDHFMFU_H__

//standard ultralight
int CmdHF14AMfUWrBl(const char *Cmd);
int CmdHF14AMfURdBl(const char *Cmd);

//Crypto Cards
int CmdHF14AMfUCRdBl(const char *Cmd);
int CmdHF14AMfUCRdCard(const char *Cmd);
int CmdHF14AMfucAuth(const char *Cmd);

uint8_t requestAuthentication( uint8_t *nonce);
int try3DesAuthentication( uint8_t *key, bool switch_off_field);

//general stuff
int CmdHF14AMfUDump(const char *Cmd);
int CmdHF14AMfUInfo(const char *Cmd);
uint16_t GetHF14AMfU_Type(void);

void rol (uint8_t *data, const size_t len);
int ul_print_type(uint16_t tagtype, uint8_t spacer);
void ul_switch_off_field(void);

int usage_hf_mfu_dump(void);
int usage_hf_mfu_info(void);

int CmdHFMFUltra(const char *Cmd);

typedef enum TAGTYPE_UL {
	UNKNOWN       = 0x0000,
	UL            = 0x0001,
	UL_C          = 0x0002,
	UL_EV1_48     = 0x0004,
	UL_EV1_128    = 0x0008,
	NTAG          = 0x0010,
	NTAG_213      = 0x0020,
	NTAG_215      = 0x0040,
	NTAG_216      = 0x0080,
	MY_D          = 0x0100,
	MY_D_NFC      = 0x0200,
	MY_D_MOVE     = 0x0400,
	MY_D_MOVE_NFC = 0x0800,
	MAGIC         = 0x1000,
	UL_MAGIC      = UL | MAGIC,
	UL_C_MAGIC    = UL_C | MAGIC,
	UL_ERROR      = 0xFFFF,
} TagTypeUL_t;

#endif
