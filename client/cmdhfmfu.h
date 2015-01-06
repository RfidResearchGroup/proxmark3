#include "cmdhfmf.h"


//standard ultralight
int CmdHF14AMfUWrBl(const char *Cmd);
int CmdHF14AMfURdBl(const char *Cmd);
int CmdHF14AMfURdCard(const char *Cmd);
int CmdHF14AMfUDump(const char *Cmd);
//Crypto Cards
int CmdHF14AMfUCRdBl(const char *Cmd);
int CmdHF14AMfUCRdCard(const char *Cmd);
int CmdHF14AMfUCDump(const char *Cmd);
int CmdHF14AMfucAuth(const char *Cmd);
void rol (uint8_t *data, const size_t len);

//general stuff
int CmdHFMFUltra(const char *Cmd);
int CmdHF14AMfUInfo(const char *Cmd)
