#include "cmdhfmf.h"
#include "cmdhf14a.h"

//standard ultralight
int CmdHF14AMfUWrBl(const char *Cmd);
int CmdHF14AMfURdBl(const char *Cmd);

//Crypto Cards
int CmdHF14AMfUCRdBl(const char *Cmd);
int CmdHF14AMfUCRdCard(const char *Cmd);
int CmdHF14AMfucAuth(const char *Cmd);

//general stuff
int CmdHF14AMfUDump(const char *Cmd);
void rol (uint8_t *data, const size_t len);


int CmdHFMFUltra(const char *Cmd);
int CmdHF14AMfUInfo(const char *Cmd);
