#ifndef CMDHF14A_H__
#define CMDHF14A_H__

int CmdHF14A(const char *Cmd);

int CmdHF14AList(const char *Cmd);
int CmdHF14AMifare(const char *Cmd);
int CmdHF14AReader(const char *Cmd);
int CmdHF14ASim(const char *Cmd);
int CmdHF14ASnoop(const char *Cmd);

#endif
