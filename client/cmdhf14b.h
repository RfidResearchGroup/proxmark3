#ifndef CMDHF14B_H__
#define CMDHF14B_H__

int CmdHF14B(const char *Cmd);

int CmdHF14BDemod(const char *Cmd);
int CmdHF14BList(const char *Cmd);
int CmdHF14BRead(const char *Cmd);
int CmdHF14Sim(const char *Cmd);
int CmdHFSimlisten(const char *Cmd);
int CmdHF14BSnoop(const char *Cmd);
int CmdSri512Read(const char *Cmd);
int CmdSrix4kRead(const char *Cmd);

#endif
