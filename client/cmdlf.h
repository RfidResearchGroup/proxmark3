#ifndef CMDLF_H__
#define CMDLF_H__

int CmdLF(const char *Cmd);

int CmdLFCommandRead(const char *Cmd);
int CmdFlexdemod(const char *Cmd);
int CmdIndalaDemod(const char *Cmd);
int CmdLFRead(const char *Cmd);
int CmdLFSim(const char *Cmd);
int CmdLFSimBidir(const char *Cmd);
int CmdLFSimManchester(const char *Cmd);
int CmdVchDemod(const char *Cmd);

#endif
