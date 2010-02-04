#ifndef CMDPARSER_H__
#define CMDPARSER_H__ 

typedef struct command_s
{
  const char * Name;
  int (*Parse)(const char *Cmd);
  int Offline;
  const char * Help;
} command_t;

// command_t array are expected to be NULL terminated

// Print help for each command in the command array
void CmdsHelp(const command_t Commands[]);
// Parse a command line
void CmdsParse(const command_t Commands[], const char *Cmd);

#endif