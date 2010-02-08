#include <stdio.h>
#include <string.h>
#include "ui.h"
#include "cmdparser.h"

void CmdsHelp(const command_t Commands[])
{
  if (Commands[0].Name == NULL)
    return;
  int i = 0;
  while (Commands[i].Name)
  {
    if (!offline || Commands[i].Offline)
      PrintAndLog("%-16s %s", Commands[i].Name, Commands[i].Help);
    ++i;
  }
}

void CmdsParse(const command_t Commands[], const char *Cmd)
{
  char cmd_name[32];
  int len = 0;
  memset(cmd_name, 0, 32);
  sscanf(Cmd, "%31s%n", cmd_name, &len);
  int i = 0;
  while (Commands[i].Name && strcmp(Commands[i].Name, cmd_name))
    ++i;

  /* try to find exactly one prefix-match */
  if(!Commands[i].Name) {
    int last_match = 0;
    int matches = 0;

    for(i=0;Commands[i].Name;i++) {
      if( !strncmp(Commands[i].Name, cmd_name, strlen(cmd_name)) ) {
        last_match = i;
        matches++;
      }
    }
    if(matches == 1) i=last_match;
  }

  if (Commands[i].Name)
    Commands[i].Parse(Cmd + len);
  else
    // show help (always first in array) for selected hierarchy or if command not recognised
    CmdsHelp(Commands);
}
