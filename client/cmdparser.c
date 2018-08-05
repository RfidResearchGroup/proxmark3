//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Command parser
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "ui.h"
#include "cmdparser.h"
#include "proxmark3.h"

void CmdsHelp(const command_t Commands[]) {
	if (Commands[0].Name == NULL) return;
	int i = 0;
	while (Commands[i].Name) {
		if (!offline || Commands[i].Offline)
			PrintAndLogEx(NORMAL, "%-16s %s", Commands[i].Name, Commands[i].Help);
		++i;
	}
}

int CmdsParse(const command_t Commands[], const char *Cmd) {
	// Help dump children
	if (strcmp( Cmd, "XX_internal_command_dump_XX") == 0) {
		dumpCommandsRecursive(Commands, 0);
		return 0;
	}
	// Markdown help dump children
	if(strcmp( Cmd, "XX_internal_command_dump_markdown_XX") == 0) {
		dumpCommandsRecursive(Commands, 1);
		return 0;
	}
	char cmd_name[128];
	int len = 0;
	memset(cmd_name, 0, sizeof(cmd_name));
	sscanf(Cmd, "%127s%n", cmd_name, &len);
	str_lower(cmd_name);
	int i = 0;
	while (Commands[i].Name && strcmp(Commands[i].Name, cmd_name))
		++i;

	/* try to find exactly one prefix-match */
	if (!Commands[i].Name) {
		int last_match = 0;
		int matches = 0;

		for (i=0; Commands[i].Name; i++) {
			if( !strncmp(Commands[i].Name, cmd_name, strlen(cmd_name)) ) {
				last_match = i;
				matches++;
			}
		}
		if (matches == 1) i = last_match;
	}

	if (Commands[i].Name) {
		while (Cmd[len] == ' ')
		++len;
		return Commands[i].Parse(Cmd + len);
	} else {
		// show help for selected hierarchy or if command not recognised
		CmdsHelp(Commands);
	}

	return 0;
}

char pparent[512] = {0};
char *parent = pparent;

void dumpCommandsRecursive(const command_t cmds[], int markdown) {
	if (cmds[0].Name == NULL) return;

	int i = 0;
	int w_cmd = 25;
	int w_off = 8;
	// First, dump all single commands, which are not a container for 
	// other commands
	if (markdown) {
		PrintAndLogEx(NORMAL, "|%-*s|%-*s|%s\n",w_cmd,"command",w_off,"offline","description");
		PrintAndLogEx(NORMAL, "|%-*s|%-*s|%s\n",w_cmd,"-------",w_off,"-------","-----------");
	} else {
		PrintAndLogEx(NORMAL, "%-*s|%-*s|%s\n",w_cmd,"command",w_off,"offline","description");
		PrintAndLogEx(NORMAL, "%-*s|%-*s|%s\n",w_cmd,"-------",w_off,"-------","-----------");
	}

	while (cmds[i].Name) {
		char* cmd_offline = "N";
		if (cmds[i].Help[0] == '{' && ++i) continue;

		if ( cmds[i].Offline) 
			cmd_offline = "Y";
		if (markdown)
		  PrintAndLogEx(NORMAL, "|`%s%-*s`|%-*s|`%s`\n", parent, w_cmd-(int)strlen(parent)-2, cmds[i].Name, w_off, cmd_offline, cmds[i].Help);
		else
		  PrintAndLogEx(NORMAL, "%s%-*s|%-*s|%s\n", parent, w_cmd-(int)strlen(parent), cmds[i].Name, w_off, cmd_offline, cmds[i].Help);
		++i;
	}
	PrintAndLogEx(NORMAL, "\n\n");
	i = 0;
	
	// Then, print the categories. These will go into subsections with their own tables
	while (cmds[i].Name) {
		if(cmds[i].Help[0] != '{' && ++i)  continue;

		PrintAndLogEx(NORMAL, "### %s%s\n\n %s\n\n", parent, cmds[i].Name, cmds[i].Help);

		char currentparent[512] = {0};
		snprintf(currentparent, sizeof currentparent, "%s%s ", parent, cmds[i].Name);
		char *old_parent = parent;
		parent = currentparent;
		// This is what causes the recursion, since commands Parse-implementation
		// in turn calls the CmdsParse above. 
		if (markdown)
		  cmds[i].Parse("XX_internal_command_dump_markdown_XX");
		else
		  cmds[i].Parse("XX_internal_command_dump_XX");

		parent = old_parent;
		++i;
	}
}
