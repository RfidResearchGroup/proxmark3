//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// GUI dummy file
//-----------------------------------------------------------------------------

#include <stdio.h>

void ShowGraphWindow(void)
{
	static int warned = 0;

	if (!warned) {
		printf("No GUI in this build!\n");
		warned = 1;
	}
}

void HideGraphWindow(void) {}
void RepaintGraphWindow(void) {}
void MainGraphics() {}
void InitGraphics(int argc, char **argv) {}
void ExitGraphics(void) {}
