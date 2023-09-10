//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// GUI dummy file
//-----------------------------------------------------------------------------

#include <stdio.h>

extern "C" void ShowGraphWindow(void) {
    static int warned = 0;

    if (!warned) {
        printf("No GUI in this build!\n");
        warned = 1;
    }
}

extern "C" void HideGraphWindow(void) {}
extern "C" void RepaintGraphWindow(void) {}

extern "C" void ShowPictureWindow(char *fn, int len) {
    static int warned = 0;

    if (!warned) {
        printf("No GUI in this build!\n");
        warned = 1;
    }
}
extern "C" void ShowBase64PictureWindow(char *b64) {
    static int warned = 0;

    if (!warned) {
        printf("No GUI in this build!\n");
        warned = 1;
    }
}
extern "C" void HidePictureWindow(void) {}
extern "C" void RepaintPictureWindow(void) {}

extern "C" void MainGraphics() {}
extern "C" void InitGraphics(int argc, char **argv) {}
extern "C" void ExitGraphics(void) {}
