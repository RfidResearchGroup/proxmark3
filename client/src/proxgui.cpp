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
// GUI functions
//-----------------------------------------------------------------------------

#include "proxgui.h"

#include <string.h>
#include "proxguiqt.h"
#include "proxmark3.h"
#include "ui.h"  // for prints

static ProxGuiQT *gui = NULL;
static WorkerThread *main_loop_thread = NULL;

WorkerThread::WorkerThread(char *script_cmds_file, char *script_cmd, bool stayInCommandLoop) : script_cmds_file(script_cmds_file), script_cmd(script_cmd), stayInCommandLoop(stayInCommandLoop) {
}

WorkerThread::~WorkerThread() {
}

void WorkerThread::run() {
    main_loop(script_cmds_file, script_cmd, stayInCommandLoop);
}

extern "C" void ShowGraphWindow(void) {
    if (!gui) {
        // Show a notice if X11/XQuartz isn't available
#if defined(__MACH__) && defined(__APPLE__)
        PrintAndLogEx(WARNING, "You appear to be on a MacOS device without XQuartz.\nYou may need to install XQuartz (https://www.xquartz.org/) to make the plot work.");
#else
        PrintAndLogEx(WARNING, "You appear to be on an environment without an X11 server or without DISPLAY environment variable set.\nPlot may not work until you resolve these issues.");
#endif
        return;
    }

    gui->ShowGraphWindow();

}

extern "C" void HideGraphWindow(void) {
    if (!gui)
        return;

    gui->HideGraphWindow();
}

extern "C" void RepaintGraphWindow(void) {
    if (!gui)
        return;

    gui->RepaintGraphWindow();
}


// hook up picture viewer
extern "C" void ShowPictureWindow(uint8_t *data, int len) {
    // No support for jpeg2000 in Qt Image since a while...
    // https://doc.qt.io/qt-5/qtimageformats-index.html
    QImage img = QImage::fromData(data, len);
    if (img.isNull()) {
        return;
    }
    if (!gui) {
        // Show a notice if X11/XQuartz isn't available
#if defined(__MACH__) && defined(__APPLE__)
        PrintAndLogEx(WARNING, "You appear to be on a MacOS device without XQuartz.\nYou may need to install XQuartz (https://www.xquartz.org/) to make the plot work.");
#else
        PrintAndLogEx(WARNING, "You appear to be on an environment without an X11 server or without DISPLAY environment variable set.\nPicture display may not work until you resolve these issues.");
#endif
        return;
    }

    gui->ShowPictureWindow(img);
}

extern "C" void ShowBase64PictureWindow(char *b64) {
    if (!gui) {
        // Show a notice if X11/XQuartz isn't available
#if defined(__MACH__) && defined(__APPLE__)
        PrintAndLogEx(WARNING, "You appear to be on a MacOS device without XQuartz.\nYou may need to install XQuartz (https://www.xquartz.org/) to make the plot work.");
#else
        PrintAndLogEx(WARNING, "You appear to be on an environment without an X11 server or without DISPLAY environment variable set.\nPlot may not work until you resolve these issues.");
#endif
        return;
    }

    gui->ShowBase64PictureWindow(b64);
}

extern "C" void HidePictureWindow(void) {
    if (!gui)
        return;

    gui->HidePictureWindow();
}

extern "C" void RepaintPictureWindow(void) {
    if (!gui)
        return;

    gui->RepaintPictureWindow();
}

extern "C" void MainGraphics(void) {
    if (!gui)
        return;

    gui->MainLoop();
}

extern "C" void InitGraphics(int argc, char **argv, char *script_cmds_file, char *script_cmd, bool stayInCommandLoop) {
#ifdef Q_WS_X11
    if (getenv("DISPLAY") == NULL)
        return;
#endif
#if QT_VERSION >= 0x050100
    qunsetenv("SESSION_MANAGER");
#endif
    main_loop_thread = new WorkerThread(script_cmds_file, script_cmd, stayInCommandLoop);
    gui = new ProxGuiQT(argc, argv, main_loop_thread);
}

extern "C" void ExitGraphics(void) {
    if (!gui)
        return;

    gui->Exit();
    gui = NULL;
}
