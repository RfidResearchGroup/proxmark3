//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// GUI functions
//-----------------------------------------------------------------------------

#include "proxgui.h"
#include "proxguiqt.h"
#include "proxmark3.h"

static ProxGuiQT *gui = NULL;
static WorkerThread *main_loop_thread = NULL;

WorkerThread::WorkerThread(char *script_cmds_file, char *script_cmd) : script_cmds_file(script_cmds_file), script_cmd(script_cmd) {
}

WorkerThread::~WorkerThread() {
}

void WorkerThread::run() {
    main_loop(script_cmds_file, script_cmd);
}

extern "C" void ShowGraphWindow(void) {
    if (!gui)
        return;

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

extern "C" void MainGraphics(void) {
    if (!gui)
        return;

    gui->MainLoop();
}

extern "C" void InitGraphics(int argc, char **argv, char *script_cmds_file, char *script_cmd) {
#ifdef Q_WS_X11
    if (getenv("DISPLAY") == NULL)
        return;
#endif
    main_loop_thread = new WorkerThread(script_cmds_file, script_cmd);
    gui = new ProxGuiQT(argc, argv, main_loop_thread);
}

extern "C" void ExitGraphics(void) {
    if (!gui)
        return;

    gui->Exit();
    gui = NULL;
}
