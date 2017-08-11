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

WorkerThread::WorkerThread(char *script_cmds_file, bool usb_present) : script_cmds_file(script_cmds_file), usb_present(usb_present)
{
}

WorkerThread::~WorkerThread() 
{
}

void WorkerThread::run() {
	main_loop(script_cmds_file, usb_present);
}

extern "C" void ShowGraphWindow(void)
{
	if (!gui)
		return;
	gui->ShowGraphWindow();
}

extern "C" void HideGraphWindow(void)
{
	if (!gui)
		return;
	gui->HideGraphWindow();
}

extern "C" void RepaintGraphWindow(void)
{
	if (!gui)
		return;

	gui->RepaintGraphWindow();
}

extern "C" void MainGraphics(void)
{
	if (!gui)
		return;

	main_loop_thread->start();
	gui->MainLoop();
}

extern "C" void InitGraphics(int argc, char **argv, char *script_cmds_file, bool usb_present)
{
#ifdef Q_WS_X11
	bool useGUI = getenv("DISPLAY") != 0;
#else
	bool useGUI = true;
#endif
	if (!useGUI)
		return;

	gui = new ProxGuiQT(argc, argv);
	main_loop_thread = new WorkerThread(script_cmds_file, usb_present);
	QObject::connect(main_loop_thread, SIGNAL(finished()), main_loop_thread, SLOT(deleteLater()));
	QObject::connect(main_loop_thread, SIGNAL(finished()), gui, SLOT(_Exit()));
}


extern "C" void ExitGraphics(void)
{
	if (!gui)
		return;

	gui->Exit();
	gui = NULL;
}
