#include "proxgui.h"
#include "proxguiqt.h"

static ProxGuiQT *gui = NULL;

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

  gui->MainLoop();
}

extern "C" void InitGraphics(int argc, char **argv)
{
#ifdef Q_WS_X11
  bool useGUI = getenv("DISPLAY") != 0;
#else
  bool useGUI = true;
#endif
  if (!useGUI)
    return;

  gui = new ProxGuiQT(argc, argv);
}

extern "C" void ExitGraphics(void)
{
  if (!gui)
    return;

  delete gui;
  gui = NULL;
}
