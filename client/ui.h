#ifndef UI_H__
#define UI_H__

void ShowGui(void);
void HideGraphWindow(void);
void ShowGraphWindow(void);
void RepaintGraphWindow(void);
void PrintAndLog(char *fmt, ...);
void SetLogFilename(char *fn);

extern double CursorScaleFactor;
extern int PlotGridX, PlotGridY;
extern int offline;

#endif
