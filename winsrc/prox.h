#ifndef __PROX_H
#define __PROX_H

#include "../include/usb_cmd.h"

// prox.cpp
void ReceiveCommand(UsbCommand *c);
BOOL ReceiveCommandPoll(UsbCommand *c);
void SendCommand(UsbCommand *c, BOOL wantAck);

// gui.cpp
void ShowGui(void);
void HideGraphWindow(void);
void ShowGraphWindow(void);
void RepaintGraphWindow(void);
void PrintToScrollback(char *fmt, ...);
#define MAX_GRAPH_TRACE_LEN (1024*128)
extern int GraphBuffer[MAX_GRAPH_TRACE_LEN];
extern int GraphTraceLen;
extern double CursorScaleFactor;
extern int CommandFinished;

// command.cpp
void CommandReceived(char *cmd);
void UsbCommandReceived(UsbCommand *c);

// cmdline.cpp
void ShowCommandline(void);
void ExecCmd(char *cmd);
//void PrintToScrollback(char *fmt, ...);

#endif
