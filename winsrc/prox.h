#ifndef __PROX_H
#define __PROX_H

#include "../include/usb_cmd.h"

// prox.cpp
void ReceiveCommand(UsbCommand *c);
BOOL ReceiveCommandPoll(UsbCommand *c);
void SendCommand(UsbCommand *c, BOOL wantAck);

// gui.cpp
void ShowGui();
void HideGraphWindow(void);
void ShowGraphWindow(void);
void RepaintGraphWindow(void);
void PrintToScrollback(char *fmt, ...);
#define MAX_GRAPH_TRACE_LEN (1024*128)
extern int GraphBuffer[MAX_GRAPH_TRACE_LEN];
extern int GraphTraceLen;
extern double CursorScaleFactor;
extern int PlotGridX, PlotGridY;
extern int CommandFinished;
extern int offline;

// command.cpp
static void CmdBuffClear(char *str);
static void GetFromBigBuf(BYTE *dest, int bytes);
static void CmdReset(char *str);
static void CmdQuit(char *str);
static void CmdEM410xread(char *str);
static void CmdEM410xwatch(char *str);
static void ChkBitstream(char *str);
int GetClock(char *str, int peak);
static void CmdHIDdemodFSK(char *str);
static void Cmdmanchestermod(char *str);
static void CmdTune(char *str);
static void CmdHi15read(char *str);
static void CmdHi14read(char *str);
static void CmdSri512read(char *str);
static void CmdHi14areader(char *str);
static void CmdHi15reader(char *str);
static void CmdHi15tag(char *str);
static void CmdHi14read_sim(char *str);
static void CmdHi14readt(char *str);
static void CmdHisimlisten(char *str);
static void CmdReadmem(char *str);
static void CmdHi14sim(char *str);
static void CmdHi14asim(char *str);
static void CmdHi14snoop(char *str);
static void CmdHi14asnoop(char *str);
static void CmdFPGAOff(char *str);
int CmdClearGraph(int redraw);
static void CmdAppendGraph(int redraw, int clock, int bit);
static void CmdEM410xsim(char *str);
static void CmdLosim(char *str);
static void CmdLoCommandRead(char *str);
static void CmdLoread(char *str);
static void CmdLosamples(char *str);
static void CmdBitsamples(char *str);
static void CmdHisamples(char *str);
static int CmdHisamplest(char *str, int nrlow);
static void CmdHexsamples(char *str);
static void CmdHisampless(char *str);
static WORD Iso15693Crc(BYTE *v, int n);
static void CmdHi14bdemod(char *str);
static void CmdHi14list(char *str);
static void CmdHi14alist(char *str);
static void CmdHi15demod(char *str);
static void CmdTiread(char *str);
static void CmdTibits(char *str);
static void CmdTidemod(char *cmdline);
static void CmdNorm(char *str);
static void CmdDec(char *str);
static void CmdHpf(char *str);
static void CmdZerocrossings(char *str);
static void CmdLtrim(char *str);
static void CmdAutoCorr(char *str);
static void CmdVchdemod(char *str);
static void CmdIndalademod(char *str);
static void CmdFlexdemod(char *str);
static void Cmdaskdemod(char *str);
static void Cmddetectclockrate(char *str);
int detectclock(int peak);
static void Cmdbitstream(char *str);
static void Cmdmanchesterdemod(char *str);
static void CmdHiddemod(char *str);
static void CmdPlot(char *str);
static void CmdHide(char *str);
static void CmdScale(char *str);
static void CmdSave(char *str);
static void CmdLoad(char *str);
static void CmdHIDsimTAG(char *str);
static void CmdLcdReset(char *str);
static void CmdLcd(char *str);
static void CmdTest(char *str);
static void CmdSetDivisor(char *str);
static void CmdSweepLF(char *str);
void CommandReceived(char *cmd);
void UsbCommandReceived(UsbCommand *c);


// cmdline.cpp
void ShowCommandline(void);
void ExecCmd(char *cmd);
//void PrintToScrollback(char *fmt, ...);

#endif
