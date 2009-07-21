#ifdef __cplusplus
extern "C" {
#endif

void ShowGraphWindow(void);
void HideGraphWindow(void);
void RepaintGraphWindow(void);
void MainGraphics(void);
void InitGraphics(int argc, char **argv);
void ExitGraphics(void);

#define MAX_GRAPH_TRACE_LEN (1024*128)
extern int GraphBuffer[MAX_GRAPH_TRACE_LEN];
extern int GraphTraceLen;
extern double CursorScaleFactor;
extern int PlotGridX, PlotGridY;
extern int CommandFinished;
extern int offline;

#ifdef __cplusplus
}
#endif
