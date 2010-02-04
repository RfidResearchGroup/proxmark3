#ifndef GRAPH_H__
#define GRAPH_H__

void AppendGraph(int redraw, int clock, int bit);
int ClearGraph(int redraw);
int DetectClock(int peak);
int GetClock(const char *str, int peak, int verbose);

#define MAX_GRAPH_TRACE_LEN (1024*128)
extern int GraphBuffer[MAX_GRAPH_TRACE_LEN];
extern int GraphTraceLen;

#endif
