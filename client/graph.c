//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Graph utilities
//-----------------------------------------------------------------------------
#include "graph.h"

int GraphBuffer[MAX_GRAPH_TRACE_LEN];
int GraphTraceLen;
int s_Buff[MAX_GRAPH_TRACE_LEN];

/* write a manchester bit to the graph */
void AppendGraph(int redraw, int clock, int bit) {
	int i;
	//set first half the clock bit (all 1's or 0's for a 0 or 1 bit) 
	for (i = 0; i < (int)(clock / 2); ++i)
		GraphBuffer[GraphTraceLen++] = bit ;
	//set second half of the clock bit (all 0's or 1's for a 0 or 1 bit)
	for (i = (int)(clock / 2); i < clock; ++i)
		GraphBuffer[GraphTraceLen++] = bit ^ 1;

	if (redraw)
		RepaintGraphWindow();
}

// clear out our graph window
int ClearGraph(int redraw) {
	int gtl = GraphTraceLen;
	memset(GraphBuffer, 0x00, GraphTraceLen);
	GraphTraceLen = 0;
	if (redraw)
		RepaintGraphWindow();
	return gtl;
}
// option '1' to save GraphBuffer any other to restore
void save_restoreGB(uint8_t saveOpt) {
	static int SavedGB[MAX_GRAPH_TRACE_LEN];
	static int SavedGBlen = 0;
	static bool GB_Saved = false;
	static int SavedGridOffsetAdj = 0;

	if (saveOpt == GRAPH_SAVE) { //save
		memcpy(SavedGB, GraphBuffer, sizeof(GraphBuffer));
		SavedGBlen = GraphTraceLen;
		GB_Saved = true;
		SavedGridOffsetAdj = GridOffset;
	} else if (GB_Saved){ //restore
		memcpy(GraphBuffer, SavedGB, sizeof(GraphBuffer));
		GraphTraceLen = SavedGBlen;
		GridOffset = SavedGridOffsetAdj;
		RepaintGraphWindow();
	}
	return;
}

// DETECT CLOCK NOW IN LFDEMOD.C
void setGraphBuf(uint8_t *buf, size_t size) {
	if ( buf == NULL ) return;
	
	ClearGraph(0);
	
	if ( size > MAX_GRAPH_TRACE_LEN )
		size = MAX_GRAPH_TRACE_LEN;
	
	for (uint16_t i = 0; i < size; ++i)
		GraphBuffer[i] = buf[i] - 128;

	GraphTraceLen = size;
	RepaintGraphWindow();
	return;
}
size_t getFromGraphBuf(uint8_t *buf) {
	if (buf == NULL ) return 0;
	uint32_t i;
	for (i=0; i < GraphTraceLen; ++i){
		//trim
		if (GraphBuffer[i] > 127) GraphBuffer[i] = 127;
		if (GraphBuffer[i] < -127) GraphBuffer[i] = -127;
		buf[i] = (uint8_t)(GraphBuffer[i] + 128);
	}
	return i;
}

// A simple test to see if there is any data inside Graphbuffer. 
bool HasGraphData(){
	if ( GraphTraceLen <= 0) {
		PrintAndLogEx(NORMAL, "No data available, try reading something first");
		return false;
	}
	return true;	
}

// Get or auto-detect ask clock rate
int GetAskClock(const char *str, bool printAns) {

	int clock = param_get32ex(str, 0, 0, 10);
	if (clock > 0) 
		return clock;
	
	// Auto-detect clock
	uint8_t grph[MAX_GRAPH_TRACE_LEN] = {0};
	size_t size = getFromGraphBuf(grph);
	if (size == 0) {
		PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
		return -1;
	}
	//, size_t *ststart, size_t *stend
	size_t ststart = 0, stend = 0;
	bool st = DetectST(grph, &size, &clock, &ststart, &stend);
	int start = stend;
	if (st == false) {
		start = DetectASKClock(grph, size, &clock, 20);
	}
	setClockGrid(clock, start);
	// Only print this message if we're not looping something
	if (printAns || g_debugMode)
		PrintAndLogEx(NORMAL, "Auto-detected clock rate: %d, Best Starting Position: %d", clock, start);

	return clock;
}

uint8_t GetPskCarrier(const char *str, bool printAns) {
	uint8_t carrier = 0;
	uint8_t grph[MAX_GRAPH_TRACE_LEN] = {0};
	size_t size = getFromGraphBuf(grph);
	if ( size == 0 ) {
		PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
		return 0;
	}
	uint16_t fc = countFC(grph, size, 0);
	carrier = fc & 0xFF;
	if (carrier != 2 && carrier != 4 && carrier != 8) return 0;
	if (( fc >> 8) == 10 && carrier == 8) return 0;
	// Only print this message if we're not looping something
	if (printAns)
		PrintAndLogEx(NORMAL, "Auto-detected PSK carrier rate: %d", carrier);
	return carrier;
}

int GetPskClock(const char* str, bool printAns) {
	int clock = param_get32ex(str, 0, 0, 10);
	if (clock != 0) 
		return clock;
	
	// Auto-detect clock
	uint8_t grph[MAX_GRAPH_TRACE_LEN] = {0};
	size_t size = getFromGraphBuf(grph);
	if ( size == 0 ) {
		PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
		return -1;
	}
	size_t firstPhaseShiftLoc = 0;
	uint8_t curPhase = 0, fc = 0;
	clock = DetectPSKClock(grph, size, 0, &firstPhaseShiftLoc, &curPhase, &fc);
	setClockGrid(clock, firstPhaseShiftLoc);
	// Only print this message if we're not looping something
	if (printAns)
		PrintAndLogEx(NORMAL, "Auto-detected clock rate: %d", clock);
	return clock;
}

int GetNrzClock(const char* str, bool printAns) {

	int clock = param_get32ex(str, 0, 0, 10);
	if (clock != 0) 
		return clock;
	
	// Auto-detect clock
	uint8_t grph[MAX_GRAPH_TRACE_LEN] = {0};
	size_t size = getFromGraphBuf(grph);
	if ( size == 0 ) {
		PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
		return -1;
	}
	size_t clkStartIdx = 0;
	clock = DetectNRZClock(grph, size, 0, &clkStartIdx);
	setClockGrid(clock, clkStartIdx);
	// Only print this message if we're not looping something
	if (printAns)
		PrintAndLogEx(NORMAL, "Auto-detected clock rate: %d", clock);
	return clock;
}
//by marshmellow
//attempt to detect the field clock and bit clock for FSK
int GetFskClock(const char* str, bool printAns) {

	int clock = param_get32ex(str, 0, 0, 10);
	if (clock != 0) 
		return clock;

	uint8_t fc1 = 0, fc2 = 0, rf1 = 0;
	int firstClockEdge = 0;
	int ans = fskClocks(&fc1, &fc2, &rf1, &firstClockEdge);
	if (ans == 0) 
		return 0;
	
	if ((fc1==10 && fc2==8) || (fc1==8 && fc2==5)){
		if (printAns) PrintAndLogEx(NORMAL, "Detected Field Clocks: FC/%d, FC/%d - Bit Clock: RF/%d", fc1, fc2, rf1);
		setClockGrid(rf1, firstClockEdge);
		return rf1;
	}

	PrintAndLogEx(DEBUG, "DEBUG: unknown fsk field clock detected");
	PrintAndLogEx(DEBUG, "Detected Field Clocks: FC/%d, FC/%d - Bit Clock: RF/%d", fc1, fc2, rf1);
	return 0;
}
int fskClocks(uint8_t *fc1, uint8_t *fc2, uint8_t *rf1, int *firstClockEdge) {
	uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
	size_t size = getFromGraphBuf(bits);
	if (size == 0) 
		return 0;
	
	uint16_t ans = countFC(bits, size, 1); 
	if (ans == 0) {
		PrintAndLogEx(DEBUG, "DEBUG: No data found");
		return 0;
	}
	
	*fc1 = (ans >> 8) & 0xFF;
	*fc2 = ans & 0xFF;
	//int firstClockEdge = 0;
	*rf1 = detectFSKClk(bits, size, *fc1, *fc2, firstClockEdge);
	if (*rf1 == 0) {
		PrintAndLogEx(DEBUG, "DEBUG: Clock detect error");
		return 0;
	}
	return 1;
}

