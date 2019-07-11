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
size_t GraphTraceLen;
int s_Buff[MAX_GRAPH_TRACE_LEN];

/* write a manchester bit to the graph
TODO,  verfy that this doesn't overflow buffer  (iceman)
*/
void AppendGraph(bool redraw, uint16_t clock, int bit) {
    uint8_t half = clock / 2;
    uint8_t i;
    //set first half the clock bit (all 1's or 0's for a 0 or 1 bit)
    for (i = 0; i < half; ++i)
        GraphBuffer[GraphTraceLen++] = bit;

    //set second half of the clock bit (all 0's or 1's for a 0 or 1 bit)
    for (; i < clock; ++i)
        GraphBuffer[GraphTraceLen++] = bit ^ 1;

    if (redraw)
        RepaintGraphWindow();
}

// clear out our graph window
size_t ClearGraph(bool redraw) {
    size_t gtl = GraphTraceLen;
    memset(GraphBuffer, 0x00, GraphTraceLen);
    GraphTraceLen = 0;
    if (redraw)
        RepaintGraphWindow();
    return gtl;
}
// option '1' to save GraphBuffer any other to restore
void save_restoreGB(uint8_t saveOpt) {
    static int SavedGB[MAX_GRAPH_TRACE_LEN];
    static size_t SavedGBlen = 0;
    static bool GB_Saved = false;
    static int SavedGridOffsetAdj = 0;

    if (saveOpt == GRAPH_SAVE) { //save
        memcpy(SavedGB, GraphBuffer, sizeof(GraphBuffer));
        SavedGBlen = GraphTraceLen;
        GB_Saved = true;
        SavedGridOffsetAdj = GridOffset;
    } else if (GB_Saved) { //restore
        memcpy(GraphBuffer, SavedGB, sizeof(GraphBuffer));
        GraphTraceLen = SavedGBlen;
        GridOffset = SavedGridOffsetAdj;
        RepaintGraphWindow();
    }
}

void setGraphBuf(uint8_t *buff, size_t size) {
    if (buff == NULL) return;

    ClearGraph(false);

    if (size > MAX_GRAPH_TRACE_LEN)
        size = MAX_GRAPH_TRACE_LEN;

    for (size_t i = 0; i < size; ++i)
        GraphBuffer[i] = buff[i] - 128;

    GraphTraceLen = size;
    RepaintGraphWindow();
}

size_t getFromGraphBuf(uint8_t *buff) {
    if (buff == NULL) return 0;
    size_t i;
    for (i = 0; i < GraphTraceLen; ++i) {
        //trim
        if (GraphBuffer[i] > 127) GraphBuffer[i] = 127;
        if (GraphBuffer[i] < -127) GraphBuffer[i] = -127;
        buff[i] = (uint8_t)(GraphBuffer[i] + 128);
    }
    return i;
}

// A simple test to see if there is any data inside Graphbuffer.
bool HasGraphData(void) {
    if (GraphTraceLen == 0) {
        PrintAndLogEx(NORMAL, "No data available, try reading something first");
        return false;
    }
    return true;
}
bool isGraphBitstream(void) {
    // convert to bitstream if necessary
    for (int i = 0; i < GraphTraceLen; i++) {
        if (GraphBuffer[i] > 1 || GraphBuffer[i] < 0) {
            return false;
        }
    }
    return true;
}
void convertGraphFromBitstream() {
    convertGraphFromBitstreamEx(1, 0);
}
void convertGraphFromBitstreamEx(int hi, int low) {
    for (int i = 0; i < GraphTraceLen; i++) {
        if (GraphBuffer[i] == hi)
            GraphBuffer[i] = 127;
        else if (GraphBuffer[i] == low)
            GraphBuffer[i] = -127;
        else
            GraphBuffer[i] = 0;
    }
    uint8_t bits[GraphTraceLen];
    memset(bits, 0, sizeof(bits));
    size_t size = getFromGraphBuf(bits);

    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);
    RepaintGraphWindow();
}

// Get or auto-detect ask clock rate
int GetAskClock(const char *str, bool printAns) {
    if (getSignalProperties()->isnoise)
        return false;

    int clock1 = param_get32ex(str, 0, 0, 10);
    if (clock1 > 0)
        return clock1;

    // Auto-detect clock
    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
        return -1;
    }

    size_t ststart = 0, stend = 0;
    bool st = DetectST(bits, &size, &clock1, &ststart, &stend);
    int idx = stend;
    if (st == false) {
        idx = DetectASKClock(bits, size, &clock1, 20);
    }

    if (clock1 > 0) {
        setClockGrid(clock1, idx);
    }
    // Only print this message if we're not looping something
    if (printAns || g_debugMode)
        PrintAndLogEx(SUCCESS, "Auto-detected clock rate: %d, Best Starting Position: %d", clock1, idx);

    return clock1;
}

uint8_t GetPskCarrier(const char *str, bool printAns) {
    if (getSignalProperties()->isnoise)
        return false;

    uint8_t carrier = 0;
    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
        return 0;
    }
    uint16_t fc = countFC(bits, size, false);
    carrier = fc & 0xFF;
    if (carrier != 2 && carrier != 4 && carrier != 8) return 0;
    if ((fc >> 8) == 10 && carrier == 8) return 0;
    // Only print this message if we're not looping something
    if (printAns)
        PrintAndLogEx(SUCCESS, "Auto-detected PSK carrier rate: %d", carrier);
    return carrier;
}

int GetPskClock(const char *str, bool printAns) {

    if (getSignalProperties()->isnoise)
        return -1;

    int clock1 = param_get32ex(str, 0, 0, 10);
    if (clock1 != 0)
        return clock1;

    // Auto-detect clock
    uint8_t grph[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(grph);
    if (size == 0) {
        PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
        return -1;
    }
    size_t firstPhaseShiftLoc = 0;
    uint8_t curPhase = 0, fc = 0;
    clock1 = DetectPSKClock(grph, size, 0, &firstPhaseShiftLoc, &curPhase, &fc);
    setClockGrid(clock1, firstPhaseShiftLoc);
    // Only print this message if we're not looping something
    if (printAns)
        PrintAndLogEx(SUCCESS, "Auto-detected clock rate: %d", clock1);

    return clock1;
}

int GetNrzClock(const char *str, bool printAns) {

    if (getSignalProperties()->isnoise)
        return -1;

    int clock1 = param_get32ex(str, 0, 0, 10);
    if (clock1 != 0)
        return clock1;

    // Auto-detect clock
    uint8_t grph[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(grph);
    if (size == 0) {
        PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
        return -1;
    }
    size_t clkStartIdx = 0;
    clock1 = DetectNRZClock(grph, size, 0, &clkStartIdx);
    setClockGrid(clock1, clkStartIdx);
    // Only print this message if we're not looping something
    if (printAns)
        PrintAndLogEx(SUCCESS, "Auto-detected clock rate: %d", clock1);

    return clock1;
}
//by marshmellow
//attempt to detect the field clock and bit clock for FSK
int GetFskClock(const char *str, bool printAns) {

    int clock1 = param_get32ex(str, 0, 0, 10);
    if (clock1 != 0)
        return clock1;

    uint8_t fc1 = 0, fc2 = 0, rf1 = 0;
    int firstClockEdge = 0;

    if (!fskClocks(&fc1, &fc2, &rf1, &firstClockEdge))
        return 0;

    if ((fc1 == 10 && fc2 == 8) || (fc1 == 8 && fc2 == 5)) {
        if (printAns)
            PrintAndLogEx(SUCCESS, "Detected Field Clocks: FC/%d, FC/%d - Bit Clock: RF/%d", fc1, fc2, rf1);
        setClockGrid(rf1, firstClockEdge);
        return rf1;
    }

    PrintAndLogEx(DEBUG, "DEBUG: unknown fsk field clock detected");
    PrintAndLogEx(DEBUG, "Detected Field Clocks: FC/%d, FC/%d - Bit Clock: RF/%d", fc1, fc2, rf1);
    return 0;
}
bool fskClocks(uint8_t *fc1, uint8_t *fc2, uint8_t *rf1, int *firstClockEdge) {

    if (getSignalProperties()->isnoise)
        return false;

    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(bits);
    if (size == 0)
        return false;

    uint16_t ans = countFC(bits, size, true);
    if (ans == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: No data found");
        return false;
    }

    *fc1 = (ans >> 8) & 0xFF;
    *fc2 = ans & 0xFF;
    *rf1 = detectFSKClk(bits, size, *fc1, *fc2, firstClockEdge);
    if (*rf1 == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Clock detect error");
        return false;
    }
    return true;
}

