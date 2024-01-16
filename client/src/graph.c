//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Graph utilities
//-----------------------------------------------------------------------------
#include "graph.h"
#include <stdlib.h>
#include <string.h>
#include "ui.h"
#include "proxgui.h"
#include "util.h"    //param_get32ex
#include "lfdemod.h"
#include "cmddata.h" //for g_debugmode


int g_GraphBuffer[MAX_GRAPH_TRACE_LEN];
size_t g_GraphTraceLen;

/* write a manchester bit to the graph
*/
void AppendGraph(bool redraw, uint16_t clock, int bit) {
    uint16_t half = clock / 2;
    uint16_t end = clock;
    uint16_t i;

    // overflow/underflow safe checks ... Assumptions:
    //     _Assert(g_GraphTraceLen >= 0);
    //     _Assert(g_GraphTraceLen <= MAX_GRAPH_TRACE_LEN);
    // If this occurs, allow partial rendering, up to the last sample...
    if ((MAX_GRAPH_TRACE_LEN - g_GraphTraceLen) < half) {
        PrintAndLogEx(DEBUG, "WARNING: AppendGraph() - Request exceeds max graph length");
        end = MAX_GRAPH_TRACE_LEN - g_GraphTraceLen;
        half = end;
    }
    if ((MAX_GRAPH_TRACE_LEN - g_GraphTraceLen) < end) {
        PrintAndLogEx(DEBUG, "WARNING: AppendGraph() - Request exceeds max graph length");
        end = MAX_GRAPH_TRACE_LEN - g_GraphTraceLen;
    }

    //set first half the clock bit (all 1's or 0's for a 0 or 1 bit)
    for (i = 0; i < half; ++i) {
        g_GraphBuffer[g_GraphTraceLen++] = bit;
    }

    //set second half of the clock bit (all 0's or 1's for a 0 or 1 bit)
    for (; i < end; ++i) {
        g_GraphBuffer[g_GraphTraceLen++] = bit ^ 1;
    }

    if (redraw) {
        RepaintGraphWindow();
    }
}

// clear out our graph window
size_t ClearGraph(bool redraw) {
    size_t gtl = g_GraphTraceLen;
    memset(g_GraphBuffer, 0x00, g_GraphTraceLen);
    g_GraphTraceLen = 0;
    g_GraphStart = 0;
    g_GraphStop = 0;

    g_DemodBufferLen = 0;
    if (redraw)
        RepaintGraphWindow();

    return gtl;
}
// option '1' to save g_GraphBuffer any other to restore
void save_restoreGB(uint8_t saveOpt) {
    static int SavedGB[MAX_GRAPH_TRACE_LEN];
    static size_t SavedGBlen = 0;
    static bool GB_Saved = false;
    static int Savedg_GridOffsetAdj = 0;

    if (saveOpt == GRAPH_SAVE) { //save
        memcpy(SavedGB, g_GraphBuffer, sizeof(g_GraphBuffer));
        SavedGBlen = g_GraphTraceLen;
        GB_Saved = true;
        Savedg_GridOffsetAdj = g_GridOffset;
    } else if (GB_Saved) { //restore
        memcpy(g_GraphBuffer, SavedGB, sizeof(g_GraphBuffer));
        g_GraphTraceLen = SavedGBlen;
        g_GridOffset = Savedg_GridOffsetAdj;
        RepaintGraphWindow();
    }
}

void setGraphBuf(const uint8_t *src, size_t size) {
    if (src == NULL) return;

    ClearGraph(false);

    if (size > MAX_GRAPH_TRACE_LEN)
        size = MAX_GRAPH_TRACE_LEN;

    for (size_t i = 0; i < size; ++i)
        g_GraphBuffer[i] = src[i] - 128;

    g_GraphTraceLen = size;
    RepaintGraphWindow();
}

size_t getFromGraphBuf(uint8_t *dest) {
    if (dest == NULL) return 0;
    if (g_GraphTraceLen == 0) return 0;

    size_t i;
    for (i = 0; i < g_GraphTraceLen; ++i) {
        //trim
        if (g_GraphBuffer[i] > 127) g_GraphBuffer[i] = 127;
        if (g_GraphBuffer[i] < -127) g_GraphBuffer[i] = -127;
        dest[i] = (uint8_t)(g_GraphBuffer[i] + 128);
    }
    return i;
}

// A simple test to see if there is any data inside Graphbuffer.
bool HasGraphData(void) {
    if (g_GraphTraceLen == 0) {
        PrintAndLogEx(NORMAL, "No data available, try reading something first");
        return false;
    }
    return true;
}

bool isGraphBitstream(void) {
    // convert to bitstream if necessary
    for (int i = 0; i < g_GraphTraceLen; i++) {
        if (g_GraphBuffer[i] > 1 || g_GraphBuffer[i] < 0) {
            return false;
        }
    }
    return true;
}

void convertGraphFromBitstream(void) {
    convertGraphFromBitstreamEx(1, 0);
}

void convertGraphFromBitstreamEx(int hi, int low) {
    for (int i = 0; i < g_GraphTraceLen; i++) {
        if (g_GraphBuffer[i] == hi)
            g_GraphBuffer[i] = 127;
        else if (g_GraphBuffer[i] == low)
            g_GraphBuffer[i] = -127;
        else
            g_GraphBuffer[i] = 0;
    }

    uint8_t *bits = calloc(g_GraphTraceLen, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(DEBUG, "ERR: convertGraphFromBitstreamEx, failed to allocate memory");
        return;
    }

    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
        free(bits);
        return;
    }

    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);
    free(bits);
    RepaintGraphWindow();
}

// Get or auto-detect ask clock rate
int GetAskClock(const char *str, bool verbose) {
    if (getSignalProperties()->isnoise)
        return -1;

    int clock1 = param_get32ex(str, 0, 0, 10);
    if (clock1 > 0)
        return clock1;

    // Auto-detect clock

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN,  sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return -1;
    }

    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
        free(bits);
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
    if (verbose || g_debugMode)
        PrintAndLogEx(SUCCESS, "Auto-detected clock rate: %d, Best Starting Position: %d", clock1, idx);

    free(bits);
    return clock1;
}

int GetPskCarrier(bool verbose) {
    if (getSignalProperties()->isnoise)
        return -1;

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN,  sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return -1;
    }

    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
        free(bits);
        return -1;
    }

    uint16_t fc = countFC(bits, size, false);
    free(bits);

    uint8_t carrier = fc & 0xFF;
    if (carrier != 2 && carrier != 4 && carrier != 8) return 0;
    if ((fc >> 8) == 10 && carrier == 8) return 0;
    // Only print this message if we're not looping something
    if (verbose)
        PrintAndLogEx(SUCCESS, "Auto-detected PSK carrier rate: %d", carrier);

    return carrier;
}

int GetPskClock(const char *str, bool verbose) {

    if (getSignalProperties()->isnoise)
        return -1;

    int clock1 = param_get32ex(str, 0, 0, 10);
    if (clock1 != 0)
        return clock1;

    // Auto-detect clock
    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN,  sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return -1;
    }

    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
        free(bits);
        return -1;
    }

    size_t firstPhaseShiftLoc = 0;
    uint8_t curPhase = 0, fc = 0;
    clock1 = DetectPSKClock(bits, size, 0, &firstPhaseShiftLoc, &curPhase, &fc);

    if (clock1 >= 0)
        setClockGrid(clock1, firstPhaseShiftLoc);

    // Only print this message if we're not looping something
    if (verbose)
        PrintAndLogEx(SUCCESS, "Auto-detected clock rate: %d", clock1);

    free(bits);
    return clock1;
}

int GetNrzClock(const char *str, bool verbose) {

    if (getSignalProperties()->isnoise)
        return -1;

    int clock1 = param_get32ex(str, 0, 0, 10);
    if (clock1 != 0)
        return clock1;

    // Auto-detect clock
    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN,  sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return -1;
    }

    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
        free(bits);
        return -1;
    }

    size_t clkStartIdx = 0;
    clock1 = DetectNRZClock(bits, size, 0, &clkStartIdx);
    setClockGrid(clock1, clkStartIdx);
    // Only print this message if we're not looping something
    if (verbose)
        PrintAndLogEx(SUCCESS, "Auto-detected clock rate: %d", clock1);

    free(bits);
    return clock1;
}

//by marshmellow
//attempt to detect the field clock and bit clock for FSK
int GetFskClock(const char *str, bool verbose) {

    int clock1 = param_get32ex(str, 0, 0, 10);
    if (clock1 != 0)
        return clock1;

    uint8_t fc1 = 0, fc2 = 0, rf1 = 0;
    int firstClockEdge = 0;

    if (fskClocks(&fc1, &fc2, &rf1, &firstClockEdge) == false)
        return 0;

    if ((fc1 == 10 && fc2 == 8) || (fc1 == 8 && fc2 == 5)) {
        if (verbose)
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

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN,  sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return false;
    }

    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(WARNING, "Failed to copy from graphbuffer");
        free(bits);
        return false;
    }

    uint16_t ans = countFC(bits, size, true);
    if (ans == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: No data found");
        free(bits);
        return false;
    }

    *fc1 = (ans >> 8) & 0xFF;
    *fc2 = ans & 0xFF;
    *rf1 = detectFSKClk(bits, size, *fc1, *fc2, firstClockEdge);

    free(bits);

    if (*rf1 == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Clock detect error");
        return false;
    }
    return true;
}

