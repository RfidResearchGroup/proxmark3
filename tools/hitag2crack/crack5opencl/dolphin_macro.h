/****************************************************************************

Author : Gabriele 'matrix' Gristina <gabriele.gristina@gmail.com>
Date   : Sun Jan 10 13:59:37 CET 2021
Version: 0.1beta
License: GNU General Public License v3 or any later version (see LICENSE.txt)

*****************************************************************************
    Copyright (C) 2020-2021  <Gabriele Gristina>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
****************************************************************************/


// trust me...i'm a dolphin :P
// too many allocations, too many free to manage, I need dolphin macros :)
// they could be buggy, but if you know how to fix them, do it

#define MEMORY_FREE_ADD(a)      { \
    freeList[freeListIdx++] = (void *)(a); \
}

#define MEMORY_FREE_ALL         { \
    int t = freeListIdx; \
    while (t-- > 0) { \
        if (freeList[t] != NULL) { \
            free (freeList[t]); \
            freeList[t] = NULL; \
        }\
        if (freeList != NULL) { \
            free (freeList); \
            freeList = NULL; \
        } \
    } \
}

#define MEMORY_FREE_DEL(a)      { \
    for (int i = 0; i < freeListIdx; i++) { \
        if (freeList[i] && a == freeList[i]) { \
            free(freeList[i]); \
            freeList[i] = NULL; \
            break; \
        } \
    } \
}

#define MEMORY_FREE_LIST(a,i)   { \
    if (i > 0) { \
        int t=(int)i; \
        do { \
            if (a[t] != NULL) { \
                free(a[t]); \
                a[t]=NULL; \
            } \
        } while (--t >= 0); \
        MEMORY_FREE_DEL(a) \
    } \
}

#define MEMORY_FREE_LIST_Z(a,i) { \
    int t = (int)i; \
    do { \
        if (a[t] != NULL) { \
            free(a[t]); \
            a[t] = NULL; \
        } \
    } while (--t >= 0); \
    MEMORY_FREE_DEL(a) \
}

#define MEMORY_FREE_OPENCL(c,i) { \
    int t = (int)i; \
    do { \
        if (c.contexts[t]) \
            clReleaseContext (c.contexts[t]); \
        if (c.keystreams[t]) \
            clReleaseMemObject (c.keystreams[t]); \
        if (c.candidates[t]) \
            clReleaseMemObject (c.candidates[t]); \
        if (c.matches[t]) \
            clReleaseMemObject (c.matches[t]); \
        if (c.matches_found[t]) \
            clReleaseMemObject (c.matches_found[t]); \
        if (c.commands[t]) \
            clReleaseCommandQueue (c.commands[t]); \
        if (c.kernels[t]) \
            clReleaseKernel (c.kernels[t]); \
        if (c.programs[t]) \
            clReleaseProgram (c.programs[t]); \
    } while (--t >= 0); \
 }
