#ifndef HT2CRACK5OPENCL_H
#define HT2CRACK5OPENCL_H

#define VERSION "1.0"

// enable generic debug messages
#define DEBUGME 0

//#define DEBUG_HITAG2 0 // you can set this (1) to enable debug messages in hitag2 cpu code

#ifdef __APPLE__

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
#define OFF_FORMAT_U llu
#define OFF_FORMAT_X llx
#endif // DEBUG_HITAG2

#else // ! Apple

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
#define OFF_FORMAT_U lu
#define OFF_FORMAT_X lx
#endif // DEBUG_HITAG2

#endif // __APPLE__

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
#define STR_STRING(x) #x
#define STR(x) STR_STRING(x)
#endif // DEBUG_HITAG2

// some defines
#define APPLE_GPU_BROKEN 0                          // if your Apple GPU is broken, try set to (1).
//#define MAX_OPENCL_DEVICES 16                       // max number of concurrent devices (tested up to 4x RTX 3090)
#define GLOBAL_WS_1 1024                            // default size of 2nd work-items dimension
#define GLOBAL_WS_2 1                               // default size of 3rd work-items dimension
#define PROFILE_DEFAULT 2                           // (0) is the best for Intel GPU's (NEO) and Apple GPU's (only Iris tested), (2) for all others. Some limitations are applyed later
#define TDEBUG 0                                    // (0) hide or (1) enable thread's debug messages
#define EXPERIMENTAL_RECOVERY 0                     // untested work-unit recovery logic, in case of failure. supported only with THREAD_SCHEDULER_TYPE as (0)
//#define CLEAN_EXIT 1                                // (1) seems to be fixed, but add a global cond_wait/cond_signal pair to make sure threads end before free memory maybe an idea
#define ENABLE_EMOJ 0                               // only for fun

#define WGS_MATCHES_FACTOR_MID 1.41421              // Pythagoras, the square of 2, not full but probably good trade-off
#define WGS_MATCHES_FACTOR_FULL 3.14159265359       // Pi, maybe is the correct one
#define WGS_MATCHES_FACTOR WGS_MATCHES_FACTOR_MID   // trying with Pythagoras, but if you got the following error, change to Pi: 'clEnqueueReadBuffer(matches) failed (-30)'

#endif // HT2CRACK5OPENCL_H
