#ifndef __ANSI_H
#define __ANSI_H

#define AEND  "\x1b[0m"

#define _BLUE_(s) "\x1b[34m" s AEND
#define _RED_(s) "\x1b[31m" s AEND
#define _BOLD_RED_(s) "\x1b[1;31m" s AEND
#define _GREEN_(s) "\x1b[32m" s AEND
#define _BOLD_GREEN_(s) "\x1b[1;32m" s AEND
#define _YELLOW_(s) "\x1b[33m" s AEND
#define _MAGENTA_(s) "\x1b[35m" s AEND
#define _CYAN_(s) "\x1b[36m" s AEND
#define _WHITE_(s) "\x1b[37m" s AEND

#endif
