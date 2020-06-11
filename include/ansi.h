#ifndef __ANSI_H
#define __ANSI_H

#define AEND  "\x1b[0m"

#define _BLUE_(s) "\x1b[34m" s AEND
#define _RED_(s) "\x1b[31m" s AEND
#define _GREEN_(s) "\x1b[32m" s AEND
#define _YELLOW_(s) "\x1b[33m" s AEND
#define _MAGENTA_(s) "\x1b[35m" s AEND
#define _CYAN_(s) "\x1b[36m" s AEND
#define _WHITE_(s) "\x1b[37m" s AEND

// https://wiki.hackzine.org/development/misc/readline-color-prompt.html
// Applications may indicate that the prompt contains
// characters that take up no physical screen space when displayed by
// bracketing a sequence of such characters with the special markers
// RL_PROMPT_START_IGNORE = '\001' and RL_PROMPT_END_IGNORE = '\002'
#define RL_ESC(a) "\001" a "\002"

#define _RL_RED_(s) RL_ESC("\x1b[31m") s RL_ESC(AEND)
#define _RL_GREEN_(s) RL_ESC("\x1b[32m") s RL_ESC(AEND)
#define _RL_BOLD_RED_(s) RL_ESC("\x1b[1;31m") s RL_ESC(AEND)
#define _RL_BOLD_GREEN_(s) RL_ESC("\x1b[1;32m") s RL_ESC(AEND)

#endif
