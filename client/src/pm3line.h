// Copyright (C) 2020 Doegox
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------

#ifndef PM3LINE_H__
#define PM3LINE_H__

void pm3line_init(void);
char *pm3line_read(const char* s);
void pm3line_free(void *ref);
void pm3line_update_prompt(const char *prompt);
int pm3line_load_history(const char *path);
void pm3line_add_history(const char *line);
int pm3line_save_history(const char *path);
void pm3line_check(int (check)(void));

#endif // PM3LINE_H__
