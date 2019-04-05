//-----------------------------------------------------------------------------
// Copyright (C) 2017 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// platform-independant sleep macros
//-----------------------------------------------------------------------------

#ifndef SCANDIR_H__
#define SCANDIR_H__

#include <dirent.h>
#include <stdlib.h>

#ifdef _WIN32
int scandir(const char *dir, struct dirent ***namelist, int (*select)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **));
int alphasort(const struct dirent **a, const struct dirent **b);
#endif // _WIN32

#endif // SCANDIR_H__
