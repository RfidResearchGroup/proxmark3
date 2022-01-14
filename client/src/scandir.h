//-----------------------------------------------------------------------------
// Borrowed initially from
// https://github.com/msysgit/msys/blob/master/winsup/cygwin/scandir.cc
// Copyright (C) 1998-2001 Red Hat, Inc. Corinna Vinschen <corinna.vinschen@cityweb.de>
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

#ifndef SCANDIR_H__
#define SCANDIR_H__

#include <dirent.h>
#include <stdlib.h>

#ifdef _WIN32
int scandir(const char *dir, struct dirent ***namelist, int (*select)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **));
int alphasort(const struct dirent **a, const struct dirent **b);
#endif // _WIN32

#endif // SCANDIR_H__
