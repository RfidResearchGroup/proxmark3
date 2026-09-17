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

#include "scandir.h"

#ifdef _WIN32


#ifdef __cplusplus
extern "C" {
#endif
int scandir(const char *dir,
            struct dirent ***namelist,
            int (*select)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **)) {
    DIR *dirp;
    struct dirent *ent, *etmp, **nl = NULL, **ntmp;
    int count = 0;
    int allocated = 0;
    int err_no = 0;

    if (!(dirp = opendir(dir)))
        return -1;

    while ((ent = readdir(dirp))) {
        if (!select || select(ent)) {

            err_no = 0;

            if (count == allocated) {
                if (allocated == 0)
                    allocated = 10;
                else
                    allocated *= 2;

                ntmp = (struct dirent **) realloc(nl, allocated * sizeof * nl);
                if (!ntmp) {
                    err_no = 1;
                    break;
                }
                nl = ntmp;
            }

            etmp = (struct dirent *) calloc(sizeof * ent, sizeof(char));
            if (!etmp) {
                err_no = 1;
                break;
            }
            *etmp = *ent;
            nl[count++] = etmp;
        }
    }

    if (err_no != 0) {
        closedir(dirp);
        if (nl) {
            while (count > 0) {
                free(nl[--count]);
            }
            free(nl);
        }
        return -1;
    }

    closedir(dirp);

    qsort(nl, count, sizeof * nl, (int (*)(const void *, const void *)) compar);
    if (namelist)
        *namelist = nl;
    return count;
}
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
int alphasort(const struct dirent **a, const struct dirent **b) {
    return strcoll((*a)->d_name, (*b)->d_name);
}
#ifdef __cplusplus
}
#endif

#endif  // win32
