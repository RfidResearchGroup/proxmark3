/* scandir.cc

   Copyright 1998, 1999, 2000, 2001 Red Hat, Inc.

   Written by Corinna Vinschen <corinna.vinschen@cityweb.de>

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

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
