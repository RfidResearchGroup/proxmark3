#ifndef LIBPM3_H
#define LIBPM3_H

#ifdef SWIG
%module pm3
%{
/* Include the header in the wrapper code */
#include "pm3.h"
%}

/* Strip "pm3_" from API functions for SWIG */
%rename("%(strip:[pm3_])s") "";
%feature("immutable","1") pm3_current_dev;

/* Parse the header file to generate wrappers */
#endif

typedef struct pm3_device pm3_device;
pm3_device* pm3_open(char *port);
int pm3_console(pm3_device* dev, char *cmd);
void pm3_close(pm3_device* dev);
pm3_device* pm3_get_current_dev(void);
#endif
