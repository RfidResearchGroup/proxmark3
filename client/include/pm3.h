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

typedef struct pm3_context pm3_context;
pm3_context *pm3_init(void);
void pm3_exit(pm3_context *ctx);
pm3_context *pm3_get_current_context(void);
typedef struct pm3_device pm3_device;
pm3_device *pm3_open(pm3_context *ctx, char *port);
pm3_device *pm3_get_dev(pm3_context *ctx, int n);
int pm3_console(pm3_device *dev, char *cmd);
void pm3_close(pm3_device *dev);
#endif
