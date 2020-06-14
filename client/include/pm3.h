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
struct pm3_device { };
%extend pm3_device {
    pm3_device() {
        printf("SWIG pm3_device constructor, get current pm3\n");
        _embedded = 1;
        return pm3_get_current_dev();
    }
    pm3_device(char *port) {
        printf("SWIG pm3_device constructor with port, open pm3\n");
        _embedded = 0;
        return pm3_open(port);
    }
    ~pm3_device() {
        if (_embedded) {
            printf("SWIG pm3_device destructor, nothing to do\n");
        } else {
            printf("SWIG pm3_device destructor, close pm3\n");
            pm3_close($self);
        }
    }
    int console(char *cmd) {
        return pm3_console($self, cmd);
    }
    char *get_name() {
        return pm3_get_name($self);
    }
}
//%nodefaultctor pm3_device;
//%nodefaultdtor pm3_device;

/* Parse the header file to generate wrappers */
#endif // SWIG

// TODO better than this global?
int _embedded;

typedef struct pm3_device pm3_device;
pm3_device* pm3_open(char *port);
int pm3_console(pm3_device* dev, char *cmd);
char *pm3_get_name(pm3_device* dev);
void pm3_close(pm3_device* dev);
pm3_device* pm3_get_current_dev(void);
#endif // LIBPM3_H
