%module pm3
%{
/* Include the header in the wrapper code */
#include "pm3.h"
#include "comms.h"
%}

/* Strip "pm3_" from API functions for SWIG */
%rename("%(strip:[pm3_])s") "";
%feature("immutable","1") pm3_current_dev;
typedef struct {
    %extend {
        pm3_device() {
            printf("SWIG pm3_device constructor, get current pm3\n");
            pm3_device * p = pm3_device_get_current_dev();
            p->script_embedded = 1;
            return p;
        }
        pm3_device(char *port) {
            printf("SWIG pm3_device constructor with port, open pm3\n");
            pm3_device * p = pm3_open(port);
            p->script_embedded = 0;
            return p;
        }
        ~pm3_device() {
            if ($self->script_embedded) {
                printf("SWIG pm3_device destructor, nothing to do\n");
            } else {
                printf("SWIG pm3_device destructor, close pm3\n");
                pm3_device_close($self);
            }
        }
        int console(char *cmd);
        char const * const name;
    }
} pm3_device;
//%nodefaultctor device;
//%nodefaultdtor device;
/* Parse the header file to generate wrappers */