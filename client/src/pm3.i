%module pm3
%{
/* Include the header in the wrapper code */
#include "pm3.h"
#include "comms.h"
%}

/* Strip "pm3_" from API functions for SWIG */
%rename("%(strip:[pm3_])s") "";
%feature("immutable","1") pm3_current_dev;

#ifdef PYWRAP
    #include <Python.h>
    %typemap(default) bool capture {
        $1 = Py_True;
    }
    %typemap(default) bool quiet {
        $1 = Py_True;
    }
#endif
typedef struct {
    %extend {
        pm3() {
//            printf("SWIG pm3 constructor, get current pm3\n");
            pm3_device_t * p = pm3_get_current_dev();
            p->script_embedded = 1;
            return p;
        }
        pm3(char *port) {
//            printf("SWIG pm3 constructor with port, open pm3\n");
            pm3_device_t * p = pm3_open(port);
            p->script_embedded = 0;
            return p;
        }
        ~pm3() {
            if ($self->script_embedded) {
//                printf("SWIG pm3 destructor, nothing to do\n");
            } else {
//                printf("SWIG pm3 destructor, close pm3\n");
                pm3_close($self);
            }
        }
        int console(char *cmd, bool capture = true, bool quiet = true);
        char const * const name;
        char const * const grabbed_output;
    }
} pm3;
//%nodefaultctor device;
//%nodefaultdtor device;
/* Parse the header file to generate wrappers */
