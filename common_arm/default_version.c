#include "proxmark3_arm.h"
/* This is the default version.c file that Makefile.common falls back to if neither sh nor perl are available */
const struct version_information __attribute__((section(".version_information"))) version_information = {
    VERSION_INFORMATION_MAGIC,
    1, /* version 1 */
    0, /* version information not present */
    2, /* cleanliness couldn't be determined */
    /* Remaining fields: zero */
};
