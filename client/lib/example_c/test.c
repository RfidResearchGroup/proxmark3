#include "pm3.h"

int main(int argc, char *argv[]) {
    pm3_device *p;
    p = pm3_open("/dev/ttyACM0");
    pm3_console(p, "hw status");
    pm3_close(p);
}
