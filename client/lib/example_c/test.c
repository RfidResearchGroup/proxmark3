#include "pm3.h"

int main(int argc, char *argv[]) {
    pm3_context *ctx;
    ctx = pm3_init();
    pm3_device *p;
    p = pm3_open(ctx, "/dev/ttyACM0");
    pm3_console(p, "hw status");
    pm3_close(p);
    pm3_exit(ctx);
}
