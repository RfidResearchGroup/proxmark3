#ifndef LIBPM3_H
#define LIBPM3_H

typedef struct pm3_device pm3_device;

pm3_device* pm3_open(char *port);
int pm3_device_console(pm3_device* dev, char *cmd);
const char * pm3_device_name_get(pm3_device* dev);
void pm3_device_close(pm3_device* dev);
pm3_device* pm3_device_get_current_dev(void);
#endif // LIBPM3_H
