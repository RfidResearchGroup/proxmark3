#ifndef LIBPM3_H
#define LIBPM3_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pm3_device pm3;

pm3 *pm3_open(char *port);

// not catching output
int pm3_console(pm3 *dev, char *cmd);
// catching output as it comes
int pm3_console_async(pm3 *dev, char *cmd, int (*callback)(char* s));
// catching output at the end
//int pm3_console_sync(pm3 *dev, char *cmd, char* outbuf, int outbufsize);

const char *pm3_name_get(pm3 *dev);
void pm3_close(pm3 *dev);
pm3 *pm3_get_current_dev(void);

#ifdef __cplusplus
}
#endif
#endif // LIBPM3_H
