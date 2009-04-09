#define PROXPROMPT "proxmark3> "

extern usb_dev_handle *devh;
extern unsigned char return_on_error;
extern unsigned char error_occured;

int ReceiveCommandP(UsbCommand *c);
usb_dev_handle* OpenProxmark(int);
void CloseProxmark(void);

void setlogfilename(char *fn);
