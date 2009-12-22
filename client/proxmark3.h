#define PROXPROMPT "proxmark3> "

#define FLASH_ADDR_OS		0x10000
#define FLASH_ADDR_FPGA		0x2000

extern usb_dev_handle *devh;
extern unsigned char return_on_error;
extern unsigned char error_occured;

int ReceiveCommandP(UsbCommand *c);
usb_dev_handle* OpenProxmark(int);
void CloseProxmark(void);

void setlogfilename(char *fn);
