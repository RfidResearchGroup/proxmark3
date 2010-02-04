#include "ui.h"
#include "proxusb.h"
#include "cmdmain.h"

#define HANDLE_ERROR if (error_occured) { \
  error_occured = 0;\
  break;\
}

int main()
{
  usb_init();
  SetLogFilename("snooper.log");

  return_on_error = 1;

  while(1) {
    while (!OpenProxmark(0)) { sleep(1); }
    while (1) {
      UsbCommand cmdbuf;
      CommandReceived("hi14asnoop");
      HANDLE_ERROR;
      ReceiveCommand(&cmdbuf);
      HANDLE_ERROR;
      for (int i = 0; i < 5; ++i) {
        ReceiveCommandPoll(&cmdbuf);
      }
      HANDLE_ERROR;
      CommandReceived("hi14alist");
      HANDLE_ERROR;
    }
  }

  CloseProxmark();
  return 0;
}
