//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Snooper binary
//-----------------------------------------------------------------------------

#include "sleep.h"
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
      CommandReceived("hf 14a snoop");
      HANDLE_ERROR;
      ReceiveCommand(&cmdbuf);
      HANDLE_ERROR;
      for (int i = 0; i < 5; ++i) {
        ReceiveCommandPoll(&cmdbuf);
      }
      HANDLE_ERROR;
      CommandReceived("hf 14a list");
      HANDLE_ERROR;
    }
  }

  CloseProxmark();
  return 0;
}
