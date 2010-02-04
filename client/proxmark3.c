#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "proxusb.h"
#include "proxmark3.h"
#include "proxgui.h"
#include "cmdmain.h"

struct usb_receiver_arg
{
  int run;
};

struct main_loop_arg
{
  int usb_present;
};

static void *usb_receiver(void *targ)
{
  struct usb_receiver_arg *arg = (struct usb_receiver_arg*)targ;
  UsbCommand cmdbuf;

  while (arg->run) {
    if (ReceiveCommandPoll(&cmdbuf)) {
      for (int i = 0; i < strlen(PROXPROMPT); i++)
        putchar(0x08);
      UsbCommandReceived(&cmdbuf);
      printf(PROXPROMPT);
      fflush(NULL);
    }
  }

  pthread_exit(NULL);
}

static void *main_loop(void *targ)
{
  struct main_loop_arg *arg = (struct main_loop_arg*)targ;
  struct usb_receiver_arg rarg;
  char *cmd = NULL;
  pthread_t reader_thread;

  if (arg->usb_present == 1) {
    rarg.run=1;
    pthread_create(&reader_thread, NULL, &usb_receiver, &rarg);
  }

  while(1) {
    cmd = readline(PROXPROMPT);
    if (cmd) {
      if (cmd[0] != 0x00) {
        CommandReceived(cmd);
        add_history(cmd);
      }
      free(cmd);
    } else {
      printf("\n");
      break;
    }
  }

  if (arg->usb_present == 1) {
    rarg.run = 0;
    pthread_join(reader_thread, NULL);
  }

  ExitGraphics();
  pthread_exit(NULL);
}

int main(int argc, char **argv)
{
  struct main_loop_arg marg;
  pthread_t main_loop_t;
  usb_init();

  if (!OpenProxmark(1)) {
    fprintf(stderr,"PROXMARK3: NOT FOUND!\n");
    marg.usb_present = 0;
    offline = 1;
  } else {
    marg.usb_present = 1;
    offline = 0;
  }

  pthread_create(&main_loop_t, NULL, &main_loop, &marg);
  InitGraphics(argc, argv);

  MainGraphics();

  pthread_join(main_loop_t, NULL);

  if (marg.usb_present == 1) {
    CloseProxmark();
  }
  return 0;
}
