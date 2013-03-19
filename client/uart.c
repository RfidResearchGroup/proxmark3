/*
 * Proxmark3 generic uart / rs232/ serial port library
 *
 * Copyright (c) 2012, Roel Verdult
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file uart.c
 * @brief
 *
 * Partly based on uart-code written by Teunis van Beelen, available:
 * http://www.teuniz.net/RS-232/index.html
 *
 */

#include "uart.h"
#include "messages.h"

// Test if we are dealing with unix operating systems
#ifndef _WIN32

#include <termios.h>
typedef struct termios term_info;
typedef struct {
  int fd;           // Serial port file descriptor
  term_info tiOld;  // Terminal info before using the port
  term_info tiNew;  // Terminal info during the transaction
} serial_port_unix;

// Set time-out on 30 miliseconds
const struct timeval timeout = { 
  .tv_sec  =     0, // 0 second
  .tv_usec = 30000  // 30000 micro seconds
};

// Work-around to claim uart interface using the c_iflag (software input processing) from the termios struct
#define CCLAIMED 0x80000000

serial_port uart_open(const char* pcPortName)
{
  serial_port_unix* sp = malloc(sizeof(serial_port_unix));

  if (sp == 0) return INVALID_SERIAL_PORT;

  sp->fd = open(pcPortName, O_RDWR | O_NOCTTY | O_NDELAY | O_NONBLOCK);
  if(sp->fd == -1)
  {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }

  if(tcgetattr(sp->fd,&sp->tiOld) == -1)
  {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }

  // Make sure the port is not claimed already
  if (sp->tiOld.c_iflag & CCLAIMED)
  {
    uart_close(sp);
    return CLAIMED_SERIAL_PORT;
  }

  // Copy the old terminal info struct
  sp->tiNew = sp->tiOld;

  sp->tiNew.c_cflag = CS8 | CLOCAL | CREAD;
  sp->tiNew.c_iflag = CCLAIMED | IGNPAR;
  sp->tiNew.c_oflag = 0;
  sp->tiNew.c_lflag = 0;
  
  // Set serial port equivalent to raw mode
//  sp->tiNew.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
//  sp->tiNew.c_oflag &= ~OPOST;
//  sp->tiNew.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
//  sp->tiNew.c_cflag &= ~(CSIZE | PARENB);
//  sp->tiNew.c_iflag |= CCLAIMED | IGNPAR;
//  sp->tiNew.c_cflag |= CS8 | CLOCAL | CREAD;

  sp->tiNew.c_cc[VMIN] = 0;      // block until n bytes are received
  sp->tiNew.c_cc[VTIME] = 0;     // block until a timer expires (n * 100 mSec.)

  if(tcsetattr(sp->fd,TCSANOW,&sp->tiNew) == -1)
  {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }

  tcflush(sp->fd, TCIOFLUSH);
  return sp;
}

void uart_set_speed(serial_port sp, const uint32_t uiPortSpeed)
{
  DBG("Serial port speed requested to be set to %d bauds.", uiPortSpeed);
  // Set port speed (Input and Output)
  speed_t stPortSpeed = B9600;
  switch(uiPortSpeed) {
    case 9600: stPortSpeed = B9600;
    break;
    case 19200: stPortSpeed = B19200;
    break;
    case 38400: stPortSpeed = B38400;
    break;
    case 57600: stPortSpeed = B57600;
    break;
    case 115200: stPortSpeed = B115200;
    break;
    case 230400: stPortSpeed = B230400;
    break;
#ifdef B460800
    case 460800: stPortSpeed = B460800;
    break;
#endif
    default:
#ifdef B460800
      ERR("Unable to set serial port speed to %d bauds. Speed value must be one of these constants: 9600 (default), 19200, 38400, 57600, 115200, 230400 or 460800.", uiPortSpeed);
#else
      ERR("Unable to set serial port speed to %d bauds. Speed value must be one of these constants: 9600 (default), 19200, 38400, 57600, 115200 or 230400.", uiPortSpeed);
#endif
  };
  const serial_port_unix* spu = (serial_port_unix*)sp;
  cfsetispeed((struct termios*)&spu->tiNew, stPortSpeed);
  cfsetospeed((struct termios*)&spu->tiNew, stPortSpeed);
  if( tcsetattr(spu->fd, TCSADRAIN, &spu->tiNew)  == -1)
  {
    ERR("Unable to apply new speed settings.");
  }
}

uint32_t uart_get_speed(const serial_port sp)
{
  uint32_t uiPortSpeed = 0;
  const serial_port_unix* spu = (serial_port_unix*)sp;
  switch (cfgetispeed(&spu->tiNew))
  {
    case B9600: uiPortSpeed = 9600;
    break;
    case B19200: uiPortSpeed = 19200;
    break;
    case B38400: uiPortSpeed = 38400;
    break;
    case B57600: uiPortSpeed = 57600;
    break;
    case B115200: uiPortSpeed = 115200;
    break;
    case B230400: uiPortSpeed = 230400;
    break;
#ifdef B460800
    case B460800: uiPortSpeed = 460800;
    break;
#endif
  }

  return uiPortSpeed;
}

void uart_close(const serial_port sp)
{
  tcflush(((serial_port_unix*)sp)->fd,TCIOFLUSH);
  tcsetattr(((serial_port_unix*)sp)->fd,TCSANOW,&((serial_port_unix*)sp)->tiOld);
  close(((serial_port_unix*)sp)->fd);
  free(sp);
}

bool uart_cts(const serial_port sp)
{
  char status;
  if (ioctl(((serial_port_unix*)sp)->fd,TIOCMGET,&status) < 0) return false;
  return (status & TIOCM_CTS);
}

bool uart_receive(const serial_port sp, byte_t* pbtRx, size_t* pszRxLen)
{
  int res;
  int byteCount;
  fd_set rfds;
  struct timeval tv;

  // Reset the output count  
  *pszRxLen = 0;

  do {
    // Reset file descriptor
    FD_ZERO(&rfds);
    FD_SET(((serial_port_unix*)sp)->fd,&rfds);
    tv = timeout;
    res = select(((serial_port_unix*)sp)->fd+1, &rfds, NULL, NULL, &tv);

    // Read error
    if (res < 0) {
      DBG("RX error.");
      return false;
    }

    // Read time-out
    if (res == 0) {
      if (*pszRxLen == 0) {
        // Error, we received no data
        DBG("RX time-out, buffer empty.");
        return false;
      } else {
        // We received some data, but nothing more is available
        return true;
      }
    }

    // Retrieve the count of the incoming bytes
    res = ioctl(((serial_port_unix*)sp)->fd, FIONREAD, &byteCount);
    if (res < 0) return false;

    // There is something available, read the data
    res = read(((serial_port_unix*)sp)->fd,pbtRx+(*pszRxLen),byteCount);

    // Stop if the OS has some troubles reading the data
    if (res <= 0) return false;

    *pszRxLen += res;

  } while (byteCount);

  return true;
}

bool uart_send(const serial_port sp, const byte_t* pbtTx, const size_t szTxLen)
{
  int32_t res;
  size_t szPos = 0;
  fd_set rfds;
  struct timeval tv;

  while (szPos < szTxLen)
  {
    // Reset file descriptor
    FD_ZERO(&rfds);
    FD_SET(((serial_port_unix*)sp)->fd,&rfds);
    tv = timeout;
    res = select(((serial_port_unix*)sp)->fd+1, NULL, &rfds, NULL, &tv);

    // Write error
    if (res < 0) {
      DBG("TX error.");
      return false;
    }

    // Write time-out
    if (res == 0) {
      DBG("TX time-out.");
      return false;
    }

    // Send away the bytes
    res = write(((serial_port_unix*)sp)->fd,pbtTx+szPos,szTxLen-szPos);
    
    // Stop if the OS has some troubles sending the data
    if (res <= 0) return false;

    szPos += res;
  }
  return true;
}

#else
// The windows serial port implementation

typedef struct { 
  HANDLE hPort;     // Serial port handle
  DCB dcb;          // Device control settings
  COMMTIMEOUTS ct;  // Serial port time-out configuration
} serial_port_windows;

void upcase(char *p) {
	while(*p != '\0') {
		if(*p >= 97 && *p <= 122) {
			*p -= 32;
    }
		++p;
	}
}

serial_port uart_open(const char* pcPortName)
{
  char acPortName[255];
  serial_port_windows* sp = malloc(sizeof(serial_port_windows));

  // Copy the input "com?" to "\\.\COM?" format
  sprintf(acPortName,"\\\\.\\%s",pcPortName);
  upcase(acPortName);

  // Try to open the serial port
  sp->hPort = CreateFileA(acPortName,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
  if (sp->hPort == INVALID_HANDLE_VALUE)
  {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }

  // Prepare the device control
  memset(&sp->dcb, 0, sizeof(DCB));
  sp->dcb.DCBlength = sizeof(DCB);
  if(!BuildCommDCBA("baud=9600 data=8 parity=N stop=1",&sp->dcb))
  {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }

  // Update the active serial port
  if(!SetCommState(sp->hPort,&sp->dcb))
  {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }

  sp->ct.ReadIntervalTimeout         = 0;
  sp->ct.ReadTotalTimeoutMultiplier  = 0;
  sp->ct.ReadTotalTimeoutConstant    = 30;
  sp->ct.WriteTotalTimeoutMultiplier = 0;
  sp->ct.WriteTotalTimeoutConstant   = 30;

  if(!SetCommTimeouts(sp->hPort,&sp->ct))
  {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }

  PurgeComm(sp->hPort, PURGE_RXABORT | PURGE_RXCLEAR);

  return sp;
}

void uart_close(const serial_port sp)
{
  CloseHandle(((serial_port_windows*)sp)->hPort);
  free(sp);
}

void uart_set_speed(serial_port sp, const uint32_t uiPortSpeed)
{
  serial_port_windows* spw;

  DBG("Serial port speed requested to be set to %d bauds.", uiPortSpeed);
  // Set port speed (Input and Output)
  switch(uiPortSpeed) {
    case 9600:
    case 19200:
    case 38400:
    case 57600:
    case 115200:
    case 230400:
    case 460800:
    break;
    default:
      ERR("Unable to set serial port speed to %d bauds. Speed value must be one of these constants: 9600 (default), 19200, 38400, 57600, 115200, 230400 or 460800.", uiPortSpeed);
  };

  spw = (serial_port_windows*)sp;
  spw->dcb.BaudRate = uiPortSpeed;
  if (!SetCommState(spw->hPort, &spw->dcb))
  {
    ERR("Unable to apply new speed settings.");
  }
}

uint32_t uart_get_speed(const serial_port sp)
{
  const serial_port_windows* spw = (serial_port_windows*)sp;
  if (!GetCommState(spw->hPort, (serial_port)&spw->dcb))
    return spw->dcb.BaudRate;
  
  return 0;
}

bool uart_receive(const serial_port sp, byte_t* pbtRx, size_t* pszRxLen)
{
  ReadFile(((serial_port_windows*)sp)->hPort,pbtRx,*pszRxLen,(LPDWORD)pszRxLen,NULL);
  return (*pszRxLen != 0);
}

bool uart_send(const serial_port sp, const byte_t* pbtTx, const size_t szTxLen)
{
  DWORD dwTxLen = 0;
  return WriteFile(((serial_port_windows*)sp)->hPort,pbtTx,szTxLen,&dwTxLen,NULL);
  return (dwTxLen != 0);
}

#endif
