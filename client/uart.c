/*
 * Generic uart / rs232/ serial port library
 *
 * Copyright (c) 2013, Roel Verdult
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
 */

#include "uart.h"

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

serial_port uart_open(const char* pcPortName)
{
  serial_port_unix* sp = malloc(sizeof(serial_port_unix));
  if (sp == 0) return INVALID_SERIAL_PORT;
  
  sp->fd = open(pcPortName, O_RDWR | O_NOCTTY | O_NDELAY | O_NONBLOCK);
  if(sp->fd == -1) {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }

  // Finally figured out a way to claim a serial port interface under unix
  // We just try to set a (advisory) lock on the file descriptor
  struct flock fl;
  fl.l_type   = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start  = 0;
  fl.l_len    = 0;
  fl.l_pid    = getpid();
  
  // Does the system allows us to place a lock on this file descriptor
  if (fcntl(sp->fd, F_SETLK, &fl) == -1) {
    // A conflicting lock is held by another process
    free(sp);
    return CLAIMED_SERIAL_PORT;
  }

  // Try to retrieve the old (current) terminal info struct
  if(tcgetattr(sp->fd,&sp->tiOld) == -1) {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }
  
  // Duplicate the (old) terminal info struct
  sp->tiNew = sp->tiOld;
  
  // Configure the serial port
  sp->tiNew.c_cflag = CS8 | CLOCAL | CREAD;
  sp->tiNew.c_iflag = IGNPAR;
  sp->tiNew.c_oflag = 0;
  sp->tiNew.c_lflag = 0;
    
  // Block until n bytes are received
  sp->tiNew.c_cc[VMIN] = 0;
  // Block until a timer expires (n * 100 mSec.)
  sp->tiNew.c_cc[VTIME] = 0;
  
  // Try to set the new terminal info struct
  if(tcsetattr(sp->fd,TCSANOW,&sp->tiNew) == -1) {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }
  
  // Flush all lingering data that may exist
  tcflush(sp->fd, TCIOFLUSH);

  return sp;
}

void uart_close(const serial_port sp) {
  serial_port_unix* spu = (serial_port_unix*)sp;
  tcflush(spu->fd,TCIOFLUSH);
  tcsetattr(spu->fd,TCSANOW,&(spu->tiOld));
  struct flock fl;
  fl.l_type   = F_UNLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start  = 0;
  fl.l_len    = 0;
  fl.l_pid    = getpid();

  // Does the system allows us to place a lock on this file descriptor
  int err = fcntl(spu->fd, F_SETLK, &fl);
  if ( err == -1) {
     //perror("fcntl");
  }  
  close(spu->fd);
  free(sp);
}

bool uart_set_speed(serial_port sp, const uint32_t uiPortSpeed) {
  const serial_port_unix* spu = (serial_port_unix*)sp;
  speed_t stPortSpeed;
  switch (uiPortSpeed) {
    case 0: stPortSpeed = B0; break;
    case 50: stPortSpeed = B50; break;
    case 75: stPortSpeed = B75; break;
    case 110: stPortSpeed = B110; break;
    case 134: stPortSpeed = B134; break;
    case 150: stPortSpeed = B150; break;
    case 300: stPortSpeed = B300; break;
    case 600: stPortSpeed = B600; break;
    case 1200: stPortSpeed = B1200; break;
    case 1800: stPortSpeed = B1800; break;
    case 2400: stPortSpeed = B2400; break;
    case 4800: stPortSpeed = B4800; break;
    case 9600: stPortSpeed = B9600; break;
    case 19200: stPortSpeed = B19200; break;
    case 38400: stPortSpeed = B38400; break;
#  ifdef B57600
    case 57600: stPortSpeed = B57600; break;
#  endif
#  ifdef B115200
    case 115200: stPortSpeed = B115200; break;
#  endif
#  ifdef B230400
    case 230400: stPortSpeed = B230400; break;
#  endif
#  ifdef B460800
    case 460800: stPortSpeed = B460800; break;
#  endif
#  ifdef B921600
    case 921600: stPortSpeed = B921600; break;
#  endif
    default: return false;
  };
  struct termios ti;
  if (tcgetattr(spu->fd,&ti) == -1) return false;
  // Set port speed (Input and Output)
  cfsetispeed(&ti,stPortSpeed);
  cfsetospeed(&ti,stPortSpeed);
  return (tcsetattr(spu->fd,TCSANOW,&ti) != -1);
}

uint32_t uart_get_speed(const serial_port sp) {
  struct termios ti;
  uint32_t uiPortSpeed;
  const serial_port_unix* spu = (serial_port_unix*)sp;
  if (tcgetattr(spu->fd,&ti) == -1) return 0;
  // Set port speed (Input)
  speed_t stPortSpeed = cfgetispeed(&ti);
  switch (stPortSpeed) {
    case B0: uiPortSpeed = 0; break;
    case B50: uiPortSpeed = 50; break;
    case B75: uiPortSpeed = 75; break;
    case B110: uiPortSpeed = 110; break;
    case B134: uiPortSpeed = 134; break;
    case B150: uiPortSpeed = 150; break;
    case B300: uiPortSpeed = 300; break;
    case B600: uiPortSpeed = 600; break;
    case B1200: uiPortSpeed = 1200; break;
    case B1800: uiPortSpeed = 1800; break;
    case B2400: uiPortSpeed = 2400; break;
    case B4800: uiPortSpeed = 4800; break;
    case B9600: uiPortSpeed = 9600; break;
    case B19200: uiPortSpeed = 19200; break;
    case B38400: uiPortSpeed = 38400; break;
#  ifdef B57600
    case B57600: uiPortSpeed = 57600; break;
#  endif
#  ifdef B115200
    case B115200: uiPortSpeed = 115200; break;
#  endif
#  ifdef B230400
    case B230400: uiPortSpeed = 230400; break;
#  endif
#  ifdef B460800
    case B460800: uiPortSpeed = 460800; break;
#  endif
#  ifdef B921600
    case B921600: uiPortSpeed = 921600; break;
#  endif
    default: return 0;
  };
  return uiPortSpeed;
}

bool uart_set_parity(serial_port sp, serial_port_parity spp) {
  struct termios ti;
  const serial_port_unix* spu = (serial_port_unix*)sp;
  if (tcgetattr(spu->fd,&ti) == -1) return false;
  switch(spp) {
    case SP_INVALID: return false;
    case SP_NONE: ti.c_cflag &= ~(PARENB | PARODD); break;
    case SP_EVEN: ti.c_cflag |= PARENB; ti.c_cflag &= ~(PARODD); break;
    case SP_ODD: ti.c_cflag |= PARENB | PARODD; break;
  }
  return (tcsetattr(spu->fd,TCSANOW,&ti) != -1);
}

serial_port_parity uart_get_parity(const serial_port sp) {
  struct termios ti;
  const serial_port_unix* spu = (serial_port_unix*)sp;
  if (tcgetattr(spu->fd,&ti) == -1) return SP_INVALID;
  
  if (ti.c_cflag & PARENB) {
    if (ti.c_cflag & PARODD) {
      return SP_ODD;
    } else {
      return SP_EVEN;
    }
  } else {
    return SP_NONE;
  }
}

bool uart_cts(const serial_port sp) {
  char status;
  if (ioctl(((serial_port_unix*)sp)->fd,TIOCMGET,&status) < 0) return false;
  return (status & TIOCM_CTS);
}

bool uart_receive(const serial_port sp, byte_t* pbtRx, size_t* pszRxLen) {

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
      return false;
    }
 
    // Read time-out
    if (res == 0) {
      if (*pszRxLen == 0) {
        // Error, we received no data
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

    if(res==byteCount)
        return true;
    
  } while (byteCount);

  return true;
}

bool uart_send(const serial_port sp, const byte_t* pbtTx, const size_t szTxLen) {
  int32_t res;
  size_t szPos = 0;
  fd_set rfds;
  struct timeval tv;
  
  while (szPos < szTxLen) {
    // Reset file descriptor
    FD_ZERO(&rfds);
    FD_SET(((serial_port_unix*)sp)->fd,&rfds);
    tv = timeout;
    res = select(((serial_port_unix*)sp)->fd+1, NULL, &rfds, NULL, &tv);
    
    // Write error
    if (res < 0) {
      return false;
    }
    
    // Write time-out
    if (res == 0) {
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

serial_port uart_open(const char* pcPortName) {
  char acPortName[255];
  serial_port_windows* sp = malloc(sizeof(serial_port_windows));
  
  // Copy the input "com?" to "\\.\COM?" format
  sprintf(acPortName,"\\\\.\\%s",pcPortName);
  upcase(acPortName);
  
  // Try to open the serial port
  sp->hPort = CreateFileA(acPortName,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
  if (sp->hPort == INVALID_HANDLE_VALUE) {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }
  
  // Prepare the device control
  memset(&sp->dcb, 0, sizeof(DCB));
  sp->dcb.DCBlength = sizeof(DCB);
  if(!BuildCommDCBA("baud=115200 parity=N data=8 stop=1",&sp->dcb)) {
		uart_close(sp);
		return INVALID_SERIAL_PORT;
	}
  
  // Update the active serial port
  if(!SetCommState(sp->hPort,&sp->dcb)) {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }
  
  sp->ct.ReadIntervalTimeout         = 0;
  sp->ct.ReadTotalTimeoutMultiplier  = 0;
  sp->ct.ReadTotalTimeoutConstant    = 30;
  sp->ct.WriteTotalTimeoutMultiplier = 0;
  sp->ct.WriteTotalTimeoutConstant   = 30;
  
  if(!SetCommTimeouts(sp->hPort,&sp->ct)) {
    uart_close(sp);
    return INVALID_SERIAL_PORT;
  }
  
  PurgeComm(sp->hPort, PURGE_RXABORT | PURGE_RXCLEAR);
  
  return sp;
}

void uart_close(const serial_port sp) {
  CloseHandle(((serial_port_windows*)sp)->hPort);
  free(sp);
}

bool uart_set_speed(serial_port sp, const uint32_t uiPortSpeed) {
  serial_port_windows* spw;
  spw = (serial_port_windows*)sp;
  spw->dcb.BaudRate = uiPortSpeed;
  return SetCommState(spw->hPort, &spw->dcb);
}

uint32_t uart_get_speed(const serial_port sp) {
  const serial_port_windows* spw = (serial_port_windows*)sp;
  if (!GetCommState(spw->hPort, (serial_port)&spw->dcb)) {
    return spw->dcb.BaudRate;
  }
  return 0;
}

bool uart_receive(const serial_port sp, byte_t* pbtRx, size_t* pszRxLen) {
  ReadFile(((serial_port_windows*)sp)->hPort,pbtRx,*pszRxLen,(LPDWORD)pszRxLen,NULL);
  return (*pszRxLen != 0);
}

bool uart_send(const serial_port sp, const byte_t* pbtTx, const size_t szTxLen) {
  DWORD dwTxLen = 0;
  return WriteFile(((serial_port_windows*)sp)->hPort,pbtTx,szTxLen,&dwTxLen,NULL);
  return (dwTxLen != 0);
}

#endif
