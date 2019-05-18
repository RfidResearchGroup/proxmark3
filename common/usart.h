#ifndef __USART_H
#define __USART_H

#include <stddef.h>
#include "proxmark3.h"

//#define USART_BAUD_RATE 9600
#define USART_BAUD_RATE 115200
//#define USART_BAUD_RATE 230400
//#define USART_BAUD_RATE 460800
//#define USART_BAUD_RATE 921600
//#define USART_BAUD_RATE 1382400

extern uint32_t usart_baudrate;
#define USART_PARITY 'N'
extern uint8_t usart_parity;

void usart_init(uint32_t baudrate, uint8_t parity);
int usart_writebuffer_sync(uint8_t *data, size_t len);
uint32_t usart_read_ng(uint8_t *data, size_t len);
uint16_t usart_rxdata_available(void);
#define USART_BUFFLEN 512
#define USART_FIFOLEN (2*USART_BUFFLEN)

#endif
