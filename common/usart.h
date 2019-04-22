#ifndef __USART_H
#define __USART_H

#include <stddef.h>
#include "proxmark3.h"

//#define USART_BAUD_RATE 9600
#define USART_BAUD_RATE 115200
//#define USART_BAUD_RATE 460800


void usart_init(void);
void usart_close(void);

int32_t usart_writebuffer_sync(uint8_t *data, size_t len);
uint32_t usart_read_ng(uint8_t *data, size_t len);
uint16_t usart_rxdata_available(void);
#define USART_BUFFLEN 512
#define USART_FIFOLEN (2*USART_BUFFLEN)

#endif
