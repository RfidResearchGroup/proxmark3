#ifndef __USART_H
#define __USART_H

#include <stddef.h>
#include "proxmark3.h"

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
extern void Dbprintf(const char *fmt, ...);

void usart_init(void);
void usart_close(void);

uint32_t usart_rx_ready();
uint32_t usart_tx_ready();

uint8_t usart_read(uint32_t timeout);
uint8_t usart_readbuffer(uint8_t *data, size_t len);

void usart_write( uint8_t data, uint32_t timeout);
uint8_t usart_writebuffer(uint8_t *data, size_t len, uint32_t timeout);
#endif
