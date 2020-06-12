#ifndef __USART_H
#define __USART_H

#include "common.h"
#include "usart_defs.h"

#define USART_BUFFLEN 512
#define USART_FIFOLEN (2*USART_BUFFLEN)

// Higher baudrates are pointless, only increasing overflow risk

extern uint32_t g_usart_baudrate;
extern uint8_t g_usart_parity;

void usart_init(uint32_t baudrate, uint8_t parity);
int usart_writebuffer_sync(uint8_t *data, size_t len);
uint32_t usart_read_ng(uint8_t *data, size_t len);
uint16_t usart_rxdata_available(void);

#endif
