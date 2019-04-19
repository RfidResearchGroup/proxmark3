#ifndef __USART_H
#define __USART_H

#include <stddef.h>
#include "proxmark3.h"

#define AT91_BAUD_RATE 115200

void usart_init(void);
void usart_close(void);

int16_t usart_readbuffer(uint8_t *data);
int16_t usart_writebuffer(uint8_t *data, size_t len);
bool usart_dataavailable(void);
int16_t usart_readcommand(uint8_t *data);
void usart_readcheck(uint8_t *data, size_t len);
uint32_t usart_read_ng(uint8_t *data, size_t len);

bool usart_commandavailable(void);
#endif
