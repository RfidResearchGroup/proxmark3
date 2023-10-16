#ifndef _RINGBUFFER_H_
#define _RINGBUFFER_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t* data;
    int capacity;
    int size;
    int front;
    int rear;
} RingBuffer;

RingBuffer* RingBuf_create(int capacity);
bool RingBuf_isFull(RingBuffer* buffer);
bool RingBuf_isEmpty(RingBuffer* buffer);
bool RingBuf_enqueue(RingBuffer* buffer, uint8_t value);
bool RingBuf_dequeue(RingBuffer* buffer, uint8_t* value);
int RingBuf_enqueueBatch(RingBuffer* buffer, const uint8_t* values, int count);
int RingBuf_dequeueBatch(RingBuffer* buffer, uint8_t* values, int count);
int RingBuf_getUsedSize(RingBuffer* buffer);
int RingBuf_getAvailableSize(RingBuffer* buffer);
void RingBuf_destroy(RingBuffer* buffer);

// for direct write
int RingBuf_getContinousAvailableSize(RingBuffer* buffer);
void RingBuf_postEnqueueBatch(RingBuffer* buffer, int count);
uint8_t* RingBuf_getRearPtr(RingBuffer* buffer);

#endif
