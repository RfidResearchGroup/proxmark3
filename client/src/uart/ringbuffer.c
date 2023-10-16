#include "ringbuffer.h"
#include <stdlib.h>

RingBuffer* RingBuf_create(int capacity) {
    RingBuffer* buffer = (RingBuffer*)malloc(sizeof(RingBuffer));
    if (!buffer) {
        return NULL;
    }

    buffer->data = (uint8_t*)calloc(capacity, sizeof(uint8_t));
    if (!buffer->data) {
        free(buffer);
        return NULL;
    }

    buffer->capacity = capacity;
    buffer->size = 0;
    buffer->front = 0;
    buffer->rear = 0;

    return buffer;
}

inline bool RingBuf_isFull(RingBuffer* buffer) {
    return buffer->size == buffer->capacity;
}

inline bool RingBuf_isEmpty(RingBuffer* buffer) {
    return buffer->size == 0;
}

bool RingBuf_enqueue(RingBuffer* buffer, uint8_t value) {
    if (RingBuf_isFull(buffer)) {
        return false;
    }

    buffer->data[buffer->rear] = value;
    buffer->rear = (buffer->rear + 1) % buffer->capacity;
    buffer->size++;
    return true;
}

bool RingBuf_dequeue(RingBuffer* buffer, uint8_t* value) {
    if (RingBuf_isEmpty(buffer)) {
        return false;
    }

    *value = buffer->data[buffer->front];
    buffer->front = (buffer->front + 1) % buffer->capacity;
    buffer->size--;
    return true;
}

int RingBuf_enqueueBatch(RingBuffer* buffer, const uint8_t* values, int count) {
    int processed = 0;

    if (RingBuf_getAvailableSize(buffer) < count) {
        count = RingBuf_getAvailableSize(buffer);
    }

    for (int i = 0; i < count; i++) {
        buffer->data[buffer->rear] = values[i];
        buffer->rear = (buffer->rear + 1) % buffer->capacity;
        processed++;
    }

    buffer->size += processed;

    return processed;
}

int RingBuf_dequeueBatch(RingBuffer* buffer, uint8_t* values, int count) {
    int processed = 0;

    if (buffer->size < count) {
        count = buffer->size;
    }

    for (int i = 0; i < count; i++) {
        values[i] = buffer->data[buffer->front];
        buffer->front = (buffer->front + 1) % buffer->capacity;
        processed++;
    }

    buffer->size -= processed;

    return processed;
}

inline int RingBuf_getUsedSize(RingBuffer* buffer) {
    return buffer->size;
}

inline int RingBuf_getAvailableSize(RingBuffer* buffer) {
    return (buffer->capacity) - (buffer->size);
}

void RingBuf_destroy(RingBuffer* buffer) {
    if (buffer != NULL)
        free(buffer->data);
    free(buffer);
}

inline int RingBuf_getContinousAvailableSize(RingBuffer* buffer) {
    const int availableSize = RingBuf_getAvailableSize(buffer);
    const int continousSize = (buffer->capacity) - (buffer->rear);
    return (availableSize < continousSize) ? availableSize : continousSize;
}

inline void RingBuf_postEnqueueBatch(RingBuffer* buffer, int count) {
    // no check there
    buffer->rear = (buffer->rear + count) % buffer->capacity;
    buffer->size += count;
}

inline uint8_t* RingBuf_getRearPtr(RingBuffer* buffer) {
    return buffer->data + buffer->rear;
}
