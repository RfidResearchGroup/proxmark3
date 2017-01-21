#ifndef __TLV_H
#define __TLV_H

#include <stdint.h>
#include <string.h>
#include <stddef.h>

//structure buffer definitions
#define TAG_LENGTH 2
#define VALUE_LENGTH 1024

//masks
//if TLV_TAG_NUMBER_MASK bits are set, refer to the next byte for the tag number
//otherwise its located in bits 1-5
#define TLV_TAG_NUMBER_MASK 0x1f
//if TLV_DATA_MASK set then its a 'constructed data object'
//otherwise a 'primitive data object'
#define TLV_DATA_MASK 0x20
#define TLV_TAG_MASK 0x80
#define TLV_LENGTH_MASK 0x80

//tlv tag structure, tag can be max of 2 bytes, length up to 65535 and value 1024 bytes long 
typedef struct {
    uint8_t tag[TAG_LENGTH];
    uint16_t fieldlength;
    uint16_t valuelength; 
    uint8_t value[VALUE_LENGTH];
}tlvtag;

//decode a BER TLV 
extern int decode_ber_tlv_item(uint8_t* data, tlvtag* returnedtag);
extern int encode_ber_tlv_item(uint8_t* tag, uint8_t taglen, uint8_t*data, uint32_t datalen, uint8_t* outputtag, uint32_t* outputtaglen);
#endif //__TLV_H
