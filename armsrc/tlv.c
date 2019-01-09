#include <tlv.h>

int decode_ber_tlv_item(uint8_t* data, tlvtag* returnedtag)
{
    uint8_t tag[TAG_LENGTH] = {0x00, 0x00, 0x00, 0x00};
    uint16_t length = 0;
    //uint8_t value[VALUE_LENGTH];
    uint8_t lenlen = 0;
    int i = 0; 
    int z = 0; 
    //decode tag
    tag[0] = data[0];
    if ((tag[0] & TLV_TAG_NUMBER_MASK) == TLV_TAG_NUMBER_MASK) { //see subsequent bytes
        i++; 
       
		tag[i] = data[i];

		while((data[i] & TLV_TAG_MASK) == TLV_TAG_MASK){
			i++; 
			tag[i] = data[i];
		}

    }
    i++; 
    //decode length
    if ((data[i] & TLV_LENGTH_MASK) == TLV_LENGTH_MASK) {
        lenlen = data[i] ^ TLV_LENGTH_MASK;
        i++;
        length = (uint16_t)data[i];
        z = 1;
        while (z < lenlen) {
            i++;
            z++;
            length <<= 8;
            length += (uint16_t)data[i];
        }
        i++;
    } else {
        length = (uint16_t)data[i];
        i++;
    }
    // copy results into the structure and return 
    memcpy(returnedtag->tag, tag, TAG_LENGTH);
	
	// return length of tag value 
    (*returnedtag).valuelength = length;
	
	// return length of total field
    (*returnedtag).fieldlength = length + i + 1;
	
    memcpy(returnedtag->value, &(data[i]), length);
    return 0; 
}

//generate a TLV tag off input data
int encode_ber_tlv_item(uint8_t* tag, uint8_t taglen, uint8_t* data, uint32_t datalen, uint8_t* outputtag, uint32_t* outputtaglen)
{
    if (!tag || !data || !outputtag || !outputtaglen)
        return 0;
    
	// field length of the tag	
    uint8_t datafieldlen = (datalen / 128) + 1;
	
	// total length of the tag
    uint8_t tlvtotallen = taglen + datafieldlen + datalen;
	
	// buffer for the returned tag
    uint8_t returnedtag[tlvtotallen];
	
    uint8_t counter = 0; 

	// copy tag into buffer
    memcpy(returnedtag, tag, taglen);
    counter += taglen; 
	
	// 1 byte length value
    if (datalen < 128){
        returnedtag[counter++] = datalen; 
    } else {
		
		// high bit set and number of length bytes
        returnedtag[counter++] = datafieldlen | 0x80;
		
        for (uint8_t i = datafieldlen; i !=0; i--) {
			// get current byte
            returnedtag[counter++] = (datalen >> (i * 8)) & 0xFF;
        } 
    }
    memcpy(&returnedtag[counter], data, datalen);
    *outputtaglen = tlvtotallen;
    memcpy(outputtag, returnedtag, tlvtotallen);
    return 0;
}

