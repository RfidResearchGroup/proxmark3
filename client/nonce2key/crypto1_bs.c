// Bit-sliced Crypto-1 implementation
// The cipher states are stored with the least significant bit first, hence all bit indexes are reversed here
/*
Copyright (c) 2015-2016 Aram Verstegen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "crypto1_bs.h"
#include <inttypes.h>
#define __STDC_FORMAT_MACROS
#define llx PRIx64
#define lli PRIi64
#define lu PRIu32

// The following functions use this global or thread-local state
// It is sized to fit exactly KEYSTREAM_SIZE more states next to the initial state
__thread bitslice_t states[KEYSTREAM_SIZE+STATE_SIZE];
__thread bitslice_t * restrict state_p;

void crypto1_bs_init(){
    // initialize constant one and zero bit vectors
    memset(bs_ones.bytes, 0xff, VECTOR_SIZE);
    memset(bs_zeroes.bytes, 0x00, VECTOR_SIZE);
}

// The following functions have side effects on 48 bitslices at the state_p pointer
// use the crypto1_bs_rewind_* macros to (re-)initialize them as needed

inline const bitslice_value_t crypto1_bs_bit(const bitslice_value_t input, const bool is_encrypted){
    bitslice_value_t feedback = (state_p[47- 0].value ^ state_p[47- 5].value ^ state_p[47- 9].value ^
                                 state_p[47-10].value ^ state_p[47-12].value ^ state_p[47-14].value ^
                                 state_p[47-15].value ^ state_p[47-17].value ^ state_p[47-19].value ^
                                 state_p[47-24].value ^ state_p[47-25].value ^ state_p[47-27].value ^
                                 state_p[47-29].value ^ state_p[47-35].value ^ state_p[47-39].value ^
                                 state_p[47-41].value ^ state_p[47-42].value ^ state_p[47-43].value);
    const bitslice_value_t ks_bits = crypto1_bs_f20(state_p);
    if(is_encrypted){
        feedback ^= ks_bits;
    }
    state_p--;
    state_p[0].value = feedback ^ input;
    return ks_bits;
}

inline const bitslice_value_t crypto1_bs_lfsr_rollback(const bitslice_value_t input, const bool is_encrypted){
    bitslice_value_t feedout = state_p[0].value;
    state_p++;
    const bitslice_value_t ks_bits = crypto1_bs_f20(state_p);
    if(is_encrypted){
        feedout ^= ks_bits;
    }
    const bitslice_value_t feedback = (feedout              ^ state_p[47- 5].value ^ state_p[47- 9].value ^
                                       state_p[47-10].value ^ state_p[47-12].value ^ state_p[47-14].value ^
                                       state_p[47-15].value ^ state_p[47-17].value ^ state_p[47-19].value ^
                                       state_p[47-24].value ^ state_p[47-25].value ^ state_p[47-27].value ^
                                       state_p[47-29].value ^ state_p[47-35].value ^ state_p[47-39].value ^
                                       state_p[47-41].value ^ state_p[47-42].value ^ state_p[47-43].value);
    state_p[47].value = feedback ^ input;
    return ks_bits;
}

// side-effect free from here on
// note that bytes are sliced and unsliced with reversed endianness
inline void crypto1_bs_convert_states(bitslice_t bitsliced_states[], state_t regular_states[]){
    size_t bit_idx = 0, slice_idx = 0;
	state_t values[MAX_BITSLICES];
	memset(values, 0x0, sizeof(values));
	
    for(slice_idx = 0; slice_idx < MAX_BITSLICES; slice_idx++){
        for(bit_idx = 0; bit_idx < STATE_SIZE; bit_idx++){
            bool bit = get_vector_bit(slice_idx, bitsliced_states[bit_idx]);
            values[slice_idx].value <<= 1;
            values[slice_idx].value |= bit;
        }
        // swap endianness
        values[slice_idx].value = rev_state_t(values[slice_idx].value);
        // roll off unused bits
        //values[slice_idx].value >>= ((sizeof(state_t)*8)-STATE_SIZE); // - 48
		values[slice_idx].value >>= 16;
    }
    memcpy(regular_states, values, sizeof(values));
}

// bitslice a value
void crypto1_bs_bitslice_value32(uint32_t value, bitslice_t bitsliced_value[], size_t bit_len){
    // load nonce bytes with unswapped endianness
    size_t bit_idx;
    for(bit_idx = 0; bit_idx < bit_len; bit_idx++){
        bool bit = get_bit(bit_len-1-bit_idx, rev32(value));
        if(bit){
            bitsliced_value[bit_idx].value = bs_ones.value;
        } else {
            bitsliced_value[bit_idx].value = bs_zeroes.value;
        }
    }
}

void crypto1_bs_print_states(bitslice_t bitsliced_states[]){
    size_t slice_idx = 0;
    state_t values[MAX_BITSLICES]  = {{0x00}};
    crypto1_bs_convert_states(bitsliced_states, values);
    for(slice_idx = 0; slice_idx < MAX_BITSLICES; slice_idx++){
        printf("State %03zu: %012"llx"\n", slice_idx, values[slice_idx].value);
    }
}

