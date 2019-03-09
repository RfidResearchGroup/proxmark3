#ifndef OPTIMIZED_CIPHER_H
#define OPTIMIZED_CIPHER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
* Definition 1 (Cipher state). A cipher state of iClass s is an element of F 40/2
* consisting of the following four components:
*   1. the left register l = (l 0 . . . l 7 ) ∈ F 8/2 ;
*   2. the right register r = (r 0 . . . r 7 ) ∈ F 8/2 ;
*   3. the top register t = (t 0 . . . t 15 ) ∈ F 16/2 .
*   4. the bottom register b = (b 0 . . . b 7 ) ∈ F 8/2 .
**/
typedef struct {
    uint8_t l;
    uint8_t r;
    uint8_t b;
    uint16_t t;
} State;

/** The reader MAC is MAC(key, CC * NR )
 **/
void opt_doReaderMAC(uint8_t *cc_nr_p, uint8_t *div_key_p, uint8_t mac[4]);
/**
 * The tag MAC is MAC(key, CC * NR * 32x0))
 */
void opt_doTagMAC(uint8_t *cc_p, const uint8_t *div_key_p, uint8_t mac[4]);

/**
 * The tag MAC can be divided (both can, but no point in dividing the reader mac) into
 * two functions, since the first 8 bytes are known, we can pre-calculate the state
 * reached after feeding CC to the cipher.
 * @param cc_p
 * @param div_key_p
 * @return the cipher state
 */
State opt_doTagMAC_1(uint8_t *cc_p, const uint8_t *div_key_p);
/**
 * The second part of the tag MAC calculation, since the CC is already calculated into the state,
 * this function is fed only the NR, and internally feeds the remaining 32 0-bits to generate the tag
 * MAC response.
 * @param _init - precalculated cipher state
 * @param nr - the reader challenge
 * @param mac - where to store the MAC
 * @param div_key_p - the key to use
 */
void opt_doTagMAC_2(State _init, uint8_t *nr, uint8_t mac[4], const uint8_t *div_key_p);

#endif // OPTIMIZED_CIPHER_H
