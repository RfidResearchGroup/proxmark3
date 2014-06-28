#ifndef IKEYS_H
#define IKEYS_H


/**
 * @brief
 *Definition 11. Let the function hash0 : F 82 × F 82 × (F 62 ) 8 → (F 82 ) 8 be defined as
 *	hash0(x, y, z [0] . . . z [7] ) = k [0] . . . k [7] where
 * z'[i] = (z[i] mod (63-i)) + i	i =  0...3
 * z'[i+4] = (z[i+4] mod (64-i)) + i	i =  0...3
 * ẑ = check(z');
 * @param c
 * @param k this is where the diversified key is put (should be 8 bytes)
 * @return
 */
void hash0(uint64_t c, uint8_t k[8]);
int doKeyTests(uint8_t debuglevel);
/**
 * @brief Performs Elite-class key diversification
 * @param csn
 * @param key
 * @param div_key
 */

void diversifyKey(uint8_t csn[8], uint8_t key[8], uint8_t div_key[8]);
/**
 * @brief Permutes a key from standard NIST format to Iclass specific format
 * @param key
 * @param dest
 */

#endif // IKEYS_H
