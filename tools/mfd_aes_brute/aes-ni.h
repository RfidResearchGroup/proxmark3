#ifndef __AES_NI_H__
#define __AES_NI_H__

#include "aes-ni.h"
// #include <stdint.h>     //for int8_t
// #include <string.h>     //for memcmp
// #include <wmmintrin.h>  //for intrinsics for AES-NI
//compile using gcc and following arguments: -g;-O0;-Wall;-msse2;-msse;-march=native;-maes

/*
static void AES_CBC_decrypt(const uint8_t *in,  uint8_t *out,  uint8_t iv[],  uint8_t len, uint8_t *key) {

    __m128i data, last_in;
    __m128i feedback = _mm_loadu_si128 ((__m128i*)iv);

    uint j;
    for (uint8_t i = 0; i < len; i++){
        last_in =_mm_loadu_si128 (&((__m128i*)in)[i]);
        data = _mm_xor_si128 (last_in, ((__m128i*)key)[0]);

        for (j = 1; j < 10; j++){
            data = _mm_aesdec_si128 (data, ((__m128i*)key)[j]);
        }
        data = _mm_aesdeclast_si128 (data,((__m128i*)key)[j]);
        data = _mm_xor_si128 (data, feedback);
        _mm_storeu_si128 (&((__m128i*)out)[i], data);
        feedback = last_in;
    }
}
*/

/*
INLINE static __m128i AES_128_ASSIST (__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
    temp3 = _mm_slli_si128 (temp1, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp1 = _mm_xor_si128 (temp1, temp2);
    return temp1;
}

static void AES_128_Key_Expansion (uint8_t *userkey, __m128i *key) {
    __m128i temp1, temp2;
    temp1 = _mm_loadu_si128((__m128i*)userkey);
    key[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[10] = temp1;
}

static void aes_inv_key_10(AESContext * ctx) {

    __m128i* keysched = (__m128i*)ctx->keysched;
    __m128i* invkeysched = (__m128i*)ctx->invkeysched;

    *(invkeysched + 10) = *(keysched + 0);
    *(invkeysched + 9) = _mm_aesimc_si128(*(keysched + 1));
    *(invkeysched + 8) = _mm_aesimc_si128(*(keysched + 2));
    *(invkeysched + 7) = _mm_aesimc_si128(*(keysched + 3));
    *(invkeysched + 6) = _mm_aesimc_si128(*(keysched + 4));
    *(invkeysched + 5) = _mm_aesimc_si128(*(keysched + 5));
    *(invkeysched + 4) = _mm_aesimc_si128(*(keysched + 6));
    *(invkeysched + 3) = _mm_aesimc_si128(*(keysched + 7));
    *(invkeysched + 2) = _mm_aesimc_si128(*(keysched + 8));
    *(invkeysched + 1) = _mm_aesimc_si128(*(keysched + 9));
    *(invkeysched + 0) = *(keysched + 10);
}

static void aes_decrypt_cbc_ni(const uint8_t *in,  uint8_t *out,  uint8_t iv[],  uint8_t len, uint8_t *key) {

    __m128i dec = _mm_setzero_si128();
    __m128i* block = (__m128i*)in;
    const __m128i* finish = (__m128i*)(in + len);

    // Load IV
    __m128i iv = _mm_loadu_si128((__m128i*)iv);

    while (block < finish) {

        // Key schedule ptr
        __m128i* keysched = (__m128i*)ctx->invkeysched;
        __m128i last = _mm_loadu_si128(block);

        dec  = _mm_xor_si128(last, *keysched);

        dec = _mm_aesdec_si128(dec, *(++keysched));
        dec = _mm_aesdec_si128(dec, *(++keysched));
        dec = _mm_aesdec_si128(dec, *(++keysched));
        dec = _mm_aesdec_si128(dec, *(++keysched));
        dec = _mm_aesdec_si128(dec, *(++keysched));
        dec = _mm_aesdec_si128(dec, *(++keysched));
        dec = _mm_aesdec_si128(dec, *(++keysched));
        dec = _mm_aesdec_si128(dec, *(++keysched));
        dec = _mm_aesdec_si128(dec, *(++keysched));
        dec = _mm_aesdeclast_si128(dec, *(++keysched));

        /// Xor data with IV
        dec  = _mm_xor_si128(iv, dec);

        // Store data
        _mm_storeu_si128(block, dec);
        iv = last;

        // Go to next block
        ++block;
    }

    // Update IV
    _mm_storeu_si128((__m128i*)iv, dec);
}

static void aes_setup_ni(AESContext * ctx, uint8_t *key) {

    __m128i *keysched = (__m128i*)ctx->keysched;

    ctx->decrypt_cbc = aes_decrypt_cbc_ni;

    // Now do the key setup itself.
    AES_128_Key_Expansion (key, keysched);

    // Now prepare the modified keys for the inverse cipher.
    aes_inv_key_10(ctx);
}
*/

#endif
