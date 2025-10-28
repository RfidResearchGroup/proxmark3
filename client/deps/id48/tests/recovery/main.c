#include "id48.h"
#include <stdio.h>
#include <string.h>
#include "array_size2.h"

static bool bytes_equal(const uint8_t *lhs, const uint8_t *rhs, size_t len) {
    return memcmp(lhs, rhs, len) == 0;
}

typedef struct _TEST_VECTOR_T {
    const char *description;
    const ID48LIB_KEY key;
    const ID48LIB_NONCE nonce;
    const ID48LIB_FRN expected_frn;
    const ID48LIB_GRN expected_grn;
} TEST_VECTOR_T;

// Test vectors used in various Proxmark3 client commands:
static const TEST_VECTOR_T test_vectors[] = {
    // PM3 test key
    {
        // --key F32AA98CF5BE4ADFA6D3480B
        // --rnd 45F54ADA252AAC
        // --frn 4866BB70
        // --grn 9BD180
        .description = "PM3 test key",
        .key          = { .k   = { 0xF3, 0x2A, 0xA9, 0x8C,  0xF5, 0xBE, 0x4A, 0xDF,  0xA6, 0xD3, 0x48, 0x0B, } },
        .nonce        = { .rn  = { 0x45, 0xF5, 0x4A, 0xDA,  0x25, 0x2A, 0xAC, } },
        .expected_frn = { .frn = { 0x48, 0x66, 0xBB, 0x70, } },
        .expected_grn = { .grn = { 0x9B, 0xD1, 0x80, } },
    },
    // Research paper key
    {
        // --key A090A0A02080000000000000
        // --rnd 3FFE1FB6CC513F
        // --frn F355F1A0
        // --grn 609D60
        .description = "Research paper key",
        .key          = { .k   = { 0xA0, 0x90, 0xA0, 0xA0,  0x20, 0x80, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, } },
        .nonce        = { .rn  = { 0x3F, 0xFE, 0x1F, 0xB6,  0xCC, 0x51, 0x3F, } },
        .expected_frn = { .frn = { 0xF3, 0x55, 0xF1, 0xA0, } },
        .expected_grn = { .grn = { 0x60, 0x9D, 0x60, } },
    },
    // Autorecovery test key
    {
        // --key 022A028C02BE000102030405
        // --rnd 7D5167003571F8
        // --frn 982DBCC0
        // --grn 36C0E0
        .description = "Autorecovery test key",
        .key          = { .k   = { 0x02, 0x2A, 0x02, 0x8C,  0x02, 0xBE, 0x00, 0x01,  0x02, 0x03, 0x04, 0x05, } },
        .nonce        = { .rn  = { 0x7D, 0x51, 0x67, 0x00,  0x35, 0x71, 0xF8, } },
        .expected_frn = { .frn = { 0x98, 0x2D, 0xBC, 0xC0, } },
        .expected_grn = { .grn = { 0x36, 0xC0, 0xE0, } },
    },
};

// Comment
    /// <summary>
    /// Initializes to allow iterative recovery
    /// of multiple potential keys.  After calling
    /// this init() function, can repeatedly call
    /// the next() function until it returns false
    /// to obtain all potential keys.
    /// </summary>
    /// <param name="input_partial_key">
    /// Top 48 bits of the key, such as those discovered
    /// using the proxmark3 command `lf em 4x70 brute`.
    /// Only k[0..5] are used from this parameter,
    /// corresponding to K₉₅..K₄₈.
    /// </param>
    /// <param name="input_nonce">
    /// The nonce value.
    /// Typically from a sniffed authentication.
    /// </param>
    /// <param name="input_frn">
    /// The challenge sent from the reader (e.g., car)
    /// to the tag (e.g., key).
    /// Typically from a sniffed authentication.
    /// </param>
    /// <param name="input_grn">
    /// The response sent from the tag (e.g., key)
    /// to the car (e.g., car).
    /// Typically from a sniffed authentication.
    /// </param>
    /// <remarks>
    /// Note: In C++, each parameter would be a reference (not pointer).
    /// </remarks>

// void id48lib_key_recovery_init(
//     const ID48LIB_KEY *input_partial_key,
//     const ID48LIB_NONCE *input_nonce,
//     const ID48LIB_FRN *input_frn,
//     const ID48LIB_GRN *input_grn
// );

// Comment
    /// <summary>
    /// This can be repeated called (after calling init())
    /// to find the next potential key for the given
    /// partial key + nonce + frn + grn values.
    /// I've seen combinations that have up to six
    /// potential keys available, although typically
    /// there are 1-3 results.
    /// Each call to this function will return a single
    /// value.  Call repeatedly until the function returns
    /// false to get all potential keys.
    /// </summary>
    /// <param name="potential_key_output">
    /// When the function returns true, this caller-provided
    /// value will be filled with the 96-bit key that, when
    /// programmed to the tag, should authenticate against
    /// the nonce+frn values, with tag returning the grn value.
    /// </param>
    /// <returns>
    /// true when another potential key has been found.
    /// false if no additional potential keys have been found.
    /// </returns>
    /// <remarks>
    /// Note: In C++, each parameter would be a reference (not pointer).
    /// </remarks>
// bool id48lib_key_recovery_next(
//     ID48LIB_KEY *potential_key_output
// );



bool recovery_succeeds(const TEST_VECTOR_T *test_vector, bool zero_partial_key) {

    ID48LIB_KEY partial_key = {0};
    memcpy(&partial_key, &test_vector->key, sizeof(partial_key));
    if (zero_partial_key) {
        // API is only supposed to be looking at the first 6 bytes of the key
        memset(&partial_key.k[6], 0, sizeof(partial_key.k) - 6);
    }

    id48lib_key_recovery_init(&partial_key, &test_vector->nonce, &test_vector->expected_frn, &test_vector->expected_grn);

    bool key_found = false;
    uint32_t potential_keys_found = 0;
    ID48LIB_KEY potential_key = {0};
    while (id48lib_key_recovery_next(&potential_key)) {
        potential_keys_found++;
        // just verify that the potential key matches the test vector
        if (bytes_equal(potential_key.k, test_vector->key.k, sizeof(test_vector->key.k))) {
            key_found = true;
        } 
    }
    return key_found;
}

int main(void) {
    bool any_failures = false;

    for (size_t i = 0; i < ARRAY_SIZE2(test_vectors); i++) {
        printf("Testing recovery for test vector '%s'\n", test_vectors[i].description);
        if (!recovery_succeeds(&test_vectors[i], false)) {
            printf("FAILURE: id48lib_recovery: test vector '%s'\n", test_vectors[i].description);
            any_failures = true;
        }
        printf("Testing recovery for test vector '%s' (partially-zero'd key)\n", test_vectors[i].description);
        if (!recovery_succeeds(&test_vectors[i], true)) {
            printf("FAILURE: id48lib_recovery: test vector '%s' (partially-zero'd key)\n", test_vectors[i].description);
            any_failures = true;
        }
    }
    if (any_failures) {
        printf("id48lib_recovery: some tests failed\n");
    } else {
        printf("id48lib_recovery: all tests passed\n");
    }
    return any_failures ? 120 : 0;
}
