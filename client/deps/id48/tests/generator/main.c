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

bool generator_succeeds(const TEST_VECTOR_T *test_vector) {
    ID48LIB_FRN actual_frn = {0};
    ID48LIB_GRN actual_grn = {0};

    id48lib_generator(&test_vector->key, &test_vector->nonce, &actual_frn, &actual_grn);

    if (!bytes_equal(actual_frn.frn, test_vector->expected_frn.frn, sizeof(test_vector->expected_frn.frn))) {
        printf("id48lib_generator: unexpected FRN for test vector '%s'\n", test_vector->description);
        return false;
    }

    if (!bytes_equal(actual_grn.grn, test_vector->expected_grn.grn, sizeof(test_vector->expected_grn.grn))) {
        printf("id48lib_generator: unexpected GRN for test vector '%s'\n", test_vector->description);
        return false;
    }

    return true;
}

int main(void) {
    bool any_failures = false;

    for (size_t i = 0; i < ARRAY_SIZE2(test_vectors); i++) {
        printf("Testing generator for test vector '%s'\n", test_vectors[i].description);
        if (!generator_succeeds(&test_vectors[i])) {
            printf("FAILURE: id48lib_generator: test vector '%s'\n", test_vectors[i].description);
            any_failures = true;
        }
    }
    if (any_failures) {
        printf("id48lib_generator: some tests failed\n");
    } else {
        printf("id48lib_generator: all tests passed\n");
    }
    return any_failures ? 120 : 0;
}
