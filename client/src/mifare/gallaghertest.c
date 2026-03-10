#include "gallaghertest.h"

#include <unistd.h>
#include <string.h>      // memcpy memset
#include "ui.h"
#include "crc.h"

#include "mifare/gallaghercore.h"

static bool creds_match(GallagherCredentials_t *a, GallagherCredentials_t *b) {
    return a->region_code == b->region_code &&
           a->facility_code == b->facility_code &&
           a->card_number == b->card_number &&
           a->issue_level == b->issue_level;
}

static bool test_CAD(void) {
    // Example CAD sector from https://github.com/megabug/gallagher-research/blob/master/formats/card-specific/mifare-classic.md
    uint8_t cad[] = {0x1B, 0x58, 0x00, 0x01, 0xC1, 0x33, 0x70, 0xFD, 0x13, 0x38, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x77, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    };

    // Entry 0: RC=0xC, FC=0x1337, Sector=0x0F
    int result = gallagher_parse_cad(cad, 0xC, 0x1337);
    if (result != 0x0F) {
        PrintAndLogEx(INFO, "Gallagher CAD test 1 failed: expected sector 0x0F, got 0x%02X", result);
        return false;
    }

    // Entry 1: RC=0xD, FC=0x1338, Sector=0x0D
    result = gallagher_parse_cad(cad, 0xD, 0x1338);
    if (result != 0x0D) {
        PrintAndLogEx(INFO, "Gallagher CAD test 2 failed: expected sector 0x0D, got 0x%02X", result);
        return false;
    }

    // Non-existent entry should return -1
    result = gallagher_parse_cad(cad, 0xA, 0x1234);
    if (result != -1) {
        PrintAndLogEx(INFO, "Gallagher CAD test 3 failed: expected -1, got %d", result);
        return false;
    }

    return true;
}

static bool test_creds(void) {
    GallagherCredentials_t creds1 = {
        .region_code = 0x0,
        .facility_code = 0x0,
        .card_number = 0x0,
        .issue_level = 0x0,
    };

    GallagherCredentials_t creds2 = {
        .region_code = 0x1,
        .facility_code = 0x2,
        .card_number = 0x20,
        .issue_level = 0x1,
    };

    GallagherCredentials_t cred_result = {0};
    uint8_t bytes_result[8] = {0};

    gallagher_encode_creds(bytes_result, &creds1);
    gallagher_decode_creds(bytes_result, &cred_result);
    if (!creds_match(&cred_result, &creds1)) {
        PrintAndLogEx(INFO, "Gallagher encode/decode roundtrip test 1 failed");
        return false;
    }

    gallagher_encode_creds(bytes_result, &creds2);
    gallagher_decode_creds(bytes_result, &cred_result);
    if (!creds_match(&cred_result, &creds2)) {
        PrintAndLogEx(INFO, "Gallagher encode/decode roundtrip test 2 failed");
        return false;
    }

    return true;
}

// Test decode/encode against known real-world data from the documentation
static bool test_known_vector_creds(void) {
    // From doc: 0xA3B4B0C151B0A31B decodes to RC=12, FC=4919(0x1337), CN=61453(0xF00D), IL=1
    uint8_t known_bytes[] = {0xA3, 0xB4, 0xB0, 0xC1, 0x51, 0xB0, 0xA3, 0x1B};
    GallagherCredentials_t expected = {
        .region_code = 12,
        .facility_code = 4919,
        .card_number = 61453,
        .issue_level = 1,
    };

    // Test decode
    GallagherCredentials_t result = {0};
    gallagher_decode_creds(known_bytes, &result);
    if (!creds_match(&expected, &result)) {
        PrintAndLogEx(INFO, "Known vector decode failed: RC=%d FC=%d CN=%d IL=%d",
                      result.region_code, result.facility_code, result.card_number, result.issue_level);
        return false;
    }

    // Test encode roundtrip
    uint8_t encoded[8] = {0};
    gallagher_encode_creds(encoded, &expected);
    if (memcmp(encoded, known_bytes, 8) != 0) {
        PrintAndLogEx(INFO, "Known vector encode failed");
        return false;
    }

    // Verify bitwise inverse (block 0 format: 8-byte creds + 8-byte inverse)
    uint8_t known_block0[] = {0xA3, 0xB4, 0xB0, 0xC1, 0x51, 0xB0, 0xA3, 0x1B,
                              0x5C, 0x4B, 0x4F, 0x3E, 0xAE, 0x4F, 0x5C, 0xE4
                             };
    for (int i = 0; i < 8; i++) {
        if ((uint8_t)(known_block0[i] ^ 0xFF) != known_block0[i + 8]) {
            PrintAndLogEx(INFO, "Bitwise inverse check failed at byte %d", i);
            return false;
        }
    }

    return true;
}

// Test MAD CRC against known sector 0 data from the documentation
static bool test_mad_crc(void) {
    // Full sector 0 from documentation (blocks 0-2, excluding trailer)
    uint8_t sector0[64] = {
        // Block 0 (manufacturer)
        0xE3, 0x51, 0x54, 0x3C, 0xDA, 0x08, 0x04, 0x00, 0x01, 0x6F, 0x01, 0x6D, 0x45, 0x68, 0xF8, 0x1D,
        // Block 1 (MAD: CRC, info byte, AIDs 1-7)
        0xBD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Block 2 (MAD: AIDs 8-15)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x48, 0x11, 0x48, 0x12, 0x48,
        // Block 3 (sector trailer - not part of CRC)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x77, 0x88, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    // MAD v1 CRC: computed over sector0[17..47] (info byte + 15 AID pairs = 31 bytes)
    uint8_t expected_crc = sector0[16]; // 0xBD
    uint8_t computed_crc = CRC8Mad(&sector0[16 + 1], 15 + 16);
    if (computed_crc != expected_crc) {
        PrintAndLogEx(INFO, "MAD CRC test failed: expected 0x%02X, got 0x%02X", expected_crc, computed_crc);
        return false;
    }

    return true;
}

static bool test_MES(void) {

    uint8_t csn[] = {0x3C, 0x54, 0x51, 0xE3};
    uint8_t csn_len = 4;
    uint8_t site_key[] = {0x13, 0x37, 0xD0, 0x0D, 0x13, 0x37, 0xD0, 0x0D, 0x13, 0x37, 0xD0, 0x0D, 0x13, 0x37, 0xD0, 0x0D};

    GallagherCredentials_t known_cred;
    gallagher_construct_credential(&known_cred, 12, 0x1337, 0xF00D, 1, true, csn, csn_len, site_key);

    GallagherCredentials_t result_creds = {0};
    gallagher_construct_credential(&result_creds, 0, 0, 0, 0, true, csn, csn_len, site_key);

    uint8_t sector_result[16] = {0};
    uint8_t known_sector[16] = {0x4F, 0x36, 0xB7, 0x4E, 0xFF, 0xCD, 0x76, 0xEF, 0xED, 0xA5, 0x74, 0x58, 0xC8, 0xB4, 0xE3, 0x04};

    // Test encode
    gallagher_encode_mes(sector_result, &known_cred);
    if (memcmp(sector_result, known_sector, 16) != 0) {
        PrintAndLogEx(INFO, "Gallagher MES encode test failed");
        PrintAndLogEx(INFO, "Expected: %s", sprint_hex_ascii(known_sector, 16));
        PrintAndLogEx(INFO, "Got:      %s", sprint_hex_ascii(sector_result, 16));
        return false;
    }

    // Test decode
    if (gallagher_decode_mes(known_sector, &result_creds) != PM3_SUCCESS) {
        PrintAndLogEx(INFO, "Gallagher MES decode test failed");
        return false;
    }
    if (!creds_match(&known_cred, &result_creds)) {
        PrintAndLogEx(INFO, "Gallagher MES decoded different creds than expected");
        return false;
    }

    return true;
}

bool GallagherTest(bool verbose) {
    bool result = true;
    result &= test_CAD();
    result &= test_creds();
    result &= test_known_vector_creds();
    result &= test_mad_crc();
    result &= test_MES();
    return result;
}
