/*
 * 
 * CryptoRF simulation
 *
 * Copyright (C) 2010, Flavio D. Garcia, Peter van Rossum, Roel Verdult
 * and Ronny Wichers Schreur. Radboud University Nijmegen   
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#include "defines.h"
#include <stdio.h>
#include <time.h>
#include <nfc/nfc.h>
#include "cryptolib.h"
#include "util.h"

// ~dirty globals for lazy use of libnfc
static dev_info* pdi;        // NFC device info
static tag_info ti;          // Tag info (card serial, etc.)
byte_t abtRx[MAX_FRAME_LEN]; // Communication buffer
size_t szRxLen;              // Length of communication buffer

void print_decryption(const byte_t* ct, const byte_t* pt, size_t len) {
    size_t pos,count;

    for (count = 0; count < len; count += 8) {
        printf(" ");
        for (pos = 0; pos < 8; pos++){
            if ((count+pos)<len) {
                printf("%02x ",ct[count+pos]);
            } else {
                printf("   ");
            }
        }

        printf(" =>  ");
        for (pos = 0; pos < 8; pos++) {
            if ((count + pos) < len) {
                printf("%02x ", pt[count + pos]);
            } else {
                printf("   ");
            }
        }
        printf("\n");
    }
}

bool transmit_bytes(const byte_t* pbtTx, const size_t szTxLen) {
    printf("R: "); 
    print_bytes(pbtTx, szTxLen);

    // Transmit the command bytes
    if (!nfc_initiator_transceive_bytes(pdi, pbtTx, szTxLen, abtRx, (uint32_t*)&szRxLen)) {
        printf("\nERROR: Communication failed\n\n");
        nfc_disconnect(pdi);
        exit(1);
    }

    printf("T: "); 
    print_bytes(abtRx, szRxLen);

    // Succesful transfer
    return true;
}


#define PWD_NOT_USED (uint32_t)(~0)

int main(int argc, char* argv[]) {
    // Various parameters
    crypto_state_t s; // Cryptomemory state
    size_t pos;      // Position counter

    // Main authentication values
    byte_t     Q[8]; // Reader key-auth random 
    byte_t    Gc[8]; // Secret seed
    byte_t    Ci[8]; // Card random (last state)
    byte_t    Ch[8]; // Reader answer (challenge)
    byte_t  Ci_1[8]; // Card answer
    byte_t  Ci_2[8]; // Session key

    // Session authentication values
    byte_t    Qs[8]; // Reader session-auth random
    byte_t   Chs[8]; // Reader session-answer (challenge)
    byte_t Ci_1s[8]; // Card answer for session
    byte_t Ci_2s[8]; // Is this used?

    // Various argument options
    ui64 Gc0;        // First card secret
    uint32_t zone;   // Number of userzone
    uint32_t offset; // Offset address
    uint32_t len;    // Length
    uint32_t pwd;    // Optional read password

    // Application buffers
    byte_t pt[MAX_FRAME_LEN];    // Plaintext
    byte_t ct[MAX_FRAME_LEN];    // Ciphertext
    byte_t mac[2];

    byte_t   crf_read_ci[2 +  2] = { 0x16,0x00,0x50,0x07 }; // Read first card random Ci0 (offset 50, len 8)
    byte_t crf_check_pwd[2 +  3] = { 0x1c,0x00 };           // Provide (optional) read password 
    byte_t      crf_auth[2 + 16] = { 0x18,0x00 };           // Authenticate using card secret Gc0 and Ci
    byte_t    crf_verify[2 + 16] = { 0x18,0x10 };           // Authenticate with session key
    byte_t  crf_set_zone[1 +  1] = { 0x11 };                // Set the userzone to read from
    byte_t crf_read_zone[2 +  2] = { 0x12,0x00 };           // Read n-bytes from offset
    byte_t  crf_read_mac[     4] = { 0x16,0x02,0xff,0x01 }; // Read n-bytes from offset

    // Show header and help syntax
    printf("CryptoRF example - (c) Radboud University Nijmegen\n\n");
    if (argc < 5) {
        printf("syntax: crf <Gc0> <zone> <offset> <len> [pwd]\n\n");
        return 1;
    }

    // Parse command-line arguments
    sscanf(argv[1],"%016llx", &Gc0);
    sscanf(argv[2],"%02x", &zone);
    sscanf(argv[3],"%02x", &offset);
    sscanf(argv[4],"%02x", &len);

    // Construct CryptoRF frames
    num_to_bytes(Gc0, 8, Gc);
    crf_set_zone[1] = zone;
    crf_read_zone[2] = offset;
    crf_read_zone[3] = (len == 0) ? 0 : (len - 1);

    // Check if the optional password argument was used
    if (argc == 6) {
        sscanf(argv[5], "%06x", &pwd);
        num_to_bytes(pwd, 3, crf_check_pwd + 2);
    } else {
        pwd = PWD_NOT_USED;
    }

    // Initialize randoms
    srand((uint32_t)time(0));

    for (pos = 0; pos < 8; pos++) {
        Q[pos] = rand();
        Qs[pos] = rand();
    }

    // Try to open the NFC device
    pdi = nfc_connect(NULL);
    if (pdi == INVALID_DEVICE_INFO) {
        printf("ERROR: Unable to connect to NFC device.\n");
        return 1;
    }
    nfc_initiator_init(pdi);

    // Drop the field for a while
    nfc_configure(pdi, DCO_ACTIVATE_FIELD, true);

    // Let the reader only try once to find a tag
    nfc_configure(pdi, DCO_INFINITE_SELECT, false);

    // Configure the CRC and Parity settings
    nfc_configure(pdi, DCO_HANDLE_CRC, true);
    nfc_configure(pdi, DCO_HANDLE_PARITY, true);

    printf("Connected to NFC device: %s\n\n", pdi->acName);

    // Poll for a ISO14443-B cryptomemory tag
    if (!nfc_initiator_select_tag(pdi, IM_ISO14443B_106, (byte_t*)"\x00", 1, &ti)) {
        printf("ERROR: Can not find a Atmel CryptoRF card.\n\n");
        nfc_disconnect(pdi);
        return 1;
    }

    printf("The following (NFC) ISO14443-B tag was found:\n\n");
    printf("   ATQB: "); print_bytes(ti.tib.abtAtqb, 12);
    printf("     ID: "); print_bytes(ti.tib.abtId, 4);
    printf("    CID: %02x\n", ti.tib.btCid);
    printf(" PARAMS: %02x %02x %02x %02x\n\n"
        ,ti.tib.btParam1
        ,ti.tib.btParam2
        ,ti.tib.btParam3
        ,ti.tib.btParam4
    );


    printf("Changing active userzone\n");
    transmit_bytes(crf_set_zone, sizeof(crf_set_zone));
    printf("\n");

    if (pwd != PWD_NOT_USED) {
        printf("Suppling password for communication\n");
        transmit_bytes(crf_check_pwd, sizeof(crf_check_pwd));
        printf("\n");
    }

    printf("Reading first Ci(0) from the system zone (offset = 0x50)\n");
    transmit_bytes(crf_read_ci, sizeof(crf_read_ci));
    printf("\n");

    // Save the retrieved value of Ci
    memcpy(Ci, abtRx + 2, 8);

    // Calculate key-authentication
    printf("* Computing authentication values with card secret\n\n");
    cm_auth(Gc, Ci, Q, Ch, Ci_1, Ci_2, &s);
    memcpy(crf_auth + 2, Q, 8);
    memcpy(crf_auth + 10, Ch, 8);

    printf("Authenticate using Gc, Ci and random Q\n");
    transmit_bytes(crf_auth, sizeof(crf_auth));
    printf("\n");

    printf("Reading new Ci value from the system zone (tag-answer)\n");
    transmit_bytes(crf_read_ci, sizeof(crf_read_ci));
    printf("\n");

    if (memcmp(Ci_1, abtRx + 2, 8) != 0) {
        printf("ERROR: Authentication failed\n\n");
        nfc_disconnect(pdi);
        return 1;
    }

    // Calculate session-authentication
    printf("* Computing authentication values with session key\n\n");
    cm_auth(Ci_2, Ci_1, Qs, Chs, Ci_1s, Ci_2s, &s);
    memcpy(crf_verify + 2, Qs, 8);
    memcpy(crf_verify + 10, Chs, 8);

    printf("VerifyCrypto using session key and initialize encryption\n");
    transmit_bytes(crf_verify, sizeof(crf_verify));
    printf("\n");

    printf("Reading new Ci value from the system zone (tag-answer)\n");
    transmit_bytes(crf_read_ci, sizeof(crf_read_ci));
    printf("\n");

    if (memcmp(Ci_1s, abtRx + 2, 8) != 0) {
        printf("ERROR: Session authentication failed\n\n");
        nfc_disconnect(pdi);
        return 1;
    }

    printf("* Updating the cipher by grinding Ci (offset,len,data)\n\n");
    cm_grind_read_system_zone(0x50, 8, Ci_1s, &s);

    printf("Read the data from the offset using the encrypted channel\n");
    transmit_bytes(crf_read_zone, sizeof(crf_read_zone));
    printf("\n");

    if (abtRx[1] != 0) {
        printf("ERROR: Reading failed, maybe you need to supply a password\n\n");
        nfc_disconnect(pdi);
        return 1;
    }
    memcpy(ct, abtRx + 2, len);

    printf("* Decrypting...");
    cm_decrypt(offset, len, ct, pt, &s);
    printf("done\n\n");
    print_decryption(ct, pt, len);
    printf("\n");

    if (pwd != PWD_NOT_USED) {
        num_to_bytes(pwd, 3, pt);
        cm_password(pt, crf_check_pwd + 2, &s);
        printf("Testing the feature to supply an encrypted password\n");
        transmit_bytes(crf_check_pwd, sizeof(crf_check_pwd));
        printf("\n");
    }

    // Calculate and check mac
    cm_mac(mac, &s);
    printf("Verify checksum for the transaction: %02x %02x\n", mac[0], mac[1]);
    transmit_bytes(crf_read_mac, sizeof(crf_read_mac));
    if (memcmp(mac, abtRx + 2, 2) != 0) {
        printf("ERROR: MAC checksum failed\n\n");
        nfc_disconnect(pdi);
        return 1;
    }

    printf("Communication succesful!\n\n");
    nfc_disconnect(pdi);
    return 0;
}

