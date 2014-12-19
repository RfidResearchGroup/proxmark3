#include <stdio.h>
#include <stdlib.h>
#include "des.h"

int main(int argc, const char* argv[]) {
	des_context ctx;

	unsigned char key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    printf("Key: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x ", key[i]);
    }
    printf("\n\n");
    
    // This is the challange sent from PICC
    unsigned char ek0RandB[8] = {0x4f, 0xb1, 0xed, 0x2e, 0x11, 0x37, 0xd5, 0x1a};

    if (argc == 8 + 1) {
        for (int i = 0 + 1; i < 8 + 1; i++) {
            ek0RandB[i - 1] = strtol(argv[i], NULL, 16);
        }
    }
    
    printf("ek0RandB (Challange): ");
    for (int i = 0; i < 8; i++) {
        printf("%02x ", ek0RandB[i]);
    }
    printf("\n\n");

    unsigned char RandB[8];
	unsigned char RandBP[8];
    unsigned char ek0RandBP[8];

    // TODO: Make this randomly generated
	unsigned char RandA[8] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char ek0RandA[8];
    
    unsigned char sessionKey[8];

	des_setkey_dec(&ctx, key);

    //Decrypt RandB from PICC
	des_crypt_ecb(&ctx, ek0RandB, RandB);

	printf("RandB: ");
	for (int i = 0; i < 8; i++) {
		printf("%02x ", RandB[i]);
	}
	printf("\n");

	//Shift RandB left by 8 bits to produce RandB’
	for (int x = 0; x < 7; x++) {
		RandBP[x] = RandB[x + 1];
	}
	RandBP[7] = RandB[0];

	printf("RandB’: ");
	for (int i = 0; i < 8; i++) {
		printf("%02x ", RandBP[i]);
	}
	printf("\n");

	//Print RandA
	printf("RandA: ");
	for (int i = 0; i < 8; i++) {
		printf("%02x ", RandA[i]);
	}
	printf("\n\n");

	//Encrypt RandA into ek0RandA
	des_crypt_ecb(&ctx, RandA, ek0RandA);

	printf("ek0RandA: ");
	for (int i = 0; i < 8; i++) {
		printf("%02x ", ek0RandA[i]);
	}
	printf("\n");
	
	//Encrypt ( ek0RandA XOR RandB' ) for CBC Mode chaining
	for (int i = 0; i < 8; i++) {
		ek0RandBP[i] = RandBP[i] ^ ek0RandA[i];
	}

	des_crypt_ecb(&ctx, ek0RandBP, ek0RandBP);
    
    printf("ek0(RandB' XOR ek0RandA): ");
	for (int i = 0; i < 8; i++) {
		printf("%02x ", ek0RandBP[i]);
	}
	printf("\n\n");
    
    //Varibles used in checking for proper reply from PICC
    unsigned char RandAP[8];
    unsigned char ek0RandAP[8];
    
    //Shift RandA left by 8 bits to produce RandA’
    for (int x = 0; x < 7; x++) {
        RandAP[x] = RandA[x + 1];
    }
    RandAP[7] = RandA[0];
    
    //Encrypt RandA' to check PICC's response.
    des_crypt_ecb(&ctx, RandAP, ek0RandAP);
    
    printf("ek0RandA' (Expected reply): ");
    for (int i = 0; i < 8; i++) {
        printf("%02x ", ek0RandAP[i]);
    }
    printf("\n");
    
    //Create session key
    sessionKey[0] = RandA[0];
    sessionKey[1] = RandA[1];
    sessionKey[2] = RandA[2];
    sessionKey[3] = RandA[3];
    sessionKey[4] = RandB[0];
    sessionKey[5] = RandB[1];
    sessionKey[6] = RandB[2];
    sessionKey[7] = RandB[3];
    
    printf("Session Key: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x ", sessionKey[i]);
    }
    printf("\n");
    
	return 1;
}

/*
 Recorded Activity
 
 Start = Start of Start Bit, End = End of last modulation. Src = Source of Transfer
 All times are in carrier periods (1/13.56Mhz)
 
 Start |       End | Src | Data
 -----------|-----------|-----|--------
 0 |       992 | Rdr | 52
 2228 |      4596 | Tag | 44  03
 1836032 |   1838496 | Rdr | 93  20
 1839668 |   1845492 | Tag | 88  04  6e  22  c0
 3806976 |   3817440 | Rdr | 93  70  88  04  6e  22  c0  dc  b8
 3818676 |   3822196 | Tag | 24  d8  36
 5815808 |   5818272 | Rdr | 95  20
 5819444 |   5825268 | Tag | 72  63  34  80  a5
 7757824 |   7768288 | Rdr | 95  70  72  63  34  80  a5  a7  a5
 7769524 |   7773108 | Tag | 20  fc  70
 9715072 |   9719840 | Rdr | e0  80  31  73
 9721012 |   9730292 | Tag | 06  75  77  81  02  80  02  f0
 12074624 |  12080480 | Rdr | 02  0a  00  dc  ed
 12111924 |  12125812 | Tag | 02  af  4f  b1  ed  2e  11  37  d5  1a  bf  55
 229214720 | 229237856 | Rdr | 03  af  f3  56  83  43  79  d1  65  cd  6c  6d  17  e8  14  6e  52  eb  6d  2b
 229268916 | 229282804 | Tag | 03  00  0d  9f  27  9b  a5  d8  72  60  f3  6f
*/

/*
 hf 14a raw -p -a -b 7 52
 hf 14a raw -p 93 20
 hf 14a raw -p -c 93  70  88  04  6e  22  c0
 hf 14a raw -p 95 20
 hf 14a raw -p -c 95  70  72  63  34  80  a5
 hf 14a raw -p e0  80  31  73
 hf 14a raw -p -c 02 0a 00
 hf 14a raw -p -c 03 af ...
*/