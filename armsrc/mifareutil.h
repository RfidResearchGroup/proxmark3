//-----------------------------------------------------------------------------
// Merlok, May 2011
// Many authors, that makes it possible
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// code for work with mifare cards.
//-----------------------------------------------------------------------------

#define CRYPT_NONE    0
#define CRYPT_ALL     1
#define CRYPT_REQUEST 2
#define AUTH_FIRST    0
#define AUTH_NESTED   2

//mifare emulate states
#define MFEMUL_NOFIELD  0
#define MFEMUL_IDLE     1
#define MFEMUL_SELECT1  2
#define MFEMUL_SELECT2  3
#define MFEMUL_AUTH1    4
#define MFEMUL_AUTH2    5
#define MFEMUL_HALTED   6

//functions
uint8_t* mifare_get_bigbufptr(void);
int mifare_sendcmd_short(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t data, uint8_t* answer);
int mifare_sendcmd_shortex(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t data, uint8_t* answer, uint32_t * parptr);

int mifare_classic_auth(struct Crypto1State *pcs, uint32_t uid, \
												uint8_t blockNo, uint8_t keyType, uint64_t ui64Key, uint64_t isNested);
int mifare_classic_authex(struct Crypto1State *pcs, uint32_t uid, \
													uint8_t blockNo, uint8_t keyType, uint64_t ui64Key, uint64_t isNested, uint32_t * ntptr);
int mifare_classic_readblock(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t *blockData); 
int mifare_classic_writeblock(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t *blockData);
int mifare_classic_halt(struct Crypto1State *pcs, uint32_t uid); 

