//-----------------------------------------------------------------------------
// Kevin Sheldrake <kev@headhacking.com>, Aug 2018
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Definitions hitag2 attack functions
//-----------------------------------------------------------------------------

bool hitag2_crack(uint8_t *response, uint8_t *nrarhex);
bool hitag2crack_find_valid_e_cmd(uint8_t e_cmd[], uint8_t nrar[]);
bool hitag2crack_find_e_page0_cmd(uint8_t keybits[], uint8_t e_firstcmd[], uint8_t nrar[], uint8_t uid[]);
bool hitag2crack_test_e_p0cmd(uint8_t *keybits, uint8_t *nrar, uint8_t *e_cmd, uint8_t *uid, uint8_t *e_uid);
void hitag2crack_xor(uint8_t *target, uint8_t *source, uint8_t *pad, unsigned int len);
bool hitag2crack_read_page(uint8_t *responsestr, uint8_t pagenum, uint8_t *nrar, uint8_t *keybits);
bool hitag2crack_send_e_cmd(uint8_t *responsestr, uint8_t *nrar, uint8_t *cmd, int len);
bool hitag2crack_tx_rx(uint8_t *responsestr, uint8_t *msg, int len, int state, bool reset);

bool hitag2crack_rng_init(uint8_t *response, uint8_t *input);
bool hitag2crack_decrypt_hex(uint8_t *response, uint8_t *hex);
bool hitag2crack_decrypt_bin(uint8_t *response, uint8_t *hex);
bool hitag2crack_encrypt_hex(uint8_t *response, uint8_t *hex);
bool hitag2crack_encrypt_bin(uint8_t *response, uint8_t *hex);

bool hitag2_keystream(uint8_t *response, uint8_t *nrarhex);
bool hitag2crack_send_auth(uint8_t *nrar);
bool hitag2crack_consume_keystream(uint8_t *keybits, int kslen, int *ksoffset, uint8_t *nrar);
bool hitag2crack_extend_keystream(uint8_t *keybits, int *kslen, int ksoffset, uint8_t *nrar, uint8_t *uid);

bool hitag2_reader(uint8_t *response, uint8_t *key, bool interactive);
