#ifndef __DESFIRE_KEY_INCLUDED
#define __DESFIRE_KEY_INCLUDED

#include <stdlib.h>
#include <stdint.h>
#include "iso14443a.h"
#include "desfire.h"
//#include "mifare.h" // iso14a_card_select_t struct
void Desfire_des_key_new(const uint8_t value[8], desfirekey_t key);
void Desfire_3des_key_new(const uint8_t value[16], desfirekey_t key);
void Desfire_des_key_new_with_version(const uint8_t value[8], desfirekey_t key);
void Desfire_3des_key_new_with_version(const uint8_t value[16], desfirekey_t key);
void Desfire_3k3des_key_new(const uint8_t value[24], desfirekey_t key);
void Desfire_3k3des_key_new_with_version(const uint8_t value[24], desfirekey_t key);
void Desfire_aes_key_new(const uint8_t value[16], desfirekey_t key);
void Desfire_aes_key_new_with_version(const uint8_t value[16], uint8_t version, desfirekey_t key);
uint8_t Desfire_key_get_version(desfirekey_t key);
void Desfire_key_set_version(desfirekey_t key, uint8_t version);
void Desfire_session_key_new(const uint8_t rnda[], const uint8_t rndb[], desfirekey_t authkey, desfirekey_t key);
#endif
