#ifndef PROTOCOL_H
#define PROTOCOL_H

#define ISO14443A_CMD_READBLOCK  0x30
#define ISO14443A_CMD_WRITEBLOCK 0xA0

#define MIFARE_AUTH_KEYA        0x60
#define MIFARE_AUTH_KEYB        0x61
#define MIFARE_CMD_DEC          0xC0
#define MIFARE_CMD_INC          0xC1
#define MIFARE_CMD_RESTORE      0xC2
#define MIFARE_CMD_TRANSFER     0xB0

// mifare 4bit card answers
#define CARD_ACK      0x0A  // 1010 - ACK
#define CARD_NACK_NA  0x04  // 0100 - NACK, not allowed (command not allowed)
#define CARD_NACK_TR  0x05  // 0101 - NACK, transmission error

#endif
// PROTOCOL_H
