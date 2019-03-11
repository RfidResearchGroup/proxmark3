/*
* AES Cryptographic Algorithm Header File. Include this header file in
* your source which uses these given APIs. (This source is kept under
* public domain)
*/
#ifndef __AES_H
#define __AES_H

// AES context structure
typedef struct {
    unsigned int Ek[60];
    unsigned int Dk[60];
    unsigned int Iv[4];
    unsigned char Nr;
    unsigned char Mode;
} AesCtx;

// key length in bytes
#define KEY128 16
#define KEY192 24
#define KEY256 32
// block size in bytes
#define BLOCKSZ 16
// mode
#define EBC 0
#define CBC 1

// AES API function prototype

int AesCtxIni(AesCtx *pCtx, unsigned char *pIV, unsigned char *pKey, unsigned int KeyLen, unsigned char Mode);
int AesEncrypt(AesCtx *pCtx, unsigned char *pData, unsigned char *pCipher, unsigned int DataLen);
int AesDecrypt(AesCtx *pCtx, unsigned char *pCipher, unsigned char *pData, unsigned int CipherLen);

#endif
