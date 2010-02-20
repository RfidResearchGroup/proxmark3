/*
 * Hitag2 emulation
 *
 * Contains state and functions for an emulated Hitag2 tag. Offers an entry
 * point to handle commands, needs a callback to send response.
 *
 * (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
 */

#include "proxmark3.h"
#include <stdint.h>

#include "apps.h"
#include "hitag2.h"

struct hitag2_cipher_state {
	uint64_t state;
};

struct hitag2_tag {
	uint32_t uid;
	enum {
		TAG_STATE_RESET,          // Just powered up, awaiting GetSnr
		TAG_STATE_ACTIVATING,     // In activation phase (password mode), sent UID, awaiting reader password
		TAG_STATE_AUTHENTICATING, // In activation phase (crypto mode), awaiting reader authentication
		TAG_STATE_ACTIVATED,      // Activation complete, awaiting read/write commands
		TAG_STATE_WRITING,        // In write command, awaiting sector contents to be written
	} state;
	unsigned int active_sector;
	char crypto_active;
	struct hitag2_cipher_state cs;
	char sectors[8][4];
};

static void hitag2_cipher_reset(struct hitag2_tag *tag, const char *challenge);
static int hitag2_cipher_authenticate(struct hitag2_cipher_state *cs, const char *authenticator);
static int hitag2_cipher_transcrypt(struct hitag2_cipher_state *cs, char *data, unsigned int bytes, unsigned int bits);

static struct hitag2_tag tag;
static const struct hitag2_tag resetdata = {
		.state = TAG_STATE_RESET,
		.sectors = {                                     // Password mode:               | Crypto mode:
				[0] = { 0x35, 0x33, 0x70, 0x11}, // UID                          | UID
				[1] = { 0x4d, 0x49, 0x4b, 0x52}, // Password RWD                 | 32 bit LSB key
				[2] = { 0x20, 0xf0, 0x4f, 0x4e}, // Reserved                     | 16 bit MSB key, 16 bit reserved
				[3] = { 0x0e, 0xaa, 'H', 'T'},   // Configuration, password TAG  | Configuration, password TAG
		},
};

int hitag2_reset(void)
{
	tag.state = TAG_STATE_RESET;
	tag.crypto_active = 0;
	return 0;
}

int hitag2_init(void)
{
	memcpy(&tag, &resetdata, sizeof(tag));
	hitag2_reset();
	return 0;
}

int hitag2_handle_command(const char* data, const int length, hitag2_response_callback_t cb, void *cb_cookie)
{
	(void)data; (void)length; (void)cb; (void)cb_cookie;
	int retry = 0, done = 0, result=0;
	char temp[10];

	if(tag.crypto_active && length < sizeof(temp)*8) {
		/* Decrypt command */
		memcpy(temp, data, (length+7)/8);
		hitag2_cipher_transcrypt(&(tag.cs), temp, length/8, length%8);
		data = temp;
	}


handle_command_retry:
	switch(tag.state) {
	case TAG_STATE_RESET:
		if(length == 5 && data[0] == 0xC0) {
			/* Received 11000 from the reader, request for UID, send UID */
			result=cb(tag.sectors[0], sizeof(tag.sectors[0])*8, 208, cb_cookie);
			done=1;
			if(tag.sectors[3][0] & 0x08) {
				tag.state=TAG_STATE_AUTHENTICATING;
			} else {
				tag.state=TAG_STATE_ACTIVATING;
			}
		}
		break;
	case TAG_STATE_ACTIVATING:
		if(length == 0x20) {
			/* Received RWD password, respond with configuration and our password */
			result=cb(tag.sectors[3], sizeof(tag.sectors[3])*8, 208, cb_cookie);
			done=1;
			tag.state=TAG_STATE_ACTIVATED;
		}
		break;
	case TAG_STATE_AUTHENTICATING:
		if(length == 0x40) {
			/* Received initialisation vector || authentication token, fire up cipher, send our password */
			hitag2_cipher_reset(&tag, data);
			if(hitag2_cipher_authenticate(&(tag.cs), data+4)) {
				char response_enc[4];
				memcpy(response_enc, tag.sectors[3], 4);
				hitag2_cipher_transcrypt(&(tag.cs), response_enc, 4, 0);
				result=cb(response_enc, 4*8, 208, cb_cookie);
				done=1;
				tag.crypto_active = 1;
				tag.state = TAG_STATE_ACTIVATED;
			} else {
				/* The reader failed to authenticate, do nothing */
				DbpString("Reader authentication failed");
			}
		}
		break;
	case TAG_STATE_ACTIVATED:
		if(length == 10) {
			if( ((data[0] & 0xC0) == 0xC0) && ((data[0] & 0x06) == 0) ) {
				/* Read command: 11xx x00y  yy with yyy == ~xxx, xxx is sector number */
				unsigned int sector = (~( ((data[0]<<2)&0x04) | ((data[1]>>6)&0x03) ) & 0x07);
				if(sector == ( (data[0]>>3)&0x07 ) ) {
					memcpy(temp, tag.sectors[sector], 4);
					if(tag.crypto_active) {
						hitag2_cipher_transcrypt(&(tag.cs), temp, 4, 0);
					}
					/* Respond with contents of sector sector */
					result = cb(temp, 4*8, 208, cb_cookie);
					done=1;
				} else {
					/* transmission error */
					DbpString("Transmission error (read) in activated state");
				}
			} else if( ((data[0] & 0xC0) == 0x80) && ((data[0] & 0x06) == 2) ) {
				/* Write command: 10xx x01y  yy with yyy == ~xxx, xxx is sector number */
				unsigned int sector = (~( ((data[0]<<2)&0x04) | ((data[1]>>6)&0x03) ) & 0x07);
				if(sector == ( (data[0]>>3)&0x07 ) ) {
					/* Prepare write, acknowledge by repeating command */
					if(tag.crypto_active) {
						hitag2_cipher_transcrypt(&(tag.cs), temp, length/8, length%8);
					}
					result = cb(data, length, 208, cb_cookie);
					done=1;
					tag.active_sector = sector;
					tag.state=TAG_STATE_WRITING;
				} else {
					/* transmission error */
					DbpString("Transmission error (write) in activated state");
				}
			}

		}
	case TAG_STATE_WRITING:
		if(length == 32) {
			/* These are the sector contents to be written. We don't have to do anything else. */
			memcpy(tag.sectors[tag.active_sector], data, length/8);
			tag.state=TAG_STATE_ACTIVATED;
			done=1;
		}
	}

	if(!done && !retry) {
		/* We didn't respond, maybe our state is faulty. Reset and try again. */
		retry=1;
		if(tag.crypto_active) {
			/* Restore undeciphered data */
			memcpy(temp, data, (length+7)/8);
		}
		hitag2_reset();
		goto handle_command_retry;
	}

	return result;
}

/* Following is a modified version of cryptolib.com/ciphers/hitag2/ */
// Software optimized 48-bit Philips/NXP Mifare Hitag2 PCF7936/46/47/52 stream cipher algorithm by I.C. Wiener 2006-2007.
// For educational purposes only.
// No warranties or guarantees of any kind.
// This code is released into the public domain by its author.

// Basic macros:

#define u8				uint8_t
#define u32				uint32_t
#define u64				uint64_t
#define rev8(x)			((((x)>>7)&1)+((((x)>>6)&1)<<1)+((((x)>>5)&1)<<2)+((((x)>>4)&1)<<3)+((((x)>>3)&1)<<4)+((((x)>>2)&1)<<5)+((((x)>>1)&1)<<6)+(((x)&1)<<7))
#define rev16(x)		(rev8 (x)+(rev8 (x>> 8)<< 8))
#define rev32(x)		(rev16(x)+(rev16(x>>16)<<16))
#define rev64(x)		(rev32(x)+(rev32(x>>32)<<32))
#define bit(x,n)		(((x)>>(n))&1)
#define bit32(x,n)		((((x)[(n)>>5])>>((n)))&1)
#define inv32(x,i,n)	((x)[(i)>>5]^=((u32)(n))<<((i)&31))
#define rotl64(x, n)	((((u64)(x))<<((n)&63))+(((u64)(x))>>((0-(n))&63)))

// Single bit Hitag2 functions:

#define i4(x,a,b,c,d)	((u32)((((x)>>(a))&1)+(((x)>>(b))&1)*2+(((x)>>(c))&1)*4+(((x)>>(d))&1)*8))

static const u32 ht2_f4a = 0x2C79;		// 0010 1100 0111 1001
static const u32 ht2_f4b = 0x6671;		// 0110 0110 0111 0001
static const u32 ht2_f5c = 0x7907287B;	// 0111 1001 0000 0111 0010 1000 0111 1011

static u32 _f20 (const u64 x)
{
	u32					i5;

	i5 = ((ht2_f4a >> i4 (x, 1, 2, 4, 5)) & 1)* 1
	   + ((ht2_f4b >> i4 (x, 7,11,13,14)) & 1)* 2
	   + ((ht2_f4b >> i4 (x,16,20,22,25)) & 1)* 4
	   + ((ht2_f4b >> i4 (x,27,28,30,32)) & 1)* 8
	   + ((ht2_f4a >> i4 (x,33,42,43,45)) & 1)*16;

	return (ht2_f5c >> i5) & 1;
}

static u64 _hitag2_init (const u64 key, const u32 serial, const u32 IV)
{
	u32					i;
	u64					x = ((key & 0xFFFF) << 32) + serial;

	for (i = 0; i < 32; i++)
	{
		x >>= 1;
		x += (u64) (_f20 (x) ^ (((IV >> i) ^ (key >> (i+16))) & 1)) << 47;
	}
	return x;
}

static u64 _hitag2_round (u64 *state)
{
	u64					x = *state;

	x = (x >>  1) +
	 ((((x >>  0) ^ (x >>  2) ^ (x >>  3) ^ (x >>  6)
	  ^ (x >>  7) ^ (x >>  8) ^ (x >> 16) ^ (x >> 22)
	  ^ (x >> 23) ^ (x >> 26) ^ (x >> 30) ^ (x >> 41)
	  ^ (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)) & 1) << 47);

	*state = x;
	return _f20 (x);
}

static u32 _hitag2_byte (u64 * x)
{
	u32					i, c;

	for (i = 0, c = 0; i < 8; i++) c += (u32) _hitag2_round (x) << (i^7);
	return c;
}


/* Cipher/tag glue code: */

static void hitag2_cipher_reset(struct hitag2_tag *tag, const char *iv)
{
	uint64_t key = ((uint64_t)tag->sectors[2][2]) |
			((uint64_t)tag->sectors[2][3] << 8) |
			((uint64_t)tag->sectors[1][0] << 16) |
			((uint64_t)tag->sectors[1][1] << 24) |
			((uint64_t)tag->sectors[1][2] << 32) |
			((uint64_t)tag->sectors[1][3] << 40);
	uint32_t uid = ((uint32_t)tag->sectors[0][0]) |
			((uint32_t)tag->sectors[0][1] << 8) |
			((uint32_t)tag->sectors[0][2] << 16) |
			((uint32_t)tag->sectors[0][3] << 24);
	uint32_t iv_ = (((uint32_t)(iv[0]))) |
			(((uint32_t)(iv[1])) << 8) |
			(((uint32_t)(iv[2])) << 16) |
			(((uint32_t)(iv[3])) << 24);
	tag->cs.state = _hitag2_init(rev64(key), rev32(uid), rev32(iv_));
}

static int hitag2_cipher_authenticate(struct hitag2_cipher_state *cs, const char *authenticator_is)
{
	char authenticator_should[4];
	authenticator_should[0] = ~_hitag2_byte(&(cs->state));
	authenticator_should[1] = ~_hitag2_byte(&(cs->state));
	authenticator_should[2] = ~_hitag2_byte(&(cs->state));
	authenticator_should[3] = ~_hitag2_byte(&(cs->state));
	return memcmp(authenticator_should, authenticator_is, 4) == 0;
}

static int hitag2_cipher_transcrypt(struct hitag2_cipher_state *cs, char *data, unsigned int bytes, unsigned int bits)
{
	int i;
	for(i=0; i<bytes; i++) data[i] ^= _hitag2_byte(&(cs->state));
	for(i=0; i<bits; i++) data[bytes] ^= _hitag2_round(&(cs->state)) << (7-i);
	return 0;
}
