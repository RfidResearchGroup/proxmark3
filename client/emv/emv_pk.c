/*
 * libopenemv - a library to work with EMV family of smart cards
 * Copyright (C) 2012, 2015 Dmitry Eremin-Solenikov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* For asprintf */
#define _GNU_SOURCE
#include <stdio.h>

#include "emv_pk.h"
#include "crypto.h"
#include "proxmark3.h"

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#define BCD(c) (((c) >= '0' && (c) <= '9') ? ((c) - '0') : \
		-1)

#define HEX(c) (((c) >= '0' && (c) <= '9') ? ((c) - '0') : \
		((c) >= 'A' && (c) <= 'F') ? ((c) - 'A' + 10) : \
		((c) >= 'a' && (c) <= 'f') ? ((c) - 'a' + 10) : \
		-1)

#define TOHEX(v) ((v) < 10 ? (v) + '0' : (v) - 10 + 'a')

static ssize_t emv_pk_read_bin(char *buf, unsigned char *bin, size_t size, size_t *read)
{
	size_t left = size;
	char *p = buf;
	while (*p && *p == ' ')
		p++;

	while (left > 0) {
		int c1, c2;
		c1 = HEX(*p);
		if (c1 == -1)
			return -(p - buf);
		p++;
		c2 = HEX(*p);
		if (c2 == -1)
			return -(p - buf);
		p++;
		*bin = (c1 * 16 + c2);
		bin ++;
		left --;
		if (*p == ':')
			p++;
		else if (read) {
			*read = (size - left);
			break;
		} else if (left == 0)
			break;
		else
			return -(p - buf);
	}

	while (*p && *p == ' ')
		p++;

	p--;

	return (p - buf);
}

static ssize_t emv_pk_read_ymv(char *buf, unsigned *ymv)
{
	int i;
	unsigned char temp[3];
	char *p = buf;

	*ymv = 0;

	while (*p && *p == ' ')
		p++;

	for (i = 0; i < 3; i++) {
		int c1, c2;
		c1 = BCD(*p);
		if (c1 == -1)
			return -(p - buf);
		p++;
		c2 = BCD(*p);
		if (c2 == -1)
			return -(p - buf);
		p++;
		temp[i] = (c1 * 16 + c2);
	}

	while (*p && *p == ' ')
		p++;

	p--;

	if (temp[1] > 0x12 || temp[2] > 0x31)
		return -(p - buf);

	*ymv = (temp[0] * 0x10000 + temp[1] * 0x100 + temp[2]);

	return (p - buf);
}

static ssize_t emv_pk_read_string(char *buf, char *str, size_t size)
{
	char *p = buf;
	while (*p && *p == ' ')
		p++;

	while (size > 1) {
		if (*p == ' ')
			break;
		else if (*p < 0x20 || *p >= 0x7f)
			return -(p - buf);
		*str = *p;
		p++;
		str ++;
		size --;
	}

	*str = 0;

	while (*p && *p == ' ')
		p++;

	p--;

	return (p - buf);
}


struct emv_pk *emv_pk_parse_pk(char *buf)
{
	struct emv_pk *r = calloc(1, sizeof(*r));
	ssize_t l;
	char temp[10];

	l = emv_pk_read_bin(buf, r->rid, 5, NULL);
	if (l <= 0)
		goto out;
	buf += l;

	l = emv_pk_read_bin(buf, &r->index, 1, NULL);
	if (l <= 0)
		goto out;
	buf += l;

	l = emv_pk_read_ymv(buf, &r->expire);
	if (l <= 0)
		goto out;
	buf += l;

	l = emv_pk_read_string(buf, temp, sizeof(temp));
	if (l <= 0)
		goto out;
	buf += l;

	if (!strcmp(temp, "rsa"))
		r->pk_algo = PK_RSA;
	else
		goto out;

	l = emv_pk_read_bin(buf, r->exp, sizeof(r->exp), &r->elen);
	if (l <= 0)
		goto out;
	buf += l;

	r->modulus = malloc(2048/8);
	l = emv_pk_read_bin(buf, r->modulus, 2048/8, &r->mlen);
	if (l <= 0)
		goto out2;
	buf += l;

	l = emv_pk_read_string(buf, temp, sizeof(temp));
	if (l <= 0)
		goto out2;
	buf += l;

	if (!strcmp(temp, "sha1"))
		r->hash_algo = HASH_SHA_1;
	else
		goto out2;

	l = emv_pk_read_bin(buf, r->hash, 20, NULL);
	if (l <= 0)
		goto out2;

	return r;

out2:
	free(r->modulus);
out:
	free(r);
	return NULL;
}

static size_t emv_pk_write_bin(char *out, size_t outlen, const unsigned char *buf, size_t len)
{
	int i;
	size_t pos = 0;

	if (len == 0)
		return 0;
	if (outlen < len * 3)
		return 0;

	out[pos++] = TOHEX(buf[0] >> 4);
	out[pos++] = TOHEX(buf[0] & 0xf);
	for (i = 1; i < len; i++) {
		out[pos++] = ':';
		out[pos++] = TOHEX(buf[i] >> 4);
		out[pos++] = TOHEX(buf[i] & 0xf);
	}
	out[pos++] = ' ';

	return pos;
}

static size_t emv_pk_write_str(char *out, size_t outlen, const char *str)
{
	size_t len = strlen(str);

	if (len == 0)
		return 0;
	if (outlen < len)
		return 0;

	memcpy(out, str, len);

	return len;
}

char *emv_pk_dump_pk(const struct emv_pk *pk)
{
	size_t outsize = 1024; /* should be enough */
	char *out = malloc(outsize); /* should be enough */
	size_t outpos = 0;
	size_t rc;

	if (!out)
		return NULL;

	rc = emv_pk_write_bin(out + outpos, outsize - outpos, pk->rid, 5);
	if (rc == 0)
		goto err;
	outpos += rc;

	rc = emv_pk_write_bin(out + outpos, outsize - outpos, &pk->index, 1);
	if (rc == 0)
		goto err;
	outpos += rc;

	if (outpos + 7 > outsize)
		goto err;
	out[outpos++] = TOHEX((pk->expire >> 20) & 0xf);
	out[outpos++] = TOHEX((pk->expire >> 16) & 0xf);
	out[outpos++] = TOHEX((pk->expire >> 12) & 0xf);
	out[outpos++] = TOHEX((pk->expire >> 8 ) & 0xf);
	out[outpos++] = TOHEX((pk->expire >> 4 ) & 0xf);
	out[outpos++] = TOHEX((pk->expire >> 0 ) & 0xf);
	out[outpos++] = ' ';

	if (pk->pk_algo == PK_RSA) {
		rc = emv_pk_write_str(out + outpos, outsize - outpos, "rsa");
		if (rc == 0)
			goto err;
		outpos += rc;
		out[outpos++] = ' ';
	} else {
		if (outpos + 4 > outsize)
			goto err;
		out[outpos++] = '?';
		out[outpos++] = '?';
		out[outpos++] = TOHEX(pk->pk_algo >> 4);
		out[outpos++] = TOHEX(pk->pk_algo & 0xf);
	}

	rc = emv_pk_write_bin(out + outpos, outsize - outpos, pk->exp, pk->elen);
	if (rc == 0)
		goto err;
	outpos += rc;

	rc = emv_pk_write_bin(out + outpos, outsize - outpos, pk->modulus, pk->mlen);
	if (rc == 0)
		goto err;
	outpos += rc;

	if (pk->hash_algo == HASH_SHA_1) {
		rc = emv_pk_write_str(out + outpos, outsize - outpos, "sha1");
		if (rc == 0)
			goto err;
		outpos += rc;
		out[outpos++] = ' ';
	} else {
		if (outpos + 4 > outsize)
			goto err;
		out[outpos++] = '?';
		out[outpos++] = '?';
		out[outpos++] = TOHEX(pk->pk_algo >> 4);
		out[outpos++] = TOHEX(pk->pk_algo & 0xf);
	}


	rc = emv_pk_write_bin(out + outpos, outsize - outpos, pk->hash, 20);
	if (rc == 0)
		goto err;
	outpos += rc;

	out[outpos-1] = '\0';

	return out;

err:
	free(out);
	return NULL;
}

bool emv_pk_verify(const struct emv_pk *pk)
{
	struct crypto_hash *ch = crypto_hash_open(pk->hash_algo);
	if (!ch)
		return false;

	crypto_hash_write(ch, pk->rid, sizeof(pk->rid));
	crypto_hash_write(ch, &pk->index, 1);
	crypto_hash_write(ch, pk->modulus, pk->mlen);
	crypto_hash_write(ch, pk->exp, pk->elen);

	unsigned char *h = crypto_hash_read(ch);
	if (!h) {
		crypto_hash_close(ch);
		return false;
	}

	size_t hsize = crypto_hash_get_size(ch);
	bool r = hsize && !memcmp(h, pk->hash, hsize) ? true : false;

	crypto_hash_close(ch);

	return r;
}

struct emv_pk *emv_pk_new(size_t modlen, size_t explen)
{
	struct emv_pk *pk;

	/* Not supported ATM */
	if (explen > 3)
		return NULL;

	pk = calloc(1, sizeof(*pk));
	if (!pk)
		return NULL;

	pk->mlen = modlen;
	pk->elen = explen;

	pk->modulus = calloc(modlen, 1);
	if (!pk->modulus) {
		free(pk);
		pk = NULL;
	}

	return pk;
}

void emv_pk_free(struct emv_pk *pk)
{
	if (!pk)
		return;

	free(pk->modulus);
	free(pk);
}

static struct emv_pk *emv_pk_get_ca_pk_from_file(const char *fname,
		const unsigned char *rid,
		unsigned char idx)
{
	if  (!fname)
		return NULL;

	FILE *f = fopen(fname, "r");
	if (!f) {
		perror("fopen");
		return NULL;
	}

	while (!feof(f)) {
		char buf[2048];
		if (fgets(buf, sizeof(buf), f) == NULL)
			break;

		struct emv_pk *pk = emv_pk_parse_pk(buf);
		if (!pk)
			continue;
		if (memcmp(pk->rid, rid, 5) || pk->index != idx) {
			emv_pk_free(pk);
			continue;
		}

		fclose(f);

		return pk;
	}

	fclose(f);

	return NULL;
}

char *emv_pk_get_ca_pk_file(const char *dirname, const unsigned char *rid, unsigned char idx)
{
	if (!dirname)
		dirname = ".";//openemv_config_get_str("capk.dir", NULL);

	if (!dirname)
		return NULL;

	char *filename;
	int ret = asprintf(&filename, "%s/%02hhx%02hhx%02hhx%02hhx%02hhx_%02hhx.0",
			dirname,
			rid[0],
			rid[1],
			rid[2],
			rid[3],
			rid[4],
			idx);

	if (ret <= 0)
		return NULL;

	return filename;
}

char *emv_pk_get_ca_pk_rid_file(const char *dirname, const unsigned char *rid)
{
	if (!dirname)
		dirname = "."; //openemv_config_get_str("capk.dir", NULL);

	if (!dirname)
		return NULL;

	char *filename;
	int ret = asprintf(&filename, "%s/%02hhx%02hhx%02hhx%02hhx%02hhx.pks",
			dirname,
			rid[0],
			rid[1],
			rid[2],
			rid[3],
			rid[4]);

	if (ret <= 0)
		return NULL;

	return filename;
}

struct emv_pk *emv_pk_get_ca_pk(const unsigned char *rid, unsigned char idx)
{
	struct emv_pk *pk = NULL;

/*	if (!pk) {
		char *fname = emv_pk_get_ca_pk_file(NULL, rid, idx);
		if (fname) {
			pk = emv_pk_get_ca_pk_from_file(fname, rid, idx);
			free(fname);
		}
	}

	if (!pk) {
		char *fname = emv_pk_get_ca_pk_rid_file(NULL, rid);
		if (fname) {
			pk = emv_pk_get_ca_pk_from_file(fname, rid, idx);
			free(fname);
		}
	}
*/
	if (!pk) {
		const char *relfname = "emv/capk.txt"; 

		char fname[strlen(get_my_executable_directory()) + strlen(relfname) + 1];
		strcpy(fname, get_my_executable_directory());
		strcat(fname, relfname);

		pk = emv_pk_get_ca_pk_from_file(fname, rid, idx);
	}
	if (!pk)
		return NULL;

	printf("Verifying CA PK for %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx %zd bits...",
				pk->rid[0],
				pk->rid[1],
				pk->rid[2],
				pk->rid[3],
				pk->rid[4],
				pk->index,
				pk->mlen * 8);
	if (emv_pk_verify(pk)) {
		printf("OK\n");

		return pk;
	}

	printf("Failed!\n");
	emv_pk_free(pk);

	return NULL;
}
