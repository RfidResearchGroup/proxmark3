
LIB_A = libmbedtls.a
mbedtls_SOURCES = \
	aes.c \
	asn1parse.c \
	asn1write.c \
	base64.c \
	bignum.c \
	ctr_drbg.c \
	entropy_poll.c \
	entropy.c \
	error.c \
	timing.c \
	ecp.c \
	ecp_curves.c \
	certs.c \
	camellia.c \
	blowfish.c \
	cipher_wrap.c \
	cipher.c \
	cmac.c \
	des.c \
	ecdsa.c \
	md.c \
	md_wrap.c \
	md5.c \
	oid.c \
	pem.c \
	arc4.c \
	pk.c \
	pk_wrap.c \
	pkwrite.c \
	pkcs5.c \
	pkcs12.c \
	pkparse.c \
	platform.c \
	platform_util.c \
	rsa.c \
	rsa_internal.c \
	sha1.c \
	sha256.c \
	sha512.c \
	threading.c \
	x509.c \
	x509_crl.c \
	x509_crt.c
mbedtls_LDFLAGS = \
	-no-undefined \
	-export-symbols-regex '^mbedtls_' \
	-version-info 15:0:11


CFILES = $(filter %.c, $(mbedtls_SOURCES))
CMDOBJS = $(CFILES:%.c=%.o)
CLEAN = $(CMDOBJS)

CC= gcc
CFLAGS= -O2 -Wall -Wno-unused-variable -Wno-unused-function
LDFLAGS= $(SYSLDFLAGS) $(mbedtls_LDFLAGS)
LIBS=  $(SYSLIBS) $(MYLIBS)
DEFAULT_INCLUDES = -I. -I..
DEFS = -DHAVE_STDINT_H

AR= ar rcs
RANLIB= ranlib
RM= rm -f
TST= echo

SYSLDFLAGS=
SYSLIBS=

MYLIBS=
MYOBJS=

$(LIB_A): $(CMDOBJS)
	$(AR) $(LIB_A) $(CMDOBJS)
	$(RANLIB) $(LIB_A)

all: $(LIB_A)

clean:
	$(RM) $(CLEAN)
	$(RM) $(LIB_A)

%.o: %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(CFLAGS) -c -o $@ $< $(LIBS)

.PHONY: all clean

