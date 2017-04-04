/*
 * Copyright (C) 2005-2007, 2009, 2011, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <config.h>

#include <isc/assertions.h>
#include <isc/platform.h>
#include <isc/sha3.h>
#include <isc/string.h>
#include <isc/util.h>

/* -------------------------------------------------------------------------
 * Works when compiled for either 32-bit or 64-bit targets, optimized for
 * 64 bit.
 *
 * Canonical implementation of Init/Update/Finalize for SHA-3 byte input.
 *
 * SHA3-256, SHA3-384, SHA-512 are implemented.
 *
 * Based on code from http://keccak.noekeon.org/ .
 *
 * I place the code that I wrote into public domain, free to use.
 *
 * I would appreciate if you give credits to this work if you used it to
 * write or test * your code.
 *
 * Aug 2015. Andrey Jivsov. crypto@brainhub.org
 * ---------------------------------------------------------------------- */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#define SHA3_TRACE( format, ...)
#define SHA3_TRACE_BUF( format, buf, l, ...)
#else
#define SHA3_TRACE(format, args...)
#define SHA3_TRACE_BUF(format, buf, l, args...)
#endif

#if defined(_MSC_VER)
#define SHA3_CONST(x) x
#else
#define SHA3_CONST(x) x##L
#endif

#ifndef SHA3_ROTL64
#define SHA3_ROTL64(x, y) \
	(((x) << (y)) | ((x) >> ((sizeof(isc_uint64_t)*8) - (y))))
#endif

static const isc_uint64_t keccakf_rndc[24] = {
    SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
    SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
    SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
    SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
    SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
    SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
    SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
    SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
    SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
    SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
};

static const unsigned keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
};

/* generally called after SHA3_KECCAK_SPONGE_WORDS-ctx->capacityWords words
 * are XORed into the state s
 */
static void
keccakf(isc_uint64_t s[25])
{
    int i, j, round;
    isc_uint64_t t, bc[5];
#define KECCAK_ROUNDS 24

    for(round = 0; round < KECCAK_ROUNDS; round++) {

	/* Theta */
	for(i = 0; i < 5; i++)
	    bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

	for(i = 0; i < 5; i++) {
	    t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
	    for(j = 0; j < 25; j += 5)
		s[j + i] ^= t;
	}

	/* Rho Pi */
	t = s[1];
	for(i = 0; i < 24; i++) {
	    j = keccakf_piln[i];
	    bc[0] = s[j];
	    s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
	    t = bc[0];
	}

	/* Chi */
	for(j = 0; j < 25; j += 5) {
	    for(i = 0; i < 5; i++)
		bc[i] = s[j + i];
	    for(i = 0; i < 5; i++)
		s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
	}

	/* Iota */
	s[0] ^= keccakf_rndc[round];
    }
}

/* *************************** Public Inteface ************************ */

static void
sha3_update(isc_sha3_t *ctx, void const *bufIn, size_t len)
{
    /* 0...7 -- how much is needed to have a word */
    unsigned old_tail = (8 - ctx->byteIndex) & 7;

    size_t words;
    unsigned tail;
    size_t i;

    const isc_uint8_t *buf = bufIn;

    SHA3_TRACE_BUF("called to update with:", buf, len);

    INSIST(ctx->byteIndex < 8);
    INSIST(ctx->wordIndex < sizeof(ctx->s) / sizeof(ctx->s[0]));

    if(len < old_tail) {	/* have no complete word or haven't started
				 * the word yet */
	SHA3_TRACE("because %d<%d, store it and return", (unsigned)len,
		(unsigned)old_tail);
	/* endian-independent code follows: */
	while (len--)
	    ctx->saved |= (isc_uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
	INSIST(ctx->byteIndex < 8);
	return;
    }

    if(old_tail) {		/* will have one word to process */
	SHA3_TRACE("completing one word with %d bytes", (unsigned)old_tail);
	/* endian-independent code follows: */
	len -= old_tail;
	while (old_tail--)
	    ctx->saved |= (isc_uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);

	/* now ready to add saved to the sponge */
	ctx->s[ctx->wordIndex] ^= ctx->saved;
	INSIST(ctx->byteIndex == 8);
	ctx->byteIndex = 0;
	ctx->saved = 0;
	if(++ctx->wordIndex ==
		(ISC_SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
	    keccakf(ctx->s);
	    ctx->wordIndex = 0;
	}
    }

    /* now work in full words directly from input */

    INSIST(ctx->byteIndex == 0);

    words = len / sizeof(isc_uint64_t);
    tail = len - words * sizeof(isc_uint64_t);

    SHA3_TRACE("have %d full words to process", (unsigned)words);

    for(i = 0; i < words; i++, buf += sizeof(isc_uint64_t)) {
	const isc_uint64_t t = (isc_uint64_t) (buf[0]) |
		((isc_uint64_t) (buf[1]) << 8 * 1) |
		((isc_uint64_t) (buf[2]) << 8 * 2) |
		((isc_uint64_t) (buf[3]) << 8 * 3) |
		((isc_uint64_t) (buf[4]) << 8 * 4) |
		((isc_uint64_t) (buf[5]) << 8 * 5) |
		((isc_uint64_t) (buf[6]) << 8 * 6) |
		((isc_uint64_t) (buf[7]) << 8 * 7);
#if defined(__x86_64__ ) || defined(__i386__)
	INSIST(memcmp(&t, buf, 8) == 0);
#endif
	ctx->s[ctx->wordIndex] ^= t;
	if(++ctx->wordIndex ==
		(ISC_SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
	    keccakf(ctx->s);
	    ctx->wordIndex = 0;
	}
    }

    SHA3_TRACE("have %d bytes left to process, save them", (unsigned)tail);

    /* finally, save the partial word */
    INSIST(ctx->byteIndex == 0 && tail < 8);
    while (tail--) {
	SHA3_TRACE("Store byte %02x '%c'", *buf, *buf);
	ctx->saved |= (isc_uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
    }
    INSIST(ctx->byteIndex < 8);
    SHA3_TRACE("Have saved=0x%016" PRIx64 " at the end", ctx->saved);
}

/* This is simply the 'update' with the padding block.
 * The padding block is 0x01 || 0x00* || 0x80. First 0x01 and last 0x80
 * bytes are always present, but they can be the same byte.
 */
static void const *
sha3_finalize(isc_sha3_t *ctx)
{
    SHA3_TRACE("called with %d bytes in the buffer", ctx->byteIndex);

    /* Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding we
     * use 1<<2 below. The 0x02 below corresponds to the suffix 01.
     * Overall, we feed 0, then 1, and finally 1 to start padding. Without
     * M || 01, we would simply use 1 to start padding. */

    /* SHA3 version */
    ctx->s[ctx->wordIndex] ^=
	    (ctx->saved ^ ((isc_uint64_t) ((isc_uint64_t) (0x02 | (1 << 2)) <<
			    ((ctx->byteIndex) * 8))));

    ctx->s[ISC_SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords - 1] ^=
	    SHA3_CONST(0x8000000000000000UL);
    keccakf(ctx->s);

    /* Return first bytes of the ctx->s. This conversion is not needed for
     * little-endian platforms e.g. wrap with #if !defined(__BYTE_ORDER__)
     * || !defined(__ORDER_LITTLE_ENDIAN__) || \
     * __BYTE_ORDER__!=__ORDER_LITTLE_ENDIAN__ ... the conversion below ...
     * #endif */
    {
	unsigned i;
	for(i = 0; i < ISC_SHA3_KECCAK_SPONGE_WORDS; i++) {
	    const unsigned t1 = (isc_uint32_t) ctx->s[i];
	    const unsigned t2 = (isc_uint32_t) ((ctx->s[i] >> 16) >> 16);
	    ctx->sb[i * 8 + 0] = (isc_uint8_t) (t1);
	    ctx->sb[i * 8 + 1] = (isc_uint8_t) (t1 >> 8);
	    ctx->sb[i * 8 + 2] = (isc_uint8_t) (t1 >> 16);
	    ctx->sb[i * 8 + 3] = (isc_uint8_t) (t1 >> 24);
	    ctx->sb[i * 8 + 4] = (isc_uint8_t) (t2);
	    ctx->sb[i * 8 + 5] = (isc_uint8_t) (t2 >> 8);
	    ctx->sb[i * 8 + 6] = (isc_uint8_t) (t2 >> 16);
	    ctx->sb[i * 8 + 7] = (isc_uint8_t) (t2 >> 24);
	}
    }

    SHA3_TRACE_BUF("Hash: (first 32 bytes)", ctx->sb, 256 / 8);

    return (ctx->sb);
}


/*** SHA3-256: *********************************************************/
void
isc_sha3_256_init(isc_sha3_256_t *context) {
	if (context == NULL)
		return;
	memset(context, 0, sizeof(*context));
	context->capacityWords = 2 * 256 / (8 * sizeof(isc_uint64_t));
}

void
isc_sha3_256_invalidate(isc_sha3_256_t *context) {
	memset(context, 0, sizeof(*context));
}

void
isc_sha3_256_update(isc_sha3_256_t *context, const isc_uint8_t *data, size_t len) {
	sha3_update(context, data, len);
}

void
isc_sha3_256_final(isc_uint8_t digest[], isc_sha3_256_t *context) {
	const void *d = sha3_finalize(context);
	memmove(digest, d, ISC_SHA3_256_DIGESTLENGTH);

	/* Clean up state data: */
	isc_sha3_256_invalidate(context);
}

/*** SHA3-384: *********************************************************/
void
isc_sha3_384_init(isc_sha3_384_t *context) {
	if (context == NULL)
		return;
	memset(context, 0, sizeof(*context));
	context->capacityWords = 2 * 384 / (8 * sizeof(isc_uint64_t));
}

void
isc_sha3_384_invalidate(isc_sha3_384_t *context) {
	memset(context, 0, sizeof(*context));
}

void
isc_sha3_384_update(isc_sha3_384_t *context, const isc_uint8_t *data, size_t len) {
	sha3_update(context, data, len);
}

void
isc_sha3_384_final(isc_uint8_t digest[], isc_sha3_384_t *context) {
	const void *d = sha3_finalize(context);
	memmove(digest, d, ISC_SHA3_384_DIGESTLENGTH);

	/* Clean up state data: */
	isc_sha3_384_invalidate(context);
}

/*** SHA3-512: *********************************************************/
void
isc_sha3_512_init(isc_sha3_512_t *context) {
	if (context == NULL)
		return;
	memset(context, 0, sizeof(*context));
	context->capacityWords = 2 * 512 / (8 * sizeof(isc_uint64_t));
}

void
isc_sha3_512_invalidate(isc_sha3_512_t *context) {
	memset(context, 0, sizeof(*context));
}

void
isc_sha3_512_update(isc_sha3_512_t *context, const isc_uint8_t *data, size_t len) {
	sha3_update(context, data, len);
}

void
isc_sha3_512_final(isc_uint8_t digest[], isc_sha3_512_t *context) {
	const void *d = sha3_finalize(context);
	memmove(digest, d, ISC_SHA3_512_DIGESTLENGTH);

	/* Clean up state data: */
	isc_sha3_512_invalidate(context);
}

/*
 * Constant used by SHA256/384/512_End() functions for converting the
 * digest to a readable hexadecimal character string:
 */
static const char *sha2_hex_digits = "0123456789abcdef";

char *
isc_sha3_256_end(isc_sha3_256_t *context, char buffer[]) {
	isc_uint8_t	digest[ISC_SHA3_256_DIGESTLENGTH], *d = digest;
	unsigned int	i;

	/* Sanity check: */
	REQUIRE(context != (isc_sha3_256_t *)0);

	if (buffer != (char*)0) {
		isc_sha3_256_final(digest, context);

		for (i = 0; i < ISC_SHA3_256_DIGESTLENGTH; i++) {
			*buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
			*buffer++ = sha2_hex_digits[*d & 0x0f];
			d++;
		}
		*buffer = (char)0;
	} else {
		memset(context, 0, sizeof(*context));
	}
	memset(digest, 0, ISC_SHA3_256_DIGESTLENGTH);
	return buffer;
}

char *
isc_sha3_256_data(const isc_uint8_t* data, size_t len,
		char digest[ISC_SHA3_256_DIGESTSTRINGLENGTH])
{
	isc_sha3_256_t context;

	isc_sha3_256_init(&context);
	isc_sha3_256_update(&context, data, len);
	return (isc_sha3_256_end(&context, digest));
}

char *
isc_sha3_512_end(isc_sha3_512_t *context, char buffer[]) {
	isc_uint8_t	digest[ISC_SHA3_512_DIGESTLENGTH], *d = digest;
	unsigned int	i;

	/* Sanity check: */
	REQUIRE(context != (isc_sha3_512_t *)0);

	if (buffer != (char*)0) {
		isc_sha3_512_final(digest, context);

		for (i = 0; i < ISC_SHA3_512_DIGESTLENGTH; i++) {
			*buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
			*buffer++ = sha2_hex_digits[*d & 0x0f];
			d++;
		}
		*buffer = (char)0;
	} else {
		memset(context, 0, sizeof(*context));
	}
	memset(digest, 0, ISC_SHA3_512_DIGESTLENGTH);
	return buffer;
}

char *
isc_sha3_512_data(const isc_uint8_t *data, size_t len,
		char digest[ISC_SHA3_512_DIGESTSTRINGLENGTH])
{
	isc_sha3_512_t	context;

	isc_sha3_512_init(&context);
	isc_sha3_512_update(&context, data, len);
	return (isc_sha3_512_end(&context, digest));
}

char *
isc_sha3_384_end(isc_sha3_384_t *context, char buffer[]) {
	isc_uint8_t	digest[ISC_SHA3_384_DIGESTLENGTH], *d = digest;
	unsigned int	i;

	/* Sanity check: */
	REQUIRE(context != (isc_sha3_384_t *)0);

	if (buffer != (char*)0) {
		isc_sha3_384_final(digest, context);

		for (i = 0; i < ISC_SHA3_384_DIGESTLENGTH; i++) {
			*buffer++ = sha2_hex_digits[(*d & 0xf0) >> 4];
			*buffer++ = sha2_hex_digits[*d & 0x0f];
			d++;
		}
		*buffer = (char)0;
	} else {
		memset(context, 0, sizeof(*context));
	}
	memset(digest, 0, ISC_SHA3_384_DIGESTLENGTH);
	return buffer;
}

char *
isc_sha3_384_data(const isc_uint8_t *data, size_t len,
		char digest[ISC_SHA3_384_DIGESTSTRINGLENGTH])
{
	isc_sha3_384_t context;

	isc_sha3_384_init(&context);
	isc_sha3_384_update(&context, data, len);
	return (isc_sha3_384_end(&context, digest));
}
