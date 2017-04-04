/*
 * Copyright (C) 2005-2007, 2009, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef ISC_SHA3_H
#define ISC_SHA3_H

#include <isc/lang.h>
#include <isc/platform.h>
#include <isc/types.h>

/*** SHA3-256/384/512 Various Length Definitions ***********************/

#define ISC_SHA3_256_BLOCK_LENGTH		64U
#define ISC_SHA3_256_DIGESTLENGTH	32U
#define ISC_SHA3_256_DIGESTSTRINGLENGTH	(ISC_SHA3_256_DIGESTLENGTH * 2 + 1)
#define ISC_SHA3_384_BLOCK_LENGTH		128
#define ISC_SHA3_384_DIGESTLENGTH	48U
#define ISC_SHA3_384_DIGESTSTRINGLENGTH	(ISC_SHA3_384_DIGESTLENGTH * 2 + 1)
#define ISC_SHA3_512_BLOCK_LENGTH		128U
#define ISC_SHA3_512_DIGESTLENGTH	64U
#define ISC_SHA3_512_DIGESTSTRINGLENGTH	(ISC_SHA3_512_DIGESTLENGTH * 2 + 1)

/*** SHA3-256/384/512 Context Structures *******************************/

/* 'Words' here refers to isc_uint64_t */
#define ISC_SHA3_KECCAK_SPONGE_WORDS \
	(((1600)/8/*bits to byte*/)/sizeof(isc_uint64_t))

typedef struct {
    isc_uint64_t saved;         /* the portion of the input message that we
                                 * didn't consume yet */
    union {                     /* Keccak's state */
        isc_uint64_t s[ISC_SHA3_KECCAK_SPONGE_WORDS];
        isc_uint8_t sb[ISC_SHA3_KECCAK_SPONGE_WORDS * 8];
    };
    unsigned int byteIndex;     /* 0..7--the next byte after the set one
                                 * (starts from 0; 0--none are buffered) */
    unsigned int wordIndex;     /* 0..24--the next word to integrate input
                                 * (starts from 0) */
    unsigned int capacityWords; /* the double size of the hash output in
                                 * words (e.g. 16 for Keccak 512) */
} isc_sha3_t;

typedef isc_sha3_t isc_sha3_256_t;
typedef isc_sha3_t isc_sha3_384_t;
typedef isc_sha3_t isc_sha3_512_t;

ISC_LANG_BEGINDECLS

/*** SHA3-256/384/512 Function Prototypes ******************************/

void isc_sha3_256_init (isc_sha3_256_t *);
void isc_sha3_256_invalidate (isc_sha3_256_t *);
void isc_sha3_256_update (isc_sha3_256_t *, const isc_uint8_t *, size_t);
void isc_sha3_256_final (isc_uint8_t[ISC_SHA3_256_DIGESTLENGTH], isc_sha3_256_t *);
char *isc_sha3_256_end (isc_sha3_256_t *, char[ISC_SHA3_256_DIGESTSTRINGLENGTH]);
char *isc_sha3_256_data (const isc_uint8_t *, size_t, char[ISC_SHA3_256_DIGESTSTRINGLENGTH]);

void isc_sha3_384_init (isc_sha3_384_t *);
void isc_sha3_384_invalidate (isc_sha3_384_t *);
void isc_sha3_384_update (isc_sha3_384_t *, const isc_uint8_t *, size_t);
void isc_sha3_384_final (isc_uint8_t[ISC_SHA3_384_DIGESTLENGTH], isc_sha3_384_t *);
char *isc_sha3_384_end (isc_sha3_384_t *, char[ISC_SHA3_384_DIGESTSTRINGLENGTH]);
char *isc_sha3_384_data (const isc_uint8_t *, size_t, char[ISC_SHA3_384_DIGESTSTRINGLENGTH]);

void isc_sha3_512_init (isc_sha3_512_t *);
void isc_sha3_512_invalidate (isc_sha3_512_t *);
void isc_sha3_512_update (isc_sha3_512_t *, const isc_uint8_t *, size_t);
void isc_sha3_512_final (isc_uint8_t[ISC_SHA3_512_DIGESTLENGTH], isc_sha3_512_t *);
char *isc_sha3_512_end (isc_sha3_512_t *, char[ISC_SHA3_512_DIGESTSTRINGLENGTH]);
char *isc_sha3_512_data (const isc_uint8_t *, size_t, char[ISC_SHA3_512_DIGESTSTRINGLENGTH]);

ISC_LANG_ENDDECLS

#endif /* ISC_SHA3_H */
