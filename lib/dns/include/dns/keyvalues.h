/*
 * Copyright (C) 1999-2001, 2003-2010, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: keyvalues.h,v 1.29 2010/12/23 23:47:08 tbox Exp $ */

#ifndef DNS_KEYVALUES_H
#define DNS_KEYVALUES_H 1

/*! \file dns/keyvalues.h */

/*
 * Flags field of the KEY RR rdata
 */
#define DNS_KEYFLAG_TYPEMASK	0xC000	/*%< Mask for "type" bits */
#define DNS_KEYTYPE_AUTHCONF	0x0000	/*%< Key usable for both */
#define DNS_KEYTYPE_CONFONLY	0x8000	/*%< Key usable for confidentiality */
#define DNS_KEYTYPE_AUTHONLY	0x4000	/*%< Key usable for authentication */
#define DNS_KEYTYPE_NOKEY	0xC000	/*%< No key usable for either; no key */
#define DNS_KEYTYPE_NOAUTH	DNS_KEYTYPE_CONFONLY
#define DNS_KEYTYPE_NOCONF	DNS_KEYTYPE_AUTHONLY

#define DNS_KEYFLAG_RESERVED2	0x2000	/*%< reserved - must be zero */
#define DNS_KEYFLAG_EXTENDED	0x1000	/*%< key has extended flags */
#define DNS_KEYFLAG_RESERVED4	0x0800	/*%< reserved - must be zero */
#define DNS_KEYFLAG_RESERVED5	0x0400	/*%< reserved - must be zero */
#define DNS_KEYFLAG_OWNERMASK	0x0300	/*%< these bits determine the type */
#define DNS_KEYOWNER_USER	0x0000	/*%< key is assoc. with user */
#define DNS_KEYOWNER_ENTITY	0x0200	/*%< key is assoc. with entity eg host */
#define DNS_KEYOWNER_ZONE	0x0100	/*%< key is zone key */
#define DNS_KEYOWNER_RESERVED	0x0300	/*%< reserved meaning */
#define DNS_KEYFLAG_REVOKE	0x0080	/*%< key revoked (per rfc5011) */
#define DNS_KEYFLAG_RESERVED9	0x0040	/*%< reserved - must be zero */
#define DNS_KEYFLAG_RESERVED10	0x0020	/*%< reserved - must be zero */
#define DNS_KEYFLAG_RESERVED11	0x0010	/*%< reserved - must be zero */
#define DNS_KEYFLAG_SIGNATORYMASK 0x000F /*%< key can sign RR's of same name */

#define DNS_KEYFLAG_RESERVEDMASK (DNS_KEYFLAG_RESERVED2 | \
				  DNS_KEYFLAG_RESERVED4 | \
				  DNS_KEYFLAG_RESERVED5 | \
				  DNS_KEYFLAG_RESERVED9 | \
				  DNS_KEYFLAG_RESERVED10 | \
				  DNS_KEYFLAG_RESERVED11 )
#define DNS_KEYFLAG_KSK		0x0001	/*%< key signing key */

#define DNS_KEYFLAG_RESERVEDMASK2 0xFFFF	/*%< no bits defined here */

/* The Algorithm field of the KEY and SIG RR's is an integer, {1..254} */
#define DNS_KEYALG_RSAMD5	1       /*%< RSA with MD5 */
#define DNS_KEYALG_RSA		DNS_KEYALG_RSAMD5
#define DNS_KEYALG_DH		2       /*%< Diffie Hellman KEY */
#define DNS_KEYALG_DSA		3       /*%< DSA KEY */
#define DNS_KEYALG_NSEC3DSA	6
#define DNS_KEYALG_DSS		DNS_ALG_DSA
#define DNS_KEYALG_ECC		4
#define DNS_KEYALG_RSASHA1	5
#define DNS_KEYALG_NSEC3RSASHA1	7
#define DNS_KEYALG_RSASHA256	8
#define DNS_KEYALG_RSASHA512	10
#define DNS_KEYALG_RSASHA2_256	247 /* XXXMUKS: update to real */
#define DNS_KEYALG_RSASHA2_512	248 /* XXXMUKS: update to real */
#define DNS_KEYALG_RSASHA3_256	249 /* XXXMUKS: update to real */
#define DNS_KEYALG_RSASHA3_384	250 /* XXXMUKS: update to real */
#define DNS_KEYALG_RSASHA3_512	251 /* XXXMUKS: update to real */
#define DNS_KEYALG_ECCGOST	12
#define DNS_KEYALG_ECDSA256	13
#define DNS_KEYALG_ECDSA384	14
#define DNS_KEYALG_INDIRECT	252
#define DNS_KEYALG_PRIVATEDNS	253
#define DNS_KEYALG_PRIVATEOID	254     /*%< Key begins with OID giving alg */

/* Protocol values  */
#define	DNS_KEYPROTO_RESERVED	0
#define DNS_KEYPROTO_TLS	1
#define DNS_KEYPROTO_EMAIL	2
#define DNS_KEYPROTO_DNSSEC	3
#define DNS_KEYPROTO_IPSEC	4
#define DNS_KEYPROTO_ANY	255

/* Signatures */
#define DNS_SIG_RSAMINBITS	512	/*%< Size of a mod or exp in bits */
#define DNS_SIG_RSAMAXBITS	2552
	/* Total of binary mod and exp */
#define DNS_SIG_RSAMAXBYTES	((DNS_SIG_RSAMAXBITS+7/8)*2+3)
	/*%< Max length of text sig block */
#define DNS_SIG_RSAMAXBASE64	(((DNS_SIG_RSAMAXBYTES+2)/3)*4)
#define DNS_SIG_RSAMINSIZE	((DNS_SIG_RSAMINBITS+7)/8)
#define DNS_SIG_RSAMAXSIZE	((DNS_SIG_RSAMAXBITS+7)/8)

#define DNS_SIG_DSASIGSIZE	41
#define DNS_SIG_DSAMINBITS	512
#define DNS_SIG_DSAMAXBITS	1024
#define DNS_SIG_DSAMINBYTES	213
#define DNS_SIG_DSAMAXBYTES	405

#define DNS_SIG_GOSTSIGSIZE	64

#define DNS_SIG_ECDSA256SIZE	64
#define DNS_SIG_ECDSA384SIZE	96

#define DNS_KEY_ECDSA256SIZE	64
#define DNS_KEY_ECDSA384SIZE	96

#endif /* DNS_KEYVALUES_H */
