/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004,2007,2008 IBM Corporation
 *
 * Authors:
 * Leendert van Doorn <leendert@watson.ibm.com>
 * Dave Safford <safford@watson.ibm.com>
 * Reiner Sailer <sailer@watson.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 * Debora Velarde <dvelarde@us.ibm.com>
 *
 * Maintained by: <tpmdd_devel@lists.sourceforge.net>
 *
 * Device driver for TCG/TCPA TPM (trusted platform module).
 * Specifications at www.trustedcomputinggroup.org
 */
#ifndef __LINUX_TPM_COMMON_H__
#define __LINUX_TPM_COMMON_H__

#define TPM_MAX_ORDINAL 243

#define TPM_DIGEST_SIZE		20	/* Max TPM v1.2 PCR size */
#define TPM_HEADER_SIZE		10
#define TPM_BUFSIZE		4096

#define TPM2_PLATFORM_PCR	24
#define TPM2_PCR_SELECT_MIN	3
#define TPM2_MAX_DIGEST_SIZE	SHA512_DIGEST_SIZE
#define TPM2_MAX_BANKS		4

/* if you add a new hash to this, increment TPM_MAX_HASHES below */
enum tpm_algorithms {
	TPM_ALG_ERROR		= 0x0000,
	TPM_ALG_SHA1		= 0x0004,
	TPM_ALG_AES		= 0x0006,
	TPM_ALG_KEYEDHASH	= 0x0008,
	TPM_ALG_SHA256		= 0x000B,
	TPM_ALG_SHA384		= 0x000C,
	TPM_ALG_SHA512		= 0x000D,
	TPM_ALG_NULL		= 0x0010,
	TPM_ALG_SM3_256		= 0x0012,
	TPM_ALG_ECC		= 0x0023,
	TPM_ALG_CFB		= 0x0043,
};

/*
 * The locality (0 - 4) for a TPM, as defined in section 3.2 of the
 * Client Platform Profile Specification.
 */
enum tpm_localities {
	TPM_LOCALITY_0		= 0, /* Static RTM */
	TPM_LOCALITY_1		= 1, /* Dynamic OS */
	TPM_LOCALITY_2		= 2, /* DRTM Environment */
	TPM_LOCALITY_3		= 3, /* Aux Components */
	TPM_LOCALITY_4		= 4, /* CPU DRTM Establishment */
	TPM_MAX_LOCALITY	= TPM_LOCALITY_4
};

/*
 * Structure to represent active PCR algorithm banks usable by the
 * TPM.
 */
struct tpm_bank_info {
	u16 alg_id;
	u16 digest_size;
	u16 crypto_id;
};

/*
 * 128 bytes is an arbitrary cap. This could be as large as TPM_BUFSIZE - 18
 * bytes, but 128 is still a relatively large number of random bytes and
 * anything much bigger causes users of struct tpm_cmd_t to start getting
 * compiler warnings about stack frame size.
 */
#define TPM_MAX_RNG_DATA	128

/*
 * maximum number of hashing algorithms a TPM can have.  This is
 * basically a count of every hash in tpm_algorithms above
 */
#define TPM_MAX_HASHES	5

struct tpm_digest {
	u16 alg_id;
	u8 digest[TPM2_MAX_DIGEST_SIZE];
} __packed;

#define TPM_HEADER_SIZE		10

struct tpm_header {
	__be16 tag;
	__be32 length;
	union {
		__be32 ordinal;
		__be32 return_code;
	};
} __packed;

#endif
