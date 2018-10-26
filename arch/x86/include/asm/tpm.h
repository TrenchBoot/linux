/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018 Daniel P. Smith, Apertus Solutions, LLC
 *
 * The definitions in this header are extracted from the Trusted Computing
 * Group's "TPM Main Specification", Parts 1-3.
 */

#ifndef _ASM_X86_TPM_H
#define _ASM_X86_TPM_H

#include <linux/types.h>

#define TPM_HASH_ALG_SHA1    (u16)(0x0004)
#define TPM_HASH_ALG_SHA256  (u16)(0x000B)
#define TPM_HASH_ALG_SHA384  (u16)(0x000C)
#define TPM_HASH_ALG_SHA512  (u16)(0x000D)
#define TPM_HASH_ALG_SM3_256 (u16)(0x0012)



#define TPM_NO_LOCALITY		0xFF

enum tpm_hw_intf {
	TPM_DEVNODE,
	TPM_TIS,
	TPM_CRB,
	TPM_UEFI
};

enum tpm_family {
	TPM12,
	TPM20
};

struct tpmbuff;

struct tpm {
	u32 vendor;
	enum tpm_family family;
	enum tpm_hw_intf intf;
	struct tpmbuff *buff;
};

struct tpm *enable_tpm(void);
s8 tpm_request_locality(struct tpm *t, u8 l);
void tpm_relinquish_locality(struct tpm *t);
int tpm_extend_pcr(struct tpm *t, u32 pcr, u16 algo,
		u8 *digest);
void free_tpm(struct tpm *t);


/* mirroring Linux SKB */
struct tpmbuff {
	size_t truesize;
	size_t len;

	u8 locked;

	u8 *head;
	u8 *data;
	u8 *tail;
	u8 *end;
};

u8 *tpmb_reserve(struct tpmbuff *b);
void tpmb_free(struct tpmbuff *b);
u8 *tpmb_put(struct tpmbuff *b, size_t size);
size_t tpmb_trim(struct tpmbuff *b, size_t size);
size_t tpmb_size(struct tpmbuff *b);
struct tpmbuff *alloc_tpmbuff(enum tpm_hw_intf i, u8 locality);
void free_tpmbuff(struct tpmbuff *b, enum tpm_hw_intf i);


#endif
