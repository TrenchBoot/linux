/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004 IBM Corporation
 * Copyright (C) 2015 Intel Corporation
 *
 * Authors:
 * Leendert van Doorn <leendert@watson.ibm.com>
 * Dave Safford <safford@watson.ibm.com>
 * Reiner Sailer <sailer@watson.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 *
 * Maintained by: <tpmdd-devel@lists.sourceforge.net>
 *
 * Device driver for TCG/TCPA TPM (trusted platform module).
 * Specifications at www.trustedcomputinggroup.org
 */

#ifndef __TPM2_STRUCTS_H__
#define __TPM2_STRUCTS_H__

struct tpm2_pcr_read_out {
	__be32	update_cnt;
	__be32	pcr_selects_cnt;
	__be16	hash_alg;
	u8	pcr_select_size;
	u8	pcr_select[TPM2_PCR_SELECT_MIN];
	__be32	digests_cnt;
	__be16	digest_size;
	u8	digest[];
} __packed;

struct tpm2_get_random_out {
	__be16 size;
	u8 buffer[TPM_MAX_RNG_DATA];
} __packed;

struct tpm2_get_cap_out {
	u8 more_data;
	__be32 subcap_id;
	__be32 property_cnt;
	__be32 property_id;
	__be32 value;
} __packed;

struct tpm2_pcr_selection {
	__be16  hash_alg;
	u8  size_of_select;
	u8  pcr_select[3];
} __packed;

struct tpm2_context {
	__be64 sequence;
	__be32 saved_handle;
	__be32 hierarchy;
	__be16 blob_size;
} __packed;

#endif
