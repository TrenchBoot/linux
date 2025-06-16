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

#ifndef __TPM1_STRUCTS_H__
#define __TPM1_STRUCTS_H__

struct	stclear_flags_t {
	__be16	tag;
	u8	deactivated;
	u8	disableForceClear;
	u8	physicalPresence;
	u8	physicalPresenceLock;
	u8	bGlobalLock;
} __packed;

struct tpm1_version {
	u8 major;
	u8 minor;
	u8 rev_major;
	u8 rev_minor;
} __packed;

struct tpm1_version2 {
	__be16 tag;
	struct tpm1_version version;
} __packed;

struct	timeout_t {
	__be32	a;
	__be32	b;
	__be32	c;
	__be32	d;
} __packed;

struct duration_t {
	__be32	tpm_short;
	__be32	tpm_medium;
	__be32	tpm_long;
} __packed;

struct permanent_flags_t {
	__be16	tag;
	u8	disable;
	u8	ownership;
	u8	deactivated;
	u8	readPubek;
	u8	disableOwnerClear;
	u8	allowMaintenance;
	u8	physicalPresenceLifetimeLock;
	u8	physicalPresenceHWEnable;
	u8	physicalPresenceCMDEnable;
	u8	CEKPUsed;
	u8	TPMpost;
	u8	TPMpostLock;
	u8	FIPS;
	u8	operator;
	u8	enableRevokeEK;
	u8	nvLocked;
	u8	readSRKPub;
	u8	tpmEstablished;
	u8	maintenanceDone;
	u8	disableFullDALogicInfo;
} __packed;

typedef union {
	struct	permanent_flags_t perm_flags;
	struct	stclear_flags_t	stclear_flags;
	__u8	owned;
	__be32	num_pcrs;
	struct tpm1_version version1;
	struct tpm1_version2 version2;
	__be32	manufacturer_id;
	struct timeout_t  timeout;
	struct duration_t duration;
} cap_t;

struct tpm1_get_random_out {
	__be32 rng_data_len;
	u8 rng_data[TPM_MAX_RNG_DATA];
} __packed;

#endif
