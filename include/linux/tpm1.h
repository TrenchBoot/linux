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
#ifndef __LINUX_TPM1_H__
#define __LINUX_TPM1_H__

/*
 * TPM 1.2 Main Specification
 * https://trustedcomputinggroup.org/resource/tpm-main-specification/
 */

/* Command TAGS */
enum tpm_command_tags {
	TPM_TAG_RQU_COMMAND		= 193,
	TPM_TAG_RQU_AUTH1_COMMAND	= 194,
	TPM_TAG_RQU_AUTH2_COMMAND	= 195,
	TPM_TAG_RSP_COMMAND		= 196,
	TPM_TAG_RSP_AUTH1_COMMAND	= 197,
	TPM_TAG_RSP_AUTH2_COMMAND	= 198,
};

/* Command Ordinals */
enum tpm_command_ordinals {
	TPM_ORD_CONTINUE_SELFTEST	= 83,
	TPM_ORD_GET_CAP			= 101,
	TPM_ORD_GET_RANDOM		= 70,
	TPM_ORD_PCR_EXTEND		= 20,
	TPM_ORD_PCR_READ		= 21,
	TPM_ORD_OSAP			= 11,
	TPM_ORD_OIAP			= 10,
	TPM_ORD_SAVESTATE		= 152,
	TPM_ORD_SEAL			= 23,
	TPM_ORD_STARTUP			= 153,
	TPM_ORD_UNSEAL			= 24,
};

/* Other constants */
#define SRKHANDLE                       0x40000000
#define TPM_NONCE_SIZE                  20
#define TPM_ST_CLEAR			1

#endif
