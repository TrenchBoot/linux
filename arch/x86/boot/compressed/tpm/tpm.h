// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *      Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 */

#ifndef _TPM_H
#define _TPM_H

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

extern struct tpm *enable_tpm(void);
extern u8 tpm_request_locality(struct tpm *t, u8 l);
extern void tpm_relinquish_locality(struct tpm *t);
extern int tpm_extend_pcr(struct tpm *t, u32 pcr, u16 algo,
		u8 *digest);
extern void free_tpm(struct tpm *t);
#endif
