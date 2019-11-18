/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOOT_COMPRESSED_EARLY_SHA1_H
#define BOOT_COMPRESSED_EARLY_SHA1_H

/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 */

#include <crypto/sha.h>

void early_sha1_init(struct sha1_state *sctx);
void early_sha1_update(struct sha1_state *sctx,
		       const u8 *data,
		       unsigned int len);
void early_sha1_final(struct sha1_state *sctx, u8 *out);

#endif /* BOOT_COMPRESSED_EARLY_SHA1_H */
