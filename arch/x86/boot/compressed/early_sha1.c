// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/string.h>
#include <asm/sha1.h>
#include <asm/boot.h>
#include <asm/unaligned.h>

#define SHA1_DISABLE_EXPORT
#include "../../../../lib/sha1.c"

static void early_sha1_block_fn(struct sha1_state *sst, u8 const *src,
				int blocks)
{
	u32 temp[SHA_WORKSPACE_WORDS];

	while (blocks--) {
		sha_transform(sst->state, src, temp);
		src += SHA1_BLOCK_SIZE;
	}
	memset(temp, 0, sizeof(temp));
	/*
	 * As this is cryptographic code, prevent the memset 0 from being
	 * optimized out potentially leaving secrets in memory.
	 */
	wmb();
}

void early_sha1_init(struct sha1_state *sctx)
{
	sctx->state[0] = SHA1_H0;
	sctx->state[1] = SHA1_H1;
	sctx->state[2] = SHA1_H2;
	sctx->state[3] = SHA1_H3;
	sctx->state[4] = SHA1_H4;
	sctx->count = 0;
}

void early_sha1_update(struct sha1_state *sctx,
		       const u8 *data,
		       unsigned int len)
{
	unsigned int partial = sctx->count % SHA1_BLOCK_SIZE;

	sctx->count += len;

	if (unlikely((partial + len) >= SHA1_BLOCK_SIZE)) {
		int blocks;

		if (partial) {
			int p = SHA1_BLOCK_SIZE - partial;

			memcpy(sctx->buffer + partial, data, p);
			data += p;
			len -= p;

			early_sha1_block_fn(sctx, sctx->buffer, 1);
		}

		blocks = len / SHA1_BLOCK_SIZE;
		len %= SHA1_BLOCK_SIZE;

		if (blocks) {
			early_sha1_block_fn(sctx, data, blocks);
			data += blocks * SHA1_BLOCK_SIZE;
		}
		partial = 0;
	}

	if (len)
		memcpy(sctx->buffer + partial, data, len);
}

void early_sha1_finalize(struct sha1_state *sctx)
{
	const int bit_offset = SHA1_BLOCK_SIZE - sizeof(__be64);
	__be64 *bits = (__be64 *)(sctx->buffer + bit_offset);
	unsigned int partial = sctx->count % SHA1_BLOCK_SIZE;

	sctx->buffer[partial++] = 0x80;
	if (partial > bit_offset) {
		memset(sctx->buffer + partial, 0x0, SHA1_BLOCK_SIZE - partial);
		partial = 0;

		early_sha1_block_fn(sctx, sctx->buffer, 1);
	}

	memset(sctx->buffer + partial, 0x0, bit_offset - partial);
	*bits = cpu_to_be64(sctx->count << 3);
	early_sha1_block_fn(sctx, sctx->buffer, 1);
}

void early_sha1_finish(struct sha1_state *sctx, u8 *out)
{
	__be32 *digest = (__be32 *)out;
	int i;

	for (i = 0; i < SHA1_DIGEST_SIZE / sizeof(__be32); i++)
		put_unaligned_be32(sctx->state[i], digest++);

	*sctx = (struct sha1_state){};
}
