/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 */
#ifndef _AES_CTR_WALK_H
#define _AES_CTR_WALK_H

#include <crypto/aes.h>
#include <linux/align.h>
#include <linux/errno.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/types.h>

#include "aes-mips.h"

/*
 * A scatterlist split can end inside an AES block. used is how many
 * keystream bytes of blk are already consumed; the next chunk continues
 * there instead of stepping the counter again.
 */
struct ctr_ks {
	u8 blk[AES_BLOCK_SIZE] __aligned(4);
	unsigned int used;
};

/*
 * aes_mips_ctr_crypt loads each source word before storing that same
 * word. Equal src and dst are safe. A shifted overlap, or a pointer
 * that is not 4-byte aligned, is copied through the stack one block
 * at a time. The choice is made once per chunk.
 */
static inline bool ctr_via_stack(const u8 *src, const u8 *dst, unsigned int n)
{
	if (!IS_ALIGNED((unsigned long)src | (unsigned long)dst, 4))
		return true;
	if (src == dst || !n)
		return false;
	return src < dst + n && dst < src + n;
}

static inline void ctr_block(const struct crypto_aes_ctx *aes, u8 *dst,
			     const u8 *src, u8 ctr[AES_BLOCK_SIZE])
{
	u8 in[AES_BLOCK_SIZE] __aligned(4);
	u8 out[AES_BLOCK_SIZE] __aligned(4);

	memcpy(in, src, AES_BLOCK_SIZE);
	aes_mips_ctr_crypt(aes, out, in, 1, ctr);
	memcpy(dst, out, AES_BLOCK_SIZE);
	memzero_explicit(in, sizeof(in));
	memzero_explicit(out, sizeof(out));
}

static inline void ctr_crypt(const struct crypto_aes_ctx *aes, u8 *dst,
			     const u8 *src, unsigned int len,
			     u8 ctr[AES_BLOCK_SIZE], struct ctr_ks *ks)
{
	while (len && ks->used) {
		*dst++ = *src++ ^ ks->blk[ks->used++];
		if (ks->used == AES_BLOCK_SIZE)
			ks->used = 0;
		len--;
	}

	if (len >= AES_BLOCK_SIZE) {
		unsigned int n = len >> 4;
		unsigned int bytes = n << 4;

		if (ctr_via_stack(src, dst, bytes)) {
			do {
				ctr_block(aes, dst, src, ctr);
				dst += AES_BLOCK_SIZE;
				src += AES_BLOCK_SIZE;
				len -= AES_BLOCK_SIZE;
			} while (len >= AES_BLOCK_SIZE);
		} else {
			aes_mips_ctr_crypt(aes, dst, src, n, ctr);
			dst += bytes;
			src += bytes;
			len -= bytes;
		}
	}

	if (!len)
		return;

	memset(ks->blk, 0, AES_BLOCK_SIZE);
	aes_mips_ctr_crypt(aes, ks->blk, ks->blk, 1, ctr);
	ks->used = 0;
	while (len--)
		*dst++ = *src++ ^ ks->blk[ks->used++];
}

static inline int sg_at(struct scatterlist *sg, unsigned int skip,
			struct scatterlist **out, unsigned int *off)
{
	while (sg && skip >= sg->length) {
		skip -= sg->length;
		sg = sg_next(sg);
	}
	if (!sg)
		return -EINVAL;
	*out = sg;
	*off = skip;
	return 0;
}

#endif
