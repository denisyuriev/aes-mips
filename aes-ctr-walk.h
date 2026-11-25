/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 */
#ifndef _AES_CTR_WALK_H
#define _AES_CTR_WALK_H

#include <crypto/aes.h>
#include <linux/align.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

/*
 * A scatterlist split can end inside an AES block. used is how many
 * keystream bytes of blk are already consumed; the next chunk continues
 * there instead of stepping the counter again.
 */
struct ctr_ks {
	u8 blk[AES_BLOCK_SIZE] __aligned(4);
	unsigned int used;
};

int sg_at(struct scatterlist *sg, unsigned int skip,
	  struct scatterlist **out, unsigned int *off);

/* Map the page of byte off. Highmem cuts *n to that page. */
void *sg_map(struct scatterlist *sg, unsigned int off, unsigned int *n);

/* Best effort. A short list is wiped up to its end. */
void sg_zero(struct scatterlist *sg, unsigned int skip, unsigned int len);
void ctr_crypt(const struct crypto_aes_ctx *aes, u8 *dst, const u8 *src,
	       unsigned int len, u8 ctr[AES_BLOCK_SIZE], struct ctr_ks *ks);
int ctr_sg(const struct crypto_aes_ctx *aes,
	   struct scatterlist *ssg, unsigned int sskip,
	   struct scatterlist *dsg, unsigned int dskip,
	   unsigned int len, u8 ctr[AES_BLOCK_SIZE]);

#endif
