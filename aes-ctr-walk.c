// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 *
 * Scatterlist walk for GCM and CCM. The block cipher is aes_mips_ctr_crypt.
 */

#include <linux/align.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>

#include "aes-ctr-walk.h"
#include "aes-mips.h"

/*
 * aes_mips_ctr_crypt loads each source word before storing that same
 * word. Equal src and dst are safe. A shifted overlap, or a pointer
 * that is not 4-byte aligned, is copied through the stack one block
 * at a time. The choice is made once per chunk.
 */
static bool ctr_via_stack(const u8 *src, const u8 *dst, unsigned int n)
{
	if (!IS_ALIGNED((unsigned long)src | (unsigned long)dst, 4))
		return true;
	if (src == dst)
		return false;
	return src < dst + n && dst < src + n;
}

static void ctr_block(const struct crypto_aes_ctx *aes, u8 *dst,
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

void ctr_crypt(const struct crypto_aes_ctx *aes, u8 *dst, const u8 *src,
	       unsigned int len, u8 ctr[AES_BLOCK_SIZE], struct ctr_ks *ks)
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

int sg_at(struct scatterlist *sg, unsigned int skip,
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

/*
 * Map the page that holds byte off of this segment. A highmem kmap covers
 * one page, so *n is cut to the end of that page. Lowmem is linear:
 * PageHighMem is 0 and *n is left alone. kunmap_local the returned pointer.
 */
void *sg_map(struct scatterlist *sg, unsigned int off, unsigned int *n)
{
	unsigned int pos = sg->offset + off;
	struct page *page = sg_page(sg) + (pos >> PAGE_SHIFT);

	pos = offset_in_page(pos);
	if (PageHighMem(page))
		*n = min_t(unsigned int, *n, PAGE_SIZE - pos);
	return kmap_local_page(page) + pos;
}

int ctr_sg(const struct crypto_aes_ctx *aes,
	   struct scatterlist *ssg, unsigned int sskip,
	   struct scatterlist *dsg, unsigned int dskip,
	   unsigned int len, u8 ctr[AES_BLOCK_SIZE])
{
	struct ctr_ks ks = {};

	if (!len)
		return 0;
	if (sg_at(ssg, sskip, &ssg, &sskip) || sg_at(dsg, dskip, &dsg, &dskip))
		return -EINVAL;

	while (len) {
		unsigned int n = min3(len, ssg->length - sskip, dsg->length - dskip);
		void *sp = sg_map(ssg, sskip, &n);
		void *dp = sg_map(dsg, dskip, &n);

		ctr_crypt(aes, dp, sp, n, ctr, &ks);
		kunmap_local(dp);
		kunmap_local(sp);
		len -= n;
		sskip += n;
		dskip += n;
		if (sskip == ssg->length) {
			ssg = sg_next(ssg);
			sskip = 0;
		}
		if (dskip == dsg->length) {
			dsg = sg_next(dsg);
			dskip = 0;
		}
		if (len && (!ssg || !dsg)) {
			memzero_explicit(&ks, sizeof(ks));
			return -EINVAL;
		}
	}
	memzero_explicit(&ks, sizeof(ks));
	return 0;
}

void sg_zero(struct scatterlist *sg, unsigned int skip, unsigned int len)
{
	if (!len)
		return;
	if (sg_at(sg, skip, &sg, &skip))
		return;

	while (len && sg) {
		unsigned int n = min_t(unsigned int, len, sg->length - skip);
		void *p = sg_map(sg, skip, &n);

		memzero_explicit(p, n);
		kunmap_local(p);
		len -= n;
		skip += n;
		if (skip == sg->length) {
			sg = sg_next(sg);
			skip = 0;
		}
	}
}
