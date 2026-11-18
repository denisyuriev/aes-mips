// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 *
 * AES-GCM for MIPS32r2, little-endian or big-endian.
 * CTR is aes_mips_ctr_crypt. GHASH is 16 KiB when L1 D is at least
 * 32 KiB, and 8 KiB otherwise. Both tables stay in the module:
 * init picks one, the self-test runs both. The two passes stay apart.
 */

#include <crypto/aead.h>
#include <crypto/algapi.h>
#include <crypto/internal/aead.h>
#include <crypto/scatterwalk.h>
#include <linux/align.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <asm/cpu-info.h>

#include "aes-ctr-walk.h"
#include "aes-mips.h"
#include "ghash-tab.h"

int __init gcm_aes_mips_register(void);
void gcm_aes_mips_unregister(void);

/* Set in gcm_aes_mips_register from the L1 D size. 8 KiB is order 1, 16 is 2. */
static unsigned int tab_kib;
static unsigned int tab_order;

static void ghash_tab_select(void)
{
	const struct cache_desc *d = &boot_cpu_data.dcache;
	unsigned long l1d = (unsigned long)d->sets * d->ways * d->linesz;

	if (!l1d || l1d < 32 * 1024) {
		tab_kib = 8;
		tab_order = 1;
	} else {
		tab_kib = 16;
		tab_order = 2;
	}
	pr_info("gcm-aes-mips: L1D %lu KiB, GHASH table %u KiB\n",
		l1d >> 10, tab_kib);
}

struct gcm_mips_ctx {
	struct crypto_aes_ctx aes;
	void *tab;
	unsigned int kib;
};

static void inc32(u8 block[AES_BLOCK_SIZE])
{
	unsigned int n = AES_BLOCK_SIZE;

	while (n-- > 12) {
		if (++block[n])
			break;
	}
}

static int ghash_sg(struct ghash_acc *acc, const void *tab, unsigned int kib,
		    struct scatterlist *sg, unsigned int skip, unsigned int len)
{
	if (!len)
		return 0;
	if (sg_at(sg, skip, &sg, &skip))
		return -EINVAL;

	while (len) {
		unsigned int n = min_t(unsigned int, len, sg->length - skip);
		unsigned int took = n;
		void *page = kmap_local_page(sg_page(sg));
		u8 *p = page + sg->offset + skip;

		ghash_acc_update(acc, tab, kib, p, n);
		kunmap_local(page);
		len -= took;
		skip = 0;
		sg = sg_next(sg);
		if (len && !sg)
			return -EINVAL;
	}
	return 0;
}

static int ctr_sg(const struct crypto_aes_ctx *aes,
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
		void *spage = kmap_local_page(sg_page(ssg));
		void *dpage = kmap_local_page(sg_page(dsg));

		ctr_crypt(aes, dpage + dsg->offset + dskip,
			  spage + ssg->offset + sskip, n, ctr, &ks);
		kunmap_local(dpage);
		kunmap_local(spage);
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

static void gcm_tag(struct gcm_mips_ctx *ctx, struct ghash_acc *acc,
		    const u8 mask[AES_BLOCK_SIZE], unsigned int alen,
		    unsigned int clen, u8 tag[AES_BLOCK_SIZE])
{
	ghash_acc_pad(acc, ctx->tab, ctx->kib);
	ghash_acc_lengths(acc, ctx->tab, ctx->kib, alen, clen);
	ghash_acc_final(acc, ctx->tab, ctx->kib, tag);
	crypto_xor(tag, mask, AES_BLOCK_SIZE);
}

static int gcm_mips_crypt(struct aead_request *req, bool enc)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct gcm_mips_ctx *ctx = crypto_aead_ctx(tfm);
	unsigned int authsize = crypto_aead_authsize(tfm);
	unsigned int cryptlen = req->cryptlen;
	struct scatterlist *src = req->src;
	struct scatterlist *dst = req->dst;
	u8 j0[AES_BLOCK_SIZE] __aligned(4);
	u8 mask[AES_BLOCK_SIZE] __aligned(4);
	u8 tag[AES_BLOCK_SIZE];
	u8 have[AES_BLOCK_SIZE];
	struct ghash_acc acc;
	unsigned int assoclen = req->assoclen;
	int err = 0;

	if (!enc) {
		if (cryptlen < authsize)
			return -EINVAL;
		cryptlen -= authsize;
	}

	memcpy(j0, req->iv, 12);
	j0[12] = 0;
	j0[13] = 0;
	j0[14] = 0;
	j0[15] = 1;
	aes_mips_encrypt(&ctx->aes, mask, j0);
	inc32(j0);

	ghash_acc_init(&acc);
	if (assoclen) {
		err = ghash_sg(&acc, ctx->tab, ctx->kib, src, 0, assoclen);
		if (err)
			goto out;
	}
	/* AAD is zero-padded to the block before the ciphertext is hashed. */
	ghash_acc_pad(&acc, ctx->tab, ctx->kib);

	if (enc) {
		if (cryptlen) {
			err = ctr_sg(&ctx->aes, src, assoclen, dst, assoclen,
				     cryptlen, j0);
			if (err)
				goto out;
			err = ghash_sg(&acc, ctx->tab, ctx->kib, dst, assoclen,
				       cryptlen);
			if (err)
				goto out;
		}
		gcm_tag(ctx, &acc, mask, assoclen, cryptlen, tag);
		scatterwalk_map_and_copy(tag, dst, assoclen + cryptlen,
					 authsize, 1);
	} else {
		if (cryptlen) {
			err = ghash_sg(&acc, ctx->tab, ctx->kib, src, assoclen,
				       cryptlen);
			if (err)
				goto out;
		}
		gcm_tag(ctx, &acc, mask, assoclen, cryptlen, tag);
		scatterwalk_map_and_copy(have, src, assoclen + cryptlen,
					 authsize, 0);
		if (crypto_memneq(tag, have, authsize)) {
			err = -EBADMSG;
			goto out;
		}
		if (cryptlen) {
			err = ctr_sg(&ctx->aes, src, assoclen, dst, assoclen,
				     cryptlen, j0);
			if (err)
				goto out;
		}
	}

out:
	memzero_explicit(tag, sizeof(tag));
	memzero_explicit(have, sizeof(have));
	memzero_explicit(mask, sizeof(mask));
	memzero_explicit(&acc, sizeof(acc));
	return err;
}

static int gcm_mips_encrypt(struct aead_request *req)
{
	return gcm_mips_crypt(req, true);
}

static int gcm_mips_decrypt(struct aead_request *req)
{
	return gcm_mips_crypt(req, false);
}

static int gcm_mips_setkey(struct crypto_aead *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct gcm_mips_ctx *ctx = crypto_aead_ctx(tfm);
	u8 zero[AES_BLOCK_SIZE] __aligned(4) = {};
	u8 h[AES_BLOCK_SIZE] __aligned(4);
	unsigned int kib = tab_kib;
	int err;

	if (kib != 8 && kib != 16)
		return -EINVAL;

	err = aes_mips_setkey(&ctx->aes, key, keylen);
	if (err)
		return err;

	aes_mips_encrypt(&ctx->aes, h, zero);
	err = ghash_tab_init(ctx->tab, h, kib / 4);
	if (err)
		return err;
	ctx->kib = kib;
	memzero_explicit(h, sizeof(h));
	return 0;
}

static int gcm_mips_setauthsize(struct crypto_aead *tfm, unsigned int authsize)
{
	if (authsize < 4 || authsize > AES_BLOCK_SIZE)
		return -EINVAL;
	return 0;
}

static int gcm_mips_init(struct crypto_aead *tfm)
{
	struct gcm_mips_ctx *ctx = crypto_aead_ctx(tfm);

	ctx->tab = (void *)__get_free_pages(GFP_KERNEL, tab_order);
	if (!ctx->tab)
		return -ENOMEM;
	ctx->kib = tab_kib;
	return 0;
}

static void gcm_mips_exit(struct crypto_aead *tfm)
{
	struct gcm_mips_ctx *ctx = crypto_aead_ctx(tfm);

	memzero_explicit(ctx->tab, (size_t)tab_kib << 10);
	memzero_explicit(&ctx->aes, sizeof(ctx->aes));
	free_pages((unsigned long)ctx->tab, tab_order);
}

static struct aead_alg gcm_aes_alg = {
	.setkey		= gcm_mips_setkey,
	.setauthsize	= gcm_mips_setauthsize,
	.encrypt	= gcm_mips_encrypt,
	.decrypt	= gcm_mips_decrypt,
	.init		= gcm_mips_init,
	.exit		= gcm_mips_exit,
	.ivsize		= 12,
	.maxauthsize	= AES_BLOCK_SIZE,
	.chunksize	= AES_BLOCK_SIZE,
	.base		= {
		.cra_name		= "gcm(aes)",
		.cra_driver_name	= "gcm-aes-mips",
		.cra_priority		= 400,
		.cra_flags		= CRYPTO_ALG_ALLOCATES_MEMORY,
		.cra_blocksize		= 1,
		.cra_ctxsize		= sizeof(struct gcm_mips_ctx),
		.cra_module		= THIS_MODULE,
	},
};

/* McGrew & Viega, testmgr aes_gcm_tv_template case 2. Key and IV zero. */
static const u8 mv_pt[16];
static const u8 mv_ct[32] = {
	0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
	0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
	0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
	0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
};

static int gcm_selftest_one(unsigned int kib)
{
	struct crypto_aes_ctx aes;
	void *gtab;
	u8 zero[AES_BLOCK_SIZE] __aligned(4) = {};
	u8 h[AES_BLOCK_SIZE] __aligned(4);
	u8 j0[AES_BLOCK_SIZE] __aligned(4) = {};
	u8 mask[AES_BLOCK_SIZE] __aligned(4);
	u8 out[16];
	u8 tag[AES_BLOCK_SIZE];
	struct ghash_acc acc;
	int err;

	gtab = (void *)__get_free_pages(GFP_KERNEL, GHASH_TAB_ORDER);
	if (!gtab)
		return -ENOMEM;

	err = aes_mips_setkey(&aes, zero, AES_BLOCK_SIZE);
	if (err)
		goto out;
	aes_mips_encrypt(&aes, h, zero);
	err = ghash_tab_init(gtab, h, kib / 4);
	if (err)
		goto out;

	j0[15] = 1;
	aes_mips_encrypt(&aes, mask, j0);
	inc32(j0);
	{
		struct ctr_ks ks = {};

		ctr_crypt(&aes, out, mv_pt, sizeof(mv_pt), j0, &ks);
		memzero_explicit(&ks, sizeof(ks));
	}
	if (memcmp(out, mv_ct, 16)) {
		err = -EINVAL;
		goto out;
	}

	/* McGrew–Viega case 2 again, ciphertext written over the plaintext. */
	memcpy(out, mv_pt, sizeof(mv_pt));
	memset(j0, 0, sizeof(j0));
	j0[15] = 2;
	{
		struct ctr_ks ks = {};

		ctr_crypt(&aes, out, out, sizeof(mv_pt), j0, &ks);
		memzero_explicit(&ks, sizeof(ks));
	}
	if (memcmp(out, mv_ct, 16)) {
		err = -EINVAL;
		goto out;
	}

	ghash_acc_init(&acc);
	ghash_acc_update(&acc, gtab, kib, out, 16);
	ghash_acc_lengths(&acc, gtab, kib, 0, 16);
	ghash_acc_final(&acc, gtab, kib, tag);
	crypto_xor(tag, mask, AES_BLOCK_SIZE);
	if (memcmp(tag, mv_ct + 16, 16))
		err = -EINVAL;

	/*
	 * Zero key and IV. Eight bytes of AAD and 20 bytes of plaintext
	 * take the word tail of GHASH: the AAD is two words, the
	 * ciphertext is one block and a four-byte word.
	 */
	if (!err) {
		static const u8 part_aad[8] __aligned(4) = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		};
		static const u8 part_pt[20] __aligned(4) = {
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
			0x10, 0x20, 0x30, 0x40,
		};
		static const u8 part_ct[20] = {
			0x03, 0x99, 0xf8, 0xfd, 0x24, 0xe3, 0xc5, 0xe5,
			0x7b, 0xb1, 0x68, 0x02, 0xbd, 0x6f, 0x10, 0x87,
			0xe7, 0xb5, 0x9a, 0xeb,
		};
		static const u8 part_tag[16] = {
			0x04, 0x49, 0x22, 0xfb, 0x83, 0x69, 0x21, 0xac,
			0x89, 0x69, 0xf6, 0x09, 0xf7, 0xa3, 0x48, 0xe9,
		};
		u8 pct[20] __aligned(4);
		u8 ptag[AES_BLOCK_SIZE];
		struct ghash_acc part;
		struct ctr_ks ks = {};

		memset(j0, 0, sizeof(j0));
		j0[15] = 2;
		ctr_crypt(&aes, pct, part_pt, sizeof(part_pt), j0, &ks);
		memzero_explicit(&ks, sizeof(ks));
		if (memcmp(pct, part_ct, sizeof(part_ct))) {
			memzero_explicit(pct, sizeof(pct));
			err = -EINVAL;
			goto out;
		}
		ghash_acc_init(&part);
		ghash_acc_update(&part, gtab, kib, part_aad, sizeof(part_aad));
		ghash_acc_pad(&part, gtab, kib);
		ghash_acc_update(&part, gtab, kib, pct, sizeof(pct));
		ghash_acc_pad(&part, gtab, kib);
		ghash_acc_lengths(&part, gtab, kib, sizeof(part_aad),
				  sizeof(part_ct));
		ghash_acc_final(&part, gtab, kib, ptag);
		crypto_xor(ptag, mask, AES_BLOCK_SIZE);
		if (memcmp(ptag, part_tag, sizeof(part_tag)))
			err = -EINVAL;
		memzero_explicit(&part, sizeof(part));
		memzero_explicit(pct, sizeof(pct));
		memzero_explicit(ptag, sizeof(ptag));
	}

out:
	memzero_explicit(&aes, sizeof(aes));
	memzero_explicit(h, sizeof(h));
	memzero_explicit(mask, sizeof(mask));
	memzero_explicit(gtab, GHASH_TAB_BYTES);
	free_pages((unsigned long)gtab, GHASH_TAB_ORDER);
	return err;
}

static int gcm_selftest(void)
{
	int err;

	if (!IS_ALIGNED((unsigned long)ghash_xda_le, 512)) {
		pr_err("gcm-aes-mips: xda table is not 512-aligned\n");
		return -EINVAL;
	}

	err = gcm_selftest_one(8);
	if (err) {
		pr_err("gcm-aes-mips: self-test failed for 8 KiB\n");
		return err;
	}
	err = gcm_selftest_one(16);
	if (err) {
		pr_err("gcm-aes-mips: self-test failed for 16 KiB\n");
		return err;
	}
	pr_info("gcm-aes-mips: self-test passed\n");
	return 0;
}

int __init gcm_aes_mips_register(void)
{
	int err;

	ghash_tab_select();
	err = gcm_selftest();
	if (err)
		return err;
	return crypto_register_aead(&gcm_aes_alg);
}

void gcm_aes_mips_unregister(void)
{
	crypto_unregister_aead(&gcm_aes_alg);
}
