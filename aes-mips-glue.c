// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 *
 * AES cipher and optional ECB, CBC, CTR, GCM and CCM for MIPS32r2,
 * either endian. Cipher aes-mips is priority 200, above aes-generic (100).
 * A built skcipher is priority 300 so it wins over the template spawned
 * from that cipher. A built AEAD is priority 400.
 * AES_MIPS_ECB, AES_MIPS_CBC, AES_MIPS_CTR, AES_MIPS_GCM and AES_MIPS_CCM
 * select what is registered. GCM and CCM select CTR, so AES_MIPS_CTR_ASM
 * is built with them. CBC-MAC is built with CCM.
 */

#include <crypto/internal/skcipher.h>
#include <linux/align.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <asm/cpu-features.h>
#include <linux/scatterlist.h>
#include <linux/string.h>

#include "aes-mips.h"

static int aes_mips_cia_setkey(struct crypto_tfm *tfm, const u8 *in_key,
			       unsigned int key_len)
{
	return aes_mips_setkey(crypto_tfm_ctx(tfm), in_key, key_len);
}

static void aes_mips_cia_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	aes_mips_encrypt(crypto_tfm_ctx(tfm), out, in);
}

static void aes_mips_cia_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	aes_mips_decrypt(crypto_tfm_ctx(tfm), out, in);
}

static struct crypto_alg aes_mips_alg = {
	.cra_name		= "aes",
	.cra_driver_name	= "aes-mips",
	.cra_priority		= 200,
	.cra_flags		= CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct crypto_aes_ctx),
	.cra_alignmask		= 0x3,
	.cra_module		= THIS_MODULE,
	.cra_u			= {
		.cipher = {
			.cia_min_keysize	= AES_MIN_KEY_SIZE,
			.cia_max_keysize	= AES_MAX_KEY_SIZE,
			.cia_setkey		= aes_mips_cia_setkey,
			.cia_encrypt		= aes_mips_cia_encrypt,
			.cia_decrypt		= aes_mips_cia_decrypt,
		},
	},
};

#if defined(AES_MIPS_ECB) || defined(AES_MIPS_CBC) || defined(AES_MIPS_CTR)
#define AES_MIPS_SKCIPHER 1

static int aes_mips_sk_setkey(struct crypto_skcipher *tfm, const u8 *key,
			      unsigned int len)
{
	return aes_mips_setkey(crypto_skcipher_ctx(tfm), key, len);
}

/* One lowmem segment covering len, pointer aligned to 4. */
static bool aes_mips_sg_one(struct scatterlist *sg, unsigned int len, u8 **out)
{
	if (!sg || !len || sg->length < len || PageHighMem(sg_page(sg)))
		return false;
	*out = sg_virt(sg);
	return IS_ALIGNED((unsigned long)*out, 4);
}

/* Equal pointers, or two ranges that do not overlap. */
static bool aes_mips_ranges_ok(const u8 *src, const u8 *dst, unsigned int len)
{
	if (src == dst)
		return true;
	if (src < dst)
		return src + len <= dst;
	return dst + len <= src;
}
#endif

#if defined(AES_MIPS_CBC) || defined(AES_MIPS_CTR)
/* CBC and CTR update iv in place. An unaligned IV is copied and written back. */
static u8 *aes_mips_iv_align(u8 *reqiv, u8 *scratch, bool *copied)
{
	*copied = false;
	if (IS_ALIGNED((unsigned long)reqiv, 4))
		return reqiv;
	memcpy(scratch, reqiv, AES_BLOCK_SIZE);
	*copied = true;
	return scratch;
}
#endif

#ifdef AES_MIPS_ECB
/*
 * Direct call when the whole request is one aligned lowmem segment and the
 * ranges are equal or disjoint. Anything else returns -EAGAIN for the walk.
 */
static int aes_mips_ecb_direct(struct skcipher_request *req, bool enc)
{
	struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));
	unsigned int len = req->cryptlen;
	u8 *src, *dst;

	if (!len)
		return 0;
	if (!IS_ALIGNED(len, AES_BLOCK_SIZE) ||
	    !aes_mips_sg_one(req->src, len, &src) ||
	    !aes_mips_sg_one(req->dst, len, &dst) ||
	    !aes_mips_ranges_ok(src, dst, len))
		return -EAGAIN;
	if (enc)
		aes_mips_ecb_encrypt(ctx, dst, src, len >> 4);
	else
		aes_mips_ecb_decrypt(ctx, dst, src, len >> 4);
	return 0;
}
#endif

#ifdef AES_MIPS_CBC
static int aes_mips_cbc_direct(struct skcipher_request *req, bool enc)
{
	struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));
	unsigned int len = req->cryptlen;
	u8 ivbuf[AES_BLOCK_SIZE] __aligned(4);
	u8 *src, *dst, *iv;
	bool copied;

	if (!len)
		return 0;
	if (!req->iv || !IS_ALIGNED(len, AES_BLOCK_SIZE) ||
	    !aes_mips_sg_one(req->src, len, &src) ||
	    !aes_mips_sg_one(req->dst, len, &dst) ||
	    !aes_mips_ranges_ok(src, dst, len))
		return -EAGAIN;
	iv = aes_mips_iv_align(req->iv, ivbuf, &copied);
	if (enc)
		aes_mips_cbc_encrypt(ctx, dst, src, len >> 4, iv);
	else
		aes_mips_cbc_decrypt(ctx, dst, src, len >> 4, iv);
	if (copied)
		memcpy(req->iv, ivbuf, AES_BLOCK_SIZE);
	return 0;
}
#endif

#ifdef AES_MIPS_CTR
static int aes_mips_ctr_direct(struct skcipher_request *req)
{
	struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));
	unsigned int len = req->cryptlen;
	unsigned int nblocks = len >> 4;
	unsigned int tail = len & 15;
	u8 ivbuf[AES_BLOCK_SIZE] __aligned(4);
	u8 *src, *dst, *iv;
	bool copied;

	if (!len)
		return 0;
	if (!req->iv ||
	    !aes_mips_sg_one(req->src, len, &src) ||
	    !aes_mips_sg_one(req->dst, len, &dst) ||
	    !aes_mips_ranges_ok(src, dst, len))
		return -EAGAIN;
	iv = aes_mips_iv_align(req->iv, ivbuf, &copied);
	if (nblocks)
		aes_mips_ctr_crypt(ctx, dst, src, nblocks, iv);
	if (tail) {
		u32 tmp[4] = {};
		u32 ks[4];
		unsigned int off = nblocks << 4;

		memcpy(tmp, src + off, tail);
		aes_mips_ctr_crypt(ctx, (u8 *)ks, (const u8 *)tmp, 1, iv);
		memcpy(dst + off, ks, tail);
		memzero_explicit(ks, sizeof(ks));
		memzero_explicit(tmp, sizeof(tmp));
	}
	if (copied)
		memcpy(req->iv, ivbuf, AES_BLOCK_SIZE);
	return 0;
}
#endif

#ifdef AES_MIPS_ECB
static int aes_mips_ecb_run(struct skcipher_request *req, bool enc)
{
	struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));
	struct skcipher_walk walk;
	unsigned int n;
	int err;

	err = aes_mips_ecb_direct(req, enc);
	if (!err)
		return 0;

	err = skcipher_walk_virt(&walk, req, false);
	while (walk.nbytes >= AES_BLOCK_SIZE) {
		n = walk.nbytes & ~(AES_BLOCK_SIZE - 1);
		if (enc)
			aes_mips_ecb_encrypt(ctx, walk.dst.virt.addr,
					     walk.src.virt.addr,
					     n / AES_BLOCK_SIZE);
		else
			aes_mips_ecb_decrypt(ctx, walk.dst.virt.addr,
					     walk.src.virt.addr,
					     n / AES_BLOCK_SIZE);
		err = skcipher_walk_done(&walk, walk.nbytes - n);
	}
	return err;
}

static int aes_mips_ecb_enc(struct skcipher_request *req)
{
	return aes_mips_ecb_run(req, true);
}

static int aes_mips_ecb_dec(struct skcipher_request *req)
{
	return aes_mips_ecb_run(req, false);
}
#endif

#ifdef AES_MIPS_CBC
static int aes_mips_cbc_run(struct skcipher_request *req, bool enc)
{
	struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));
	struct skcipher_walk walk;
	unsigned int nblocks;
	int err;

	err = aes_mips_cbc_direct(req, enc);
	if (!err)
		return 0;

	err = skcipher_walk_virt(&walk, req, false);
	while (walk.nbytes >= AES_BLOCK_SIZE) {
		nblocks = walk.nbytes >> 4;
		if (enc)
			aes_mips_cbc_encrypt(ctx, walk.dst.virt.addr,
					     walk.src.virt.addr, nblocks,
					     walk.iv);
		else
			aes_mips_cbc_decrypt(ctx, walk.dst.virt.addr,
					     walk.src.virt.addr, nblocks,
					     walk.iv);
		err = skcipher_walk_done(&walk, walk.nbytes & 15);
	}
	return err;
}

static int aes_mips_cbc_enc(struct skcipher_request *req)
{
	return aes_mips_cbc_run(req, true);
}

static int aes_mips_cbc_dec(struct skcipher_request *req)
{
	return aes_mips_cbc_run(req, false);
}
#endif

#ifdef AES_MIPS_CTR
static int aes_mips_ctr_run(struct skcipher_request *req)
{
	struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));
	struct skcipher_walk walk;
	unsigned int n, nblocks;
	int err;

	err = aes_mips_ctr_direct(req);
	if (!err)
		return 0;

	err = skcipher_walk_virt(&walk, req, false);
	while (walk.nbytes >= AES_BLOCK_SIZE) {
		nblocks = walk.nbytes >> 4;
		aes_mips_ctr_crypt(ctx, walk.dst.virt.addr, walk.src.virt.addr,
				   nblocks, walk.iv);
		err = skcipher_walk_done(&walk, walk.nbytes & 15);
	}
	if (walk.nbytes) {
		u32 tmp[4] = {};
		u32 ks[4];

		n = walk.nbytes;
		memcpy(tmp, walk.src.virt.addr, n);
		aes_mips_ctr_crypt(ctx, (u8 *)ks, (const u8 *)tmp, 1, walk.iv);
		memcpy(walk.dst.virt.addr, ks, n);
		memzero_explicit(ks, sizeof(ks));
		memzero_explicit(tmp, sizeof(tmp));
		err = skcipher_walk_done(&walk, 0);
	}
	return err;
}
#endif

#ifdef AES_MIPS_SKCIPHER
static struct skcipher_alg aes_mips_skciphers[] = {
#ifdef AES_MIPS_ECB
	{
		.setkey		= aes_mips_sk_setkey,
		.encrypt	= aes_mips_ecb_enc,
		.decrypt	= aes_mips_ecb_dec,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
		.ivsize		= 0,
		.chunksize	= AES_BLOCK_SIZE,
		.base		= {
			.cra_name		= "ecb(aes)",
			.cra_driver_name	= "ecb-aes-mips",
			.cra_priority		= 300,
			.cra_blocksize		= AES_BLOCK_SIZE,
			.cra_ctxsize		= sizeof(struct crypto_aes_ctx),
			.cra_alignmask		= 0x3,
			.cra_module		= THIS_MODULE,
		},
	},
#endif
#ifdef AES_MIPS_CBC
	{
		.setkey		= aes_mips_sk_setkey,
		.encrypt	= aes_mips_cbc_enc,
		.decrypt	= aes_mips_cbc_dec,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		.chunksize	= AES_BLOCK_SIZE,
		.base		= {
			.cra_name		= "cbc(aes)",
			.cra_driver_name	= "cbc-aes-mips",
			.cra_priority		= 300,
			.cra_blocksize		= AES_BLOCK_SIZE,
			.cra_ctxsize		= sizeof(struct crypto_aes_ctx),
			.cra_alignmask		= 0x3,
			.cra_module		= THIS_MODULE,
		},
	},
#endif
#ifdef AES_MIPS_CTR
	{
		.setkey		= aes_mips_sk_setkey,
		.encrypt	= aes_mips_ctr_run,
		.decrypt	= aes_mips_ctr_run,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		.chunksize	= AES_BLOCK_SIZE,
		.base		= {
			.cra_name		= "ctr(aes)",
			.cra_driver_name	= "ctr-aes-mips",
			.cra_priority		= 300,
			.cra_blocksize		= 1,
			.cra_ctxsize		= sizeof(struct crypto_aes_ctx),
			.cra_alignmask		= 0x3,
			.cra_module		= THIS_MODULE,
		},
	},
#endif
};
#endif

/* FIPS-197 Appendix C.1–C.3. */
static const u8 aes_pt[AES_BLOCK_SIZE] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static const u8 aes128_key[AES_KEYSIZE_128] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const u8 aes128_ct[AES_BLOCK_SIZE] = {
	0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
	0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
};

static const u8 aes192_key[AES_KEYSIZE_192] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
};
static const u8 aes192_ct[AES_BLOCK_SIZE] = {
	0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
	0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
};

static const u8 aes256_key[AES_KEYSIZE_256] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static const u8 aes256_ct[AES_BLOCK_SIZE] = {
	0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
	0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
};

/* SP 800-38A F.1.1 / F.2.1 / F.5.1, AES-128, four blocks. */
#if defined(AES_MIPS_ECB) || defined(AES_MIPS_CBC) || defined(AES_MIPS_CTR_ASM)
static const u8 sp_key[AES_KEYSIZE_128] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};
static const u8 sp_pt[64] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
	0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};
#ifdef AES_MIPS_ECB
static const u8 sp_ecb[64] = {
	0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
	0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
	0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
	0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
	0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
	0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
	0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
	0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4,
};
#endif
#ifdef AES_MIPS_CBC
static const u8 sp_iv[AES_BLOCK_SIZE] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const u8 sp_cbc[64] = {
	0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
	0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
	0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
	0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
	0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
	0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
	0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
	0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
};
#endif
#ifdef AES_MIPS_CTR_ASM
static const u8 sp_ctr0[AES_BLOCK_SIZE] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};
static const u8 sp_ctr[64] = {
	0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
	0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
	0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
	0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
	0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
	0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
	0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
	0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
};
#endif
#endif

static int aes_mips_check_block(const u8 *key, unsigned int key_len,
				const u8 *pt, const u8 *ct)
{
	struct crypto_aes_ctx ctx;
	u8 out[AES_BLOCK_SIZE];
	u8 back[AES_BLOCK_SIZE];
	int err;

	err = aes_mips_setkey(&ctx, key, key_len);
	if (err)
		return err;

	aes_mips_encrypt(&ctx, out, pt);
	if (memcmp(out, ct, AES_BLOCK_SIZE))
		err = -EINVAL;

	if (!err) {
		aes_mips_decrypt(&ctx, back, ct);
		if (memcmp(back, pt, AES_BLOCK_SIZE))
			err = -EINVAL;
	}

	memzero_explicit(&ctx, sizeof(ctx));
	memzero_explicit(out, sizeof(out));
	memzero_explicit(back, sizeof(back));
	return err;
}

static int aes_mips_check_unaligned(void)
{
	struct crypto_aes_ctx ctx;
	u8 in_raw[AES_BLOCK_SIZE + 1];
	u8 out_raw[AES_BLOCK_SIZE + 1];
	u8 back_raw[AES_BLOCK_SIZE + 1];
	int err;

	err = aes_mips_setkey(&ctx, aes128_key, sizeof(aes128_key));
	if (err)
		return err;

	memcpy(in_raw + 1, aes_pt, AES_BLOCK_SIZE);
	aes_mips_encrypt(&ctx, out_raw + 1, in_raw + 1);
	if (memcmp(out_raw + 1, aes128_ct, AES_BLOCK_SIZE))
		err = -EINVAL;

	if (!err) {
		memcpy(in_raw + 1, aes128_ct, AES_BLOCK_SIZE);
		aes_mips_decrypt(&ctx, back_raw + 1, in_raw + 1);
		if (memcmp(back_raw + 1, aes_pt, AES_BLOCK_SIZE))
			err = -EINVAL;
	}

	memzero_explicit(&ctx, sizeof(ctx));
	return err;
}

#if defined(AES_MIPS_ECB) || defined(AES_MIPS_CBC) || defined(AES_MIPS_CTR_ASM)
static int aes_mips_check_modes(void)
{
	struct crypto_aes_ctx ctx;
	u8 out[64];
#if defined(AES_MIPS_ECB) || defined(AES_MIPS_CTR_ASM)
	u8 back[64];
#endif
#if defined(AES_MIPS_CBC) || defined(AES_MIPS_CTR_ASM)
	u8 iv[AES_BLOCK_SIZE];
#endif
	int err;

	err = aes_mips_setkey(&ctx, sp_key, sizeof(sp_key));
	if (err)
		return err;

#ifdef AES_MIPS_ECB
	aes_mips_ecb_encrypt(&ctx, out, sp_pt, 4);
	if (memcmp(out, sp_ecb, sizeof(sp_ecb)))
		return -EINVAL;
	aes_mips_ecb_decrypt(&ctx, back, out, 4);
	if (memcmp(back, sp_pt, sizeof(sp_pt)))
		return -EINVAL;
#endif

#ifdef AES_MIPS_CBC
	memcpy(iv, sp_iv, sizeof(iv));
	aes_mips_cbc_encrypt(&ctx, out, sp_pt, 4, iv);
	if (memcmp(out, sp_cbc, sizeof(sp_cbc)))
		return -EINVAL;
	memcpy(iv, sp_iv, sizeof(iv));
	aes_mips_cbc_decrypt(&ctx, out, out, 4, iv);
	if (memcmp(out, sp_pt, sizeof(sp_pt)))
		return -EINVAL;
#endif

#ifdef AES_MIPS_CTR_ASM
	memcpy(iv, sp_ctr0, sizeof(iv));
	aes_mips_ctr_crypt(&ctx, out, sp_pt, 4, iv);
	if (memcmp(out, sp_ctr, sizeof(sp_ctr)))
		return -EINVAL;
	memcpy(iv, sp_ctr0, sizeof(iv));
	aes_mips_ctr_crypt(&ctx, back, out, 4, iv);
	if (memcmp(back, sp_pt, sizeof(sp_pt)))
		return -EINVAL;
#endif

	memzero_explicit(&ctx, sizeof(ctx));
	return 0;
}
#endif

#ifdef AES_MIPS_CTR_ASM
/* Increment a big-endian counter by one block and compare with ECB. */
static int aes_mips_check_ctr_carry(const u8 *start)
{
	struct crypto_aes_ctx ctx;
	u8 ctr[AES_BLOCK_SIZE], next[AES_BLOCK_SIZE];
	u8 pt[AES_BLOCK_SIZE], out[AES_BLOCK_SIZE], ks[AES_BLOCK_SIZE];
	unsigned int i;
	int err;

	err = aes_mips_setkey(&ctx, sp_key, sizeof(sp_key));
	if (err)
		return err;

	memcpy(ctr, start, AES_BLOCK_SIZE);
	memcpy(next, start, AES_BLOCK_SIZE);
	for (i = AES_BLOCK_SIZE; i > 0; i--) {
		next[i - 1]++;
		if (next[i - 1])
			break;
	}
	memset(pt, 0, sizeof(pt));
	aes_mips_ctr_crypt(&ctx, out, pt, 1, ctr);
	aes_mips_ecb_encrypt(&ctx, ks, start, 1);
	if (memcmp(out, ks, AES_BLOCK_SIZE) || memcmp(ctr, next, AES_BLOCK_SIZE))
		err = -EINVAL;

	memzero_explicit(&ctx, sizeof(ctx));
	return err;
}

/*
 * Four blocks, so the run of counter byte 15 is taken. Compared with ECB
 * of each explicit counter. Also in place.
 */
static int aes_mips_check_ctr_span(const u8 *key, unsigned int key_len,
				   const u8 *start)
{
	struct crypto_aes_ctx ctx;
	u8 ctr[AES_BLOCK_SIZE], expect[AES_BLOCK_SIZE];
	u8 pt[AES_BLOCK_SIZE * 4], out[AES_BLOCK_SIZE * 4];
	u8 ks[AES_BLOCK_SIZE], one[AES_BLOCK_SIZE];
	unsigned int b, i, pass;
	int err = 0;

	err = aes_mips_setkey(&ctx, key, key_len);
	if (err)
		return err;
	for (i = 0; i < 4 * AES_BLOCK_SIZE; i++)
		pt[i] = (u8)(i * 17 + 3);

	for (pass = 0; pass < 2 && !err; pass++) {
		memcpy(ctr, start, AES_BLOCK_SIZE);
		memcpy(expect, start, AES_BLOCK_SIZE);
		if (pass == 0) {
			aes_mips_ctr_crypt(&ctx, out, pt, 4, ctr);
		} else {
			memcpy(out, pt, 4 * AES_BLOCK_SIZE);
			aes_mips_ctr_crypt(&ctx, out, out, 4, ctr);
		}
		for (b = 0; b < 4 && !err; b++) {
			aes_mips_ecb_encrypt(&ctx, ks, expect, 1);
			for (i = 0; i < AES_BLOCK_SIZE; i++)
				one[i] = ks[i] ^ pt[b * AES_BLOCK_SIZE + i];
			if (memcmp(out + b * AES_BLOCK_SIZE, one, AES_BLOCK_SIZE))
				err = -EINVAL;
			for (i = AES_BLOCK_SIZE; i > 0; i--) {
				expect[i - 1]++;
				if (expect[i - 1])
					break;
			}
		}
		if (!err && memcmp(ctr, expect, AES_BLOCK_SIZE))
			err = -EINVAL;
	}

	memzero_explicit(&ctx, sizeof(ctx));
	memzero_explicit(out, sizeof(out));
	memzero_explicit(ks, sizeof(ks));
	memzero_explicit(one, sizeof(one));
	return err;
}
#endif

#ifdef AES_MIPS_CCM
/* One block and four, against a chain of aes_mips_encrypt. */
static int aes_mips_check_cbc_mac(const u8 *key, unsigned int key_len,
				  const char *name)
{
	struct crypto_aes_ctx ctx;
	u8 pt[AES_BLOCK_SIZE * 4] __aligned(4);
	u8 state[AES_BLOCK_SIZE] __aligned(4);
	u8 expect[AES_BLOCK_SIZE] __aligned(4);
	u8 block[AES_BLOCK_SIZE] __aligned(4);
	unsigned int n, i, b;
	int err;

	err = aes_mips_setkey(&ctx, key, key_len);
	if (err)
		return err;
	for (i = 0; i < sizeof(pt); i++)
		pt[i] = (u8)(i * 17 + 3);

	for (n = 1; n <= 4; n += 3) {
		memset(state, 0x5a, sizeof(state));
		memcpy(expect, state, sizeof(expect));
		aes_mips_cbc_mac(&ctx, state, pt, n);
		for (i = 0; i < n; i++) {
			for (b = 0; b < AES_BLOCK_SIZE; b++)
				block[b] = expect[b] ^ pt[i * AES_BLOCK_SIZE + b];
			aes_mips_encrypt(&ctx, expect, block);
		}
		if (memcmp(state, expect, AES_BLOCK_SIZE)) {
			pr_err("aes-mips: CBC-MAC AES-%s %u blocks failed\n",
			       name, n);
			err = -EINVAL;
			break;
		}
	}

	memzero_explicit(&ctx, sizeof(ctx));
	memzero_explicit(state, sizeof(state));
	memzero_explicit(expect, sizeof(expect));
	memzero_explicit(block, sizeof(block));
	return err;
}
#endif

static int aes_mips_selftest(void)
{
	struct crypto_aes_ctx ctx;
	u8 short_key[15];
#ifdef AES_MIPS_CTR_ASM
	u8 ctr[AES_BLOCK_SIZE];
#endif
	int err;

	err = aes_mips_check_block(aes128_key, sizeof(aes128_key),
				   aes_pt, aes128_ct);
	if (err) {
		pr_err("aes-mips: FIPS-197 C.1 failed\n");
		return err;
	}

	err = aes_mips_check_block(aes192_key, sizeof(aes192_key),
				   aes_pt, aes192_ct);
	if (err) {
		pr_err("aes-mips: FIPS-197 C.2 failed\n");
		return err;
	}

	err = aes_mips_check_block(aes256_key, sizeof(aes256_key),
				   aes_pt, aes256_ct);
	if (err) {
		pr_err("aes-mips: FIPS-197 C.3 failed\n");
		return err;
	}

	err = aes_mips_check_unaligned();
	if (err) {
		pr_err("aes-mips: unaligned block failed\n");
		return err;
	}

#if defined(AES_MIPS_ECB) || defined(AES_MIPS_CBC) || defined(AES_MIPS_CTR_ASM)
	err = aes_mips_check_modes();
	if (err) {
		pr_err("aes-mips: SP 800-38A failed\n");
		return err;
	}
#endif

#ifdef AES_MIPS_CTR_ASM
	memset(ctr, 0, sizeof(ctr));
	memset(ctr + 12, 0xff, 4);
	err = aes_mips_check_ctr_carry(ctr);
	if (err) {
		pr_err("aes-mips: CTR 32-bit carry failed\n");
		return err;
	}
	memset(ctr + 8, 0xff, 8);
	err = aes_mips_check_ctr_carry(ctr);
	if (err) {
		pr_err("aes-mips: CTR 64-bit carry failed\n");
		return err;
	}

	{
		static const struct {
			const u8 *key;
			unsigned int len;
			const char *name;
		} keys[] = {
			{ aes128_key, sizeof(aes128_key), "128" },
			{ aes192_key, sizeof(aes192_key), "192" },
			{ aes256_key, sizeof(aes256_key), "256" },
		};
		unsigned int k;

		for (k = 0; k < ARRAY_SIZE(keys); k++) {
			memset(ctr, 0x11, sizeof(ctr));
			ctr[15] = 0;
			err = aes_mips_check_ctr_span(keys[k].key, keys[k].len,
						      ctr);
			if (err) {
				pr_err("aes-mips: CTR run AES-%s failed\n",
				       keys[k].name);
				return err;
			}
			memset(ctr, 0x22, sizeof(ctr));
			ctr[15] = 0xfe;
			err = aes_mips_check_ctr_span(keys[k].key, keys[k].len,
						      ctr);
			if (err) {
				pr_err("aes-mips: CTR byte-15 carry AES-%s failed\n",
				       keys[k].name);
				return err;
			}
			memset(ctr, 0x33, sizeof(ctr));
			memset(ctr + 12, 0xff, 4);
			ctr[15] = 0xfe;
			err = aes_mips_check_ctr_span(keys[k].key, keys[k].len,
						      ctr);
			if (err) {
				pr_err("aes-mips: CTR 32-bit run AES-%s failed\n",
				       keys[k].name);
				return err;
			}
			memset(ctr, 0x44, sizeof(ctr));
			memset(ctr + 8, 0xff, 8);
			ctr[15] = 0xfe;
			err = aes_mips_check_ctr_span(keys[k].key, keys[k].len,
						      ctr);
			if (err) {
				pr_err("aes-mips: CTR 64-bit run AES-%s failed\n",
				       keys[k].name);
				return err;
			}
		}
	}
#endif

#ifdef AES_MIPS_CCM
	err = aes_mips_check_cbc_mac(aes128_key, sizeof(aes128_key), "128");
	if (err)
		return err;
	err = aes_mips_check_cbc_mac(aes192_key, sizeof(aes192_key), "192");
	if (err)
		return err;
	err = aes_mips_check_cbc_mac(aes256_key, sizeof(aes256_key), "256");
	if (err)
		return err;
#endif

	memset(short_key, 0x11, sizeof(short_key));
	err = aes_mips_setkey(&ctx, short_key, sizeof(short_key));
	memzero_explicit(&ctx, sizeof(ctx));
	memzero_explicit(short_key, sizeof(short_key));
	if (err != -EINVAL) {
		pr_err("aes-mips: bad key length not rejected\n");
		return -EINVAL;
	}

	pr_info("aes-mips: self-test passed\n");
	return 0;
}

#ifdef AES_MIPS_GCM
int __init gcm_aes_mips_register(void);
void gcm_aes_mips_unregister(void);
#endif
#ifdef AES_MIPS_CCM
int __init ccm_aes_mips_register(void);
void __exit ccm_aes_mips_unregister(void);
#endif

#ifdef TOOLCHAIN_SUPPORTS_DSP
extern u32 aes_mips_round_entry[12];
extern u32 aes_mips_round_entry_dsp[12];
#endif

static int __init aes_mips_mod_init(void)
{
	int err;

	aes_mips_be_tables();
	err = aes_mips_selftest();
	if (err)
		return err;

#ifdef TOOLCHAIN_SUPPORTS_DSP
	if (cpu_has_dsp) {
		memcpy(aes_mips_round_entry, aes_mips_round_entry_dsp,
		       sizeof(aes_mips_round_entry));
		err = aes_mips_selftest();
		if (err)
			return err;
	}
#endif

	err = crypto_register_alg(&aes_mips_alg);
	if (err)
		return err;

#ifdef AES_MIPS_SKCIPHER
	err = crypto_register_skciphers(aes_mips_skciphers,
					ARRAY_SIZE(aes_mips_skciphers));
	if (err) {
		crypto_unregister_alg(&aes_mips_alg);
		return err;
	}
#endif

#ifdef AES_MIPS_GCM
	err = gcm_aes_mips_register();
	if (err)
		goto out_sk;
#endif
#ifdef AES_MIPS_CCM
	err = ccm_aes_mips_register();
	if (err) {
#ifdef AES_MIPS_GCM
		gcm_aes_mips_unregister();
#endif
		goto out_sk;
	}
#endif
	return 0;

#if defined(AES_MIPS_GCM) || defined(AES_MIPS_CCM)
out_sk:
#ifdef AES_MIPS_SKCIPHER
	crypto_unregister_skciphers(aes_mips_skciphers,
				    ARRAY_SIZE(aes_mips_skciphers));
#endif
	crypto_unregister_alg(&aes_mips_alg);
	return err;
#endif
}

static void __exit aes_mips_mod_exit(void)
{
#ifdef AES_MIPS_CCM
	ccm_aes_mips_unregister();
#endif
#ifdef AES_MIPS_GCM
	gcm_aes_mips_unregister();
#endif
#ifdef AES_MIPS_SKCIPHER
	crypto_unregister_skciphers(aes_mips_skciphers,
				    ARRAY_SIZE(aes_mips_skciphers));
#endif
	crypto_unregister_alg(&aes_mips_alg);
}

module_init(aes_mips_mod_init);
module_exit(aes_mips_mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Denis Iurev <denis.yuriev@icloud.com>");
MODULE_INFO(description, "AES for MIPS32r2"
#ifdef AES_MIPS_ECB
	", ECB"
#endif
#ifdef AES_MIPS_CBC
	", CBC"
#endif
#ifdef AES_MIPS_CTR
	", CTR"
#endif
#ifdef AES_MIPS_GCM
	", GCM"
#endif
#ifdef AES_MIPS_CCM
	", CCM"
#endif
);
MODULE_ALIAS_CRYPTO("aes");
MODULE_ALIAS_CRYPTO("aes-mips");
#ifdef AES_MIPS_ECB
MODULE_ALIAS_CRYPTO("ecb(aes)");
MODULE_ALIAS_CRYPTO("ecb-aes-mips");
#endif
#ifdef AES_MIPS_CBC
MODULE_ALIAS_CRYPTO("cbc(aes)");
MODULE_ALIAS_CRYPTO("cbc-aes-mips");
#endif
#ifdef AES_MIPS_CTR
MODULE_ALIAS_CRYPTO("ctr(aes)");
MODULE_ALIAS_CRYPTO("ctr-aes-mips");
#endif
#ifdef AES_MIPS_GCM
MODULE_ALIAS_CRYPTO("gcm(aes)");
MODULE_ALIAS_CRYPTO("gcm-aes-mips");
#endif
#ifdef AES_MIPS_CCM
MODULE_ALIAS_CRYPTO("ccm(aes)");
MODULE_ALIAS_CRYPTO("ccm-aes-mips");
#endif
