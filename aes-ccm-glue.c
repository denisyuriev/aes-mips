// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 *
 * AES-CCM for MIPS32r2, little-endian or big-endian.
 * The keystream is aes_mips_ctr_crypt. CBC-MAC, including a partial
 * block, is aes_mips_cbc_mac. B0 stays on aes_mips_encrypt.
 * RFC 4309 stays the kernel template and picks this ccm(aes) when
 * it has the higher priority.
 */

#include <crypto/aead.h>
#include <crypto/algapi.h>
#include <crypto/internal/aead.h>
#include <crypto/scatterwalk.h>
#include <crypto/utils.h>
#include <linux/align.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/string.h>

#include "aes-ctr-walk.h"
#include "aes-mips.h"

int __init ccm_aes_mips_register(void);
void __exit ccm_aes_mips_unregister(void);

struct mac_acc {
	u8 state[AES_BLOCK_SIZE] __aligned(4);
	u8 buf[AES_BLOCK_SIZE] __aligned(4);
	unsigned int n;
};

static int set_msg_len(u8 *block, unsigned int msglen, unsigned int csize)
{
	__be32 data;

	memset(block, 0, csize);
	block += csize;

	if (csize >= 4)
		csize = 4;
	else if (msglen >= (1u << (8 * csize)))
		return -EOVERFLOW;

	data = cpu_to_be32(msglen);
	memcpy(block - csize, (u8 *)&data + 4 - csize, csize);
	return 0;
}

static int format_b0(u8 b0[AES_BLOCK_SIZE], const u8 iv[AES_BLOCK_SIZE],
		     unsigned int authsize, unsigned int assoclen,
		     unsigned int cryptlen)
{
	unsigned int l = iv[0] + 1;

	memcpy(b0, iv, AES_BLOCK_SIZE);
	b0[0] |= 8 * ((authsize - 2) / 2);
	if (assoclen)
		b0[0] |= 64;
	return set_msg_len(b0 + AES_BLOCK_SIZE - l, cryptlen, l);
}

static unsigned int format_adata(u8 adata[6], unsigned int a)
{
	if (a < 65280) {
		adata[0] = a >> 8;
		adata[1] = a;
		return 2;
	}
	adata[0] = 0xff;
	adata[1] = 0xfe;
	adata[2] = a >> 24;
	adata[3] = a >> 16;
	adata[4] = a >> 8;
	adata[5] = a;
	return 6;
}

static void mac_block(const struct crypto_aes_ctx *aes, u8 state[AES_BLOCK_SIZE],
		      const u8 block[AES_BLOCK_SIZE])
{
	aes_mips_cbc_mac(aes, state, block, 1);
}

static void mac_init(struct mac_acc *m, const struct crypto_aes_ctx *aes,
		     const u8 b0[AES_BLOCK_SIZE])
{
	m->n = 0;
	aes_mips_encrypt(aes, m->state, b0);
}

static void mac_feed(struct mac_acc *m, const struct crypto_aes_ctx *aes,
		     const u8 *p, unsigned int len)
{
	while (len) {
		unsigned int take = min_t(unsigned int, len, AES_BLOCK_SIZE - m->n);

		memcpy(m->buf + m->n, p, take);
		m->n += take;
		p += take;
		len -= take;
		if (m->n == AES_BLOCK_SIZE) {
			mac_block(aes, m->state, m->buf);
			m->n = 0;
		}
	}
}

/* Zero-fill only a partial block. An exact multiple stays as it is. */
static void mac_pad(struct mac_acc *m, const struct crypto_aes_ctx *aes)
{
	if (!m->n)
		return;
	memset(m->buf + m->n, 0, AES_BLOCK_SIZE - m->n);
	mac_block(aes, m->state, m->buf);
	m->n = 0;
}

static int mac_sg(struct mac_acc *m, const struct crypto_aes_ctx *aes,
		  struct scatterlist *sg, unsigned int skip, unsigned int len)
{
	if (!len)
		return 0;
	if (sg_at(sg, skip, &sg, &skip))
		return -EINVAL;

	while (len) {
		unsigned int n = min_t(unsigned int, len, sg->length - skip);
		u8 *p = sg_map(sg, skip, &n);
		void *map = p;
		unsigned int took = n;

		if (!m->n && n >= AES_BLOCK_SIZE &&
		    IS_ALIGNED((unsigned long)p, 4)) {
			unsigned int nblocks = n >> 4;

			aes_mips_cbc_mac(aes, m->state, p, nblocks);
			p += nblocks << 4;
			n &= AES_BLOCK_SIZE - 1;
		}
		if (n)
			mac_feed(m, aes, p, n);
		kunmap_local(map);
		len -= took;
		skip += took;
		if (skip == sg->length) {
			sg = sg_next(sg);
			skip = 0;
		}
		if (len && !sg)
			return -EINVAL;
	}
	return 0;
}

static int ccm_mac(const struct crypto_aes_ctx *aes, struct mac_acc *mac,
		   const u8 iv[AES_BLOCK_SIZE], unsigned int authsize,
		   struct scatterlist *asg, struct scatterlist *psg,
		   unsigned int assoclen, unsigned int cryptlen)
{
	u8 b0[AES_BLOCK_SIZE] __aligned(4);
	u8 adata[6];
	int err;

	err = format_b0(b0, iv, authsize, assoclen, cryptlen);
	if (err)
		return err;
	mac_init(mac, aes, b0);
	memzero_explicit(b0, sizeof(b0));

	if (assoclen) {
		mac_feed(mac, aes, adata, format_adata(adata, assoclen));
		err = mac_sg(mac, aes, asg, 0, assoclen);
		if (err)
			return err;
		mac_pad(mac, aes);
	}

	err = mac_sg(mac, aes, psg, assoclen, cryptlen);
	if (err)
		return err;
	mac_pad(mac, aes);
	return 0;
}

static void ctr_iv(u8 ctr[AES_BLOCK_SIZE], const u8 iv[AES_BLOCK_SIZE])
{
	unsigned int l = iv[0] + 1;

	memcpy(ctr, iv, AES_BLOCK_SIZE);
	memset(ctr + AES_BLOCK_SIZE - l, 0, l);
}

static int ccm_crypt(const struct crypto_aes_ctx *aes, const u8 iv[AES_BLOCK_SIZE],
		     unsigned int authsize, struct scatterlist *src,
		     struct scatterlist *dst, unsigned int assoclen,
		     unsigned int cryptlen, bool enc)
{
	struct mac_acc mac = {};
	u8 ctr[AES_BLOCK_SIZE] __aligned(4);
	u8 mask[AES_BLOCK_SIZE] __aligned(4);
	u8 tag[AES_BLOCK_SIZE] __aligned(4);
	u8 have[AES_BLOCK_SIZE] __aligned(4);
	int err;

	if (iv[0] < 1 || iv[0] > 7)
		return -EINVAL;

	ctr_iv(ctr, iv);
	memset(mask, 0, sizeof(mask));
	aes_mips_ctr_crypt(aes, mask, mask, 1, ctr);

	if (enc) {
		err = ccm_mac(aes, &mac, iv, authsize, src, src, assoclen,
			      cryptlen);
		if (err)
			goto out;
		memcpy(tag, mac.state, authsize);
		err = ctr_sg(aes, src, assoclen, dst, assoclen, cryptlen, ctr);
		if (err)
			goto out;
		crypto_xor(tag, mask, authsize);
		scatterwalk_map_and_copy(tag, dst, assoclen + cryptlen,
					 authsize, 1);
	} else {
		scatterwalk_map_and_copy(have, src, assoclen + cryptlen,
					 authsize, 0);
		crypto_xor(have, mask, authsize);
		err = ctr_sg(aes, src, assoclen, dst, assoclen, cryptlen, ctr);
		if (!err) {
			err = ccm_mac(aes, &mac, iv, authsize, src, dst,
				      assoclen, cryptlen);
			if (!err && crypto_memneq(mac.state, have, authsize))
				err = -EBADMSG;
		}
		/* ctr_sg may have stored plaintext before the tag check failed. */
		if (err)
			sg_zero(dst, assoclen, cryptlen);
	}

out:
	memzero_explicit(&mac, sizeof(mac));
	memzero_explicit(ctr, sizeof(ctr));
	memzero_explicit(mask, sizeof(mask));
	memzero_explicit(tag, sizeof(tag));
	memzero_explicit(have, sizeof(have));
	return err;
}

static int ccm_mips_crypt(struct aead_request *req, bool enc)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	unsigned int authsize = crypto_aead_authsize(tfm);
	unsigned int cryptlen = req->cryptlen;

	if (!enc) {
		if (cryptlen < authsize)
			return -EINVAL;
		cryptlen -= authsize;
	}

	return ccm_crypt(crypto_aead_ctx(tfm), req->iv, authsize, req->src,
			 req->dst, req->assoclen, cryptlen, enc);
}

static int ccm_mips_encrypt(struct aead_request *req)
{
	return ccm_mips_crypt(req, true);
}

static int ccm_mips_decrypt(struct aead_request *req)
{
	return ccm_mips_crypt(req, false);
}

static int ccm_mips_setkey(struct crypto_aead *tfm, const u8 *key,
			   unsigned int keylen)
{
	return aes_mips_setkey(crypto_aead_ctx(tfm), key, keylen);
}

static int ccm_mips_setauthsize(struct crypto_aead *tfm, unsigned int authsize)
{
	switch (authsize) {
	case 4:
	case 6:
	case 8:
	case 10:
	case 12:
	case 14:
	case 16:
		return 0;
	default:
		return -EINVAL;
	}
}

static struct aead_alg ccm_aes_alg = {
	.setkey		= ccm_mips_setkey,
	.setauthsize	= ccm_mips_setauthsize,
	.encrypt	= ccm_mips_encrypt,
	.decrypt	= ccm_mips_decrypt,
	.ivsize		= AES_BLOCK_SIZE,
	.maxauthsize	= AES_BLOCK_SIZE,
	.chunksize	= AES_BLOCK_SIZE,
	.base		= {
		.cra_name		= "ccm(aes)",
		.cra_driver_name	= "ccm-aes-mips",
		.cra_priority		= 400,
		.cra_blocksize		= 1,
		.cra_ctxsize		= sizeof(struct crypto_aes_ctx),
		.cra_module		= THIS_MODULE,
	},
};

/* RFC 3610 packet vector 1, via testmgr aes_ccm_tv_template. Tag is 8 bytes. */
static const u8 rfc_key[16] = {
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
};
static const u8 rfc_iv[16] = {
	0x01, 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0x00, 0x00,
};
static const u8 rfc_aad[8] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};
static const u8 rfc_pt[23] = {
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
};
static const u8 rfc_ct[31] = {
	0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2,
	0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
	0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84, 0x17,
	0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0,
};

static int ccm_selftest_buf(const struct crypto_aes_ctx *aes, bool inplace)
{
	u8 src[8 + 31];
	u8 dst[8 + 31];
	u8 back[8 + 23];
	struct scatterlist ssg, dsg;
	int err;

	memcpy(src, rfc_aad, sizeof(rfc_aad));
	memcpy(src + sizeof(rfc_aad), rfc_pt, sizeof(rfc_pt));
	sg_init_one(&ssg, src, sizeof(rfc_aad) + sizeof(rfc_pt));

	if (inplace) {
		sg_init_one(&dsg, src, sizeof(src));
		err = ccm_crypt(aes, rfc_iv, 8, &ssg, &dsg, sizeof(rfc_aad),
				sizeof(rfc_pt), true);
		if (err || memcmp(src + sizeof(rfc_aad), rfc_ct, sizeof(rfc_ct)))
			return -EINVAL;
		return 0;
	}

	sg_init_one(&dsg, dst, sizeof(dst));
	err = ccm_crypt(aes, rfc_iv, 8, &ssg, &dsg, sizeof(rfc_aad),
			sizeof(rfc_pt), true);
	if (err || memcmp(dst + sizeof(rfc_aad), rfc_ct, sizeof(rfc_ct)))
		return -EINVAL;

	/* Encrypt does not copy AAD. Decrypt reads it from src. */
	memcpy(dst, rfc_aad, sizeof(rfc_aad));
	sg_init_one(&ssg, dst, sizeof(rfc_aad) + sizeof(rfc_ct));
	sg_init_one(&dsg, back, sizeof(back));
	err = ccm_crypt(aes, rfc_iv, 8, &ssg, &dsg, sizeof(rfc_aad),
			sizeof(rfc_pt), false);
	if (err || memcmp(back + sizeof(rfc_aad), rfc_pt, sizeof(rfc_pt)))
		return -EINVAL;

	/* A bad tag returns -EBADMSG and leaves zeros where plaintext was. */
	dst[sizeof(rfc_aad) + sizeof(rfc_pt)] ^= 1;
	memset(back, 0xa5, sizeof(back));
	sg_init_one(&ssg, dst, sizeof(rfc_aad) + sizeof(rfc_ct));
	sg_init_one(&dsg, back, sizeof(back));
	err = ccm_crypt(aes, rfc_iv, 8, &ssg, &dsg, sizeof(rfc_aad),
			sizeof(rfc_pt), false);
	if (err != -EBADMSG)
		return -EINVAL;
	{
		unsigned int i;

		for (i = 0; i < sizeof(rfc_pt); i++) {
			if (back[sizeof(rfc_aad) + i])
				return -EINVAL;
		}
	}
	return 0;
}

static int ccm_selftest(void)
{
	struct crypto_aes_ctx aes;
	int err;

	err = aes_mips_setkey(&aes, rfc_key, sizeof(rfc_key));
	if (err)
		goto out;
	err = ccm_selftest_buf(&aes, false);
	if (err) {
		pr_err("ccm-aes-mips: RFC 3610 failed\n");
		goto out;
	}
	err = ccm_selftest_buf(&aes, true);
	if (err)
		pr_err("ccm-aes-mips: RFC 3610 in-place failed\n");
	else
		pr_info("ccm-aes-mips: self-test passed\n");

out:
	memzero_explicit(&aes, sizeof(aes));
	return err;
}

int __init ccm_aes_mips_register(void)
{
	int err;

	err = ccm_selftest();
	if (err)
		return err;
	return crypto_register_aead(&ccm_aes_alg);
}

void __exit ccm_aes_mips_unregister(void)
{
	crypto_unregister_aead(&ccm_aes_alg);
}
