/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 */
#ifndef _AES_MIPS_H
#define _AES_MIPS_H

#include <crypto/aes.h>
#include <linux/types.h>

/*
 * Key schedule is struct crypto_aes_ctx, filled by aes_expandkey().
 * Callers use aes_mips_setkey(); the library names aes_encrypt and
 * aes_expandkey stay with lib/crypto.
 *
 * Block pointers passed to the multi-block functions are 4-byte aligned.
 * nblocks is the number of 16-byte blocks. cbc and ctr update iv/ctr in place.
 * cbc_mac updates state in place and does not write the ciphertext.
 * cbc decrypt accepts dst == src.
 */

/*
 * Big-endian lw stores AES byte 0 in bits 31:24. Call this once before the
 * first aes_mips_setkey. A second call swaps the planes back.
 */
#ifdef __MIPSEB__
void aes_mips_be_tables(void);
#else
static inline void aes_mips_be_tables(void)
{
}
#endif

int aes_mips_setkey(struct crypto_aes_ctx *ctx, const u8 *in_key,
		    unsigned int key_len);
void aes_mips_encrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);
void aes_mips_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);

void aes_mips_ecb_encrypt(const struct crypto_aes_ctx *ctx, u8 *dst,
			  const u8 *src, unsigned int nblocks);
void aes_mips_ecb_decrypt(const struct crypto_aes_ctx *ctx, u8 *dst,
			  const u8 *src, unsigned int nblocks);
void aes_mips_cbc_encrypt(const struct crypto_aes_ctx *ctx, u8 *dst,
			  const u8 *src, unsigned int nblocks,
			  u8 iv[AES_BLOCK_SIZE]);
void aes_mips_cbc_mac(const struct crypto_aes_ctx *ctx,
		      u8 state[AES_BLOCK_SIZE], const u8 *src,
		      unsigned int nblocks);
void aes_mips_cbc_decrypt(const struct crypto_aes_ctx *ctx, u8 *dst,
			  const u8 *src, unsigned int nblocks,
			  u8 iv[AES_BLOCK_SIZE]);
void aes_mips_ctr_crypt(const struct crypto_aes_ctx *ctx, u8 *dst,
			const u8 *src, unsigned int nblocks,
			u8 ctr[AES_BLOCK_SIZE]);

#endif /* _AES_MIPS_H */
