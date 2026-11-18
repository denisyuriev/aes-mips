// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2003 Dr Brian Gladman, Worcester, UK.
 * Copyright (C) 2006 Rik Snel <rsnel@cube.dyndns.org>
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 *
 * The x^8 reduction table matches xda_le in lib/crypto/gf128mul.c.
 * GHASH tables of 8 and 16 KiB (2 and 4 planes) for MIPS32r2.
 * The multiply is mipsel/ or mips/ mul8k.S and mul16k.S.
 * Row layout matches gf128mul_init_4k_lle: w[0] holds GHASH bytes
 * 12..15, and byte 15 is w[0] & 0xff.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unaligned.h>

#include "ghash-tab.h"

#define GHASH_XDA_LE(i) ( \
	((i) & 0x80 ? 0xe100 : 0) ^ ((i) & 0x40 ? 0x7080 : 0) ^ \
	((i) & 0x20 ? 0x3840 : 0) ^ ((i) & 0x10 ? 0x1c20 : 0) ^ \
	((i) & 0x08 ? 0x0e10 : 0) ^ ((i) & 0x04 ? 0x0708 : 0) ^ \
	((i) & 0x02 ? 0x0384 : 0) ^ ((i) & 0x01 ? 0x01c2 : 0))

#define GHASH_XDA_ROW(q, b) \
	q(b + 0x0), q(b + 0x1), q(b + 0x2), q(b + 0x3), \
	q(b + 0x4), q(b + 0x5), q(b + 0x6), q(b + 0x7), \
	q(b + 0x8), q(b + 0x9), q(b + 0xa), q(b + 0xb), \
	q(b + 0xc), q(b + 0xd), q(b + 0xe), q(b + 0xf)

u16 ghash_xda_le[256] __aligned(512) = {
	GHASH_XDA_ROW(GHASH_XDA_LE, 0x00),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0x10),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0x20),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0x30),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0x40),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0x50),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0x60),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0x70),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0x80),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0x90),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0xa0),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0xb0),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0xc0),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0xd0),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0xe0),
	GHASH_XDA_ROW(GHASH_XDA_LE, 0xf0),
};

void ghash_mips_mul_8k(u32 w[4], const void *tab);
void ghash_mips_mul_8k_blocks(u32 w[4], const void *tab, const u8 *src,
			      unsigned int nblocks);
void ghash_mips_mul_16k(u32 w[4], const void *tab);
void ghash_mips_mul_16k_blocks(u32 w[4], const void *tab, const u8 *src,
			       unsigned int nblocks);

static void mul_x_lle(u8 r[16], const u8 x[16])
{
	u64 a = get_unaligned_be64(x);
	u64 b = get_unaligned_be64(x + 8);
	u64 tt = ((s64)(b << 63) >> 63) & ((u64)0xe1 << 56);

	put_unaligned_be64((b >> 1) | (a << 63), r + 8);
	put_unaligned_be64((a >> 1) ^ tt, r);
}

static void be128_xor(u8 r[16], const u8 a[16], const u8 b[16])
{
	unsigned int i;

	for (i = 0; i < 16; i++)
		r[i] = a[i] ^ b[i];
}

static void mem_to_words(u32 w[4], const u8 e[16])
{
	w[0] = get_unaligned_be32(e + 12);
	w[1] = get_unaligned_be32(e + 8);
	w[2] = get_unaligned_be32(e + 4);
	w[3] = get_unaligned_be32(e);
}

static void ghash_x8(u32 *r0, u32 *r1, u32 *r2, u32 *r3)
{
	u32 tt = ghash_xda_le[*r0 & 0xff];
	u32 n0 = (*r0 >> 8) | (*r1 << 24);
	u32 n1 = (*r1 >> 8) | (*r2 << 24);
	u32 n2 = (*r2 >> 8) | (*r3 << 24);
	u32 n3 = (*r3 >> 8) ^ (tt << 16);

	*r0 = n0;
	*r1 = n1;
	*r2 = n2;
	*r3 = n3;
}

/* planes is 2 or 4 (8 or 16 KiB). tab is 4 KiB-aligned. */
int ghash_tab_init(void *tab, const u8 h[16], unsigned int planes)
{
	u32 (*plane)[256][4] = tab;
	u8 (*b)[16];
	unsigned int i, j, k, v;

	b = kzalloc(256 * 16, GFP_KERNEL);
	if (!b)
		return -ENOMEM;
	memcpy(b[128], h, 16);
	for (j = 64; j > 0; j >>= 1)
		mul_x_lle(b[j], b[j + j]);
	for (j = 2; j < 256; j += j)
		for (k = 1; k < j; k++)
			be128_xor(b[j + k], b[j], b[k]);

	for (i = 0; i < 256; i++)
		mem_to_words(plane[0][i], b[i]);

	for (k = 1; k < planes; k++) {
		for (v = 0; v < 256; v++) {
			u32 r0 = plane[k - 1][v][0];
			u32 r1 = plane[k - 1][v][1];
			u32 r2 = plane[k - 1][v][2];
			u32 r3 = plane[k - 1][v][3];

			ghash_x8(&r0, &r1, &r2, &r3);
			plane[k][v][0] = r0;
			plane[k][v][1] = r1;
			plane[k][v][2] = r2;
			plane[k][v][3] = r3;
		}
	}
	memzero_explicit(b, 256 * 16);
	kfree(b);
	return 0;
}

static void mul_one(u32 *acc, const void *tab, unsigned int kib)
{
	if (kib == 16)
		ghash_mips_mul_16k(acc, tab);
	else
		ghash_mips_mul_8k(acc, tab);
}

static void mul_blocks(u32 *acc, const void *tab, unsigned int kib,
		       const u8 *src, unsigned int nblocks)
{
	if (kib == 16)
		ghash_mips_mul_16k_blocks(acc, tab, src, nblocks);
	else
		ghash_mips_mul_8k_blocks(acc, tab, src, nblocks);
}

static void xor_byte(u32 acc[4], unsigned int pos, u8 v)
{
	unsigned int from_end = 15 - pos;
	unsigned int word = from_end / 4;
	unsigned int shift = (from_end % 4) * 8;

	acc[word] ^= (u32)v << shift;
}

static void xor_block(u32 acc[4], const u8 *src)
{
	acc[3] ^= get_unaligned_be32(src);
	acc[2] ^= get_unaligned_be32(src + 4);
	acc[1] ^= get_unaligned_be32(src + 8);
	acc[0] ^= get_unaligned_be32(src + 12);
}

static void xor_partial(u32 acc[4], unsigned int pos, const u8 *src,
			unsigned int n)
{
	while (n && (pos & 3)) {
		xor_byte(acc, pos++, *src++);
		n--;
	}
	while (n >= 4 && !((unsigned long)src & 3)) {
		acc[3 - (pos >> 2)] ^= get_unaligned_be32(src);
		src += 4;
		pos += 4;
		n -= 4;
	}
	while (n--)
		xor_byte(acc, pos++, *src++);
}

void ghash_acc_init(struct ghash_acc *acc)
{
	memset(acc, 0, sizeof(*acc));
}

void ghash_acc_update(struct ghash_acc *acc, const void *tab, unsigned int kib,
		      const u8 *src, unsigned int srclen)
{
	u32 *w = acc->acc;

	if (acc->room) {
		unsigned int n = min_t(unsigned int, srclen, acc->room);
		unsigned int pos = 16 - acc->room;

		acc->room -= n;
		srclen -= n;
		xor_partial(w, pos, src, n);
		src += n;
		if (!acc->room)
			mul_one(w, tab, kib);
	}

	if (srclen >= 32 && !((unsigned long)src & 3)) {
		unsigned int n = srclen >> 4;

		mul_blocks(w, tab, kib, src, n);
		src += n * 16;
		srclen -= n * 16;
	}

	while (srclen >= 16) {
		xor_block(w, src);
		mul_one(w, tab, kib);
		src += 16;
		srclen -= 16;
	}

	if (srclen) {
		acc->room = 16 - srclen;
		xor_partial(w, 0, src, srclen);
	}
}

void ghash_acc_pad(struct ghash_acc *acc, const void *tab, unsigned int kib)
{
	if (!acc->room)
		return;
	mul_one(acc->acc, tab, kib);
	acc->room = 0;
}

void ghash_acc_lengths(struct ghash_acc *acc, const void *tab, unsigned int kib,
		       unsigned int alen, unsigned int clen)
{
	u64 abits = (u64)alen << 3;
	u64 cbits = (u64)clen << 3;

	acc->acc[3] ^= (u32)(abits >> 32);
	acc->acc[2] ^= (u32)abits;
	acc->acc[1] ^= (u32)(cbits >> 32);
	acc->acc[0] ^= (u32)cbits;
	mul_one(acc->acc, tab, kib);
}

void ghash_acc_final(struct ghash_acc *acc, const void *tab, unsigned int kib,
		     u8 dst[16])
{
	ghash_acc_pad(acc, tab, kib);
	put_unaligned_be32(acc->acc[3], dst);
	put_unaligned_be32(acc->acc[2], dst + 4);
	put_unaligned_be32(acc->acc[1], dst + 8);
	put_unaligned_be32(acc->acc[0], dst + 12);
}
