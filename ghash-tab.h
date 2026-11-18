/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 */
#ifndef _GHASH_TAB_H
#define _GHASH_TAB_H

#include <linux/types.h>

#define GHASH_TAB_BYTES 16384
#define GHASH_TAB_ORDER 2

/* ghash_x8 indexes this by the low byte of a word and loads a u16. */
extern u16 ghash_xda_le[256];

struct ghash_acc {
	u32 acc[4];
	unsigned int room;
};

/* 0 on success, -ENOMEM if the scratch row buffer cannot be allocated. */
int ghash_tab_init(void *tab, const u8 h[16], unsigned int planes);
void ghash_acc_init(struct ghash_acc *acc);
void ghash_acc_update(struct ghash_acc *acc, const void *tab, unsigned int kib,
		      const u8 *src, unsigned int len);
void ghash_acc_pad(struct ghash_acc *acc, const void *tab, unsigned int kib);
void ghash_acc_lengths(struct ghash_acc *acc, const void *tab, unsigned int kib,
		       unsigned int alen, unsigned int clen);
void ghash_acc_final(struct ghash_acc *acc, const void *tab, unsigned int kib,
		     u8 dst[16]);

#endif
