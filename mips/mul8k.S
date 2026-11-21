/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * 8 KiB GHASH multiply for MIPS 1004Kc, big-endian.
 *
 * A native lw is already the big-endian GHASH word, so the loaded
 * words are xored as they stand.
 *
 * The low half of w[0] first, then seven x^16 steps. The low byte of a
 * half is plane 1 (table + 4096). The high byte is plane 0.
 *
 * Both pointers are copies of the 4 KiB-aligned base. A byte index is
 * bits 4..11 (ins), and the plane offset stays in the lw immediate.
 * That replaces two ext, two sll and two addu. ins and the lw of that
 * pointer are at least two instructions apart. x^16 is:
 *   u = r0 << 16
 *   red = u ^ (u >> 1) ^ (u >> 2) ^ (u >> 7)
 *   n3 = (r3 >> 16) ^ red
 * DSP does not shorten this: the shifts cross a halfword, and lwx
 * cannot serve the other three words of the row.
 *
 * The blocks entry folds the last half into s0-s3. The next source
 * block is prefetched only when its 32-byte line lies inside the
 * source buffer. The one-block leaf does not prefetch: the accumulator
 * is 16 bytes.
 *
 * ghash_mips_mul_8k(acc, tab)
 * ghash_mips_mul_8k_blocks(acc, tab, src, nblocks)  nblocks >= 2, src aligned 4
 *
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 */

#include <asm/regdef.h>

.macro mul8k_x16
	sll	t4, t0, 16
	srl	t5, t4, 1
	xor	t5, t4, t5
	srl	t6, t4, 2
	xor	t5, t5, t6
	srl	t6, t4, 7
	xor	t4, t5, t6
.endm

/*
 * v1 holds the half in its low 16 bits. a2 and a3 are the two bases.
 * On entry t4 is red of the current accumulator. fold 0 writes t0-t3
 * and reduces by x^16. fold 1 writes s0-s3 and does not reduce: the
 * last half of the blocks path. fold 2 writes t0-t3 and does not
 * reduce: the last half of the leaf. reload 0 uses v1 as it stands;
 * 1..3 move s1..s3; 4..6 load a0+4/8/12.
 */
.macro mul8k_half reload fold
	.if \reload == 1
	move	v1, s1
	.elseif \reload == 2
	move	v1, s2
	.elseif \reload == 3
	move	v1, s3
	.elseif \reload == 4
	lw	v1, 4(a0)
	.elseif \reload == 5
	lw	v1, 8(a0)
	.elseif \reload == 6
	lw	v1, 12(a0)
	.endif
	ins	a2, v1, 4, 8
	srl	v1, v1, 8
	ins	a3, v1, 4, 8
	srl	v1, v1, 8
	srl	t5, t0, 16
	lw	t6, 4096(a2)
	lw	t7, 0(a3)
	lw	t8, 4100(a2)
	lw	t9, 4(a3)
	xor	t6, t6, t7
	lw	t7, 4104(a2)
	ins	t5, t1, 16, 16
	xor	t8, t8, t9
	lw	t9, 8(a3)
	xor	t7, t7, t9
	lw	t9, 4108(a2)
	srl	t0, t1, 16
	ins	t0, t2, 16, 16
	srl	t1, t2, 16
	lw	t2, 12(a3)
	ins	t1, t3, 16, 16
	srl	t3, t3, 16
	xor	t3, t3, t4
	xor	t9, t9, t2
	.if \fold == 1
	xor	s2, t1, t7
	xor	s1, t0, t8
	xor	s0, t5, t6
	xor	s3, t3, t9
	.else
	xor	t2, t1, t7
	xor	t1, t0, t8
	xor	t0, t5, t6
	xor	t3, t3, t9
	.if \fold == 0
	mul8k_x16
	.endif
	.endif
.endm

/* First half: the accumulator is the two rows. Leaves red in t4. */
.macro mul8k_open
	ins	a2, v1, 4, 8
	srl	v1, v1, 8
	ins	a3, v1, 4, 8
	srl	v1, v1, 8
	lw	t0, 4096(a2)
	lw	t6, 0(a3)
	lw	t1, 4100(a2)
	lw	t8, 4(a3)
	xor	t0, t0, t6
	lw	t6, 4104(a2)
	xor	t1, t1, t8
	lw	t8, 8(a3)
	lw	t9, 4108(a2)
	xor	t2, t6, t8
	lw	t6, 12(a3)
	xor	t3, t9, t6
	mul8k_x16
.endm

	.text
	.set	mips32r2
	.set	noreorder
	.set	noat

	.align	5
	.globl	ghash_mips_mul_8k
	.ent	ghash_mips_mul_8k
ghash_mips_mul_8k:
	move	a2, a1
	move	a3, a1
	lw	v1, 0(a0)
	mul8k_open
	mul8k_half 0, 0
	mul8k_half 4, 0
	mul8k_half 0, 0
	mul8k_half 5, 0
	mul8k_half 0, 0
	mul8k_half 6, 0
	mul8k_half 0, 2
	sw	t0, 0(a0)
	sw	t1, 4(a0)
	sw	t2, 8(a0)
	jr	ra
	sw	t3, 12(a0)
	.end	ghash_mips_mul_8k

	.align	5
	.globl	ghash_mips_mul_8k_blocks
	.ent	ghash_mips_mul_8k_blocks
ghash_mips_mul_8k_blocks:
	addiu	sp, sp, -32
	sw	s0, 0(sp)
	sw	s1, 4(sp)
	sw	s2, 8(sp)
	sw	s3, 12(sp)
	sw	s4, 16(sp)
	sw	s5, 20(sp)
	lw	s0, 0(a0)
	lw	s1, 4(a0)
	lw	s2, 8(a0)
	lw	s3, 12(a0)
	move	s4, a2
	sll	a3, a3, 4
	addu	s5, s4, a3
	move	a2, a1
	move	a3, a1

1:
	lw	t4, 0(s4)
	lw	t5, 4(s4)
	lw	t6, 8(s4)
	lw	t7, 12(s4)
	xor	s3, s3, t4
	xor	s2, s2, t5
	xor	s1, s1, t6
	xor	s0, s0, t7
	move	v1, s0
	pref	0, 16(s4)
	mul8k_open
	mul8k_half 0, 0
	mul8k_half 1, 0
	mul8k_half 0, 0
	mul8k_half 2, 0
	mul8k_half 0, 0
	mul8k_half 3, 0
	mul8k_half 0, 1
	addiu	s4, s4, 16
	bne	s4, s5, 1b
	nop

	sw	s0, 0(a0)
	sw	s1, 4(a0)
	sw	s2, 8(a0)
	sw	s3, 12(a0)
	lw	s0, 0(sp)
	lw	s1, 4(sp)
	lw	s2, 8(sp)
	lw	s3, 12(sp)
	lw	s4, 16(sp)
	lw	s5, 20(sp)
	jr	ra
	addiu	sp, sp, 32
	.end	ghash_mips_mul_8k_blocks
