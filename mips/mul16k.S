/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * 16 KiB GHASH multiply for MIPS 1004Kc, big-endian.
 *
 * A native lw is already the big-endian GHASH word, so the loaded
 * words are xored as they stand.
 *
 * w[0] first, then three x^32 reductions each followed by the XOR of
 * four rows. The low byte of a word uses plane 3 (tab + 12288), then
 * plane 2, plane 1, and the high byte uses plane 0.
 *
 * The table is 4 KiB-aligned. a1, a2, a3, t6 keep that base; each byte
 * replaces bits 4..11, which is tab + (byte << 4). Plane and column
 * offsets stay in the load immediate.
 *
 * x^32 is arithmetic, not ghash_xda_le. With d = r0 still live:
 *   n2 = r3 ^ (d << 31) ^ (d << 30) ^ (d << 25)
 *   n3 = d ^ (d >> 1) ^ (d >> 2) ^ (d >> 7)
 * n2 and n3 are written into registers the pointers do not use, and
 * r1/r2 stay where they are, so the word slide costs nothing.
 * The first word has no reduction. After it the accumulator is
 * t0,t1,t2,t3; the reductions leave t1,t2,v0,t3, then t2,v0,t0,t1,
 * then v0,t0,t3,t2.
 *
 * ghash_mips_mul_16k reads the block from memory. The blocks entry
 * keeps that block in s0-s3. The last fold xors straight into those
 * registers. Callers of the blocks entry pass nblocks >= 2 and a
 * 4-byte-aligned src.
 *
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 */

#include <asm/asm.h>
#include <asm/regdef.h>

/*
 * Four loads of one column. into is 1 for the first word, whose
 * accumulator is zero: the fold is written straight into acc.
 * Later words XOR into dest (acc itself, or s0-s3 on the last
 * blocks fold). Clobbers t7, t8, t9, v1.
 */
.macro col_xor acc, p3, p2, p1, p0, into, dest
	lw	t7, \p3(a1)
	lw	t8, \p2(a2)
	lw	t9, \p1(a3)
	lw	v1, \p0(t6)
	xor	t7, t7, t8
	xor	t9, t9, v1
	.if \into
	xor	\acc, t7, t9
	.else
	xor	t7, t7, t9
	xor	\dest, \acc, t7
	.endif
.endm

/*
 * Byte of src into bits 4..11 of each table pointer. Shifts src in
 * place; the word is finished after this.
 */
.macro word_ins src
	ins	a1, \src, 4, 8
	srl	\src, \src, 8
	ins	a2, \src, 4, 8
	srl	\src, \src, 8
	ins	a3, \src, 4, 8
	srl	\src, \src, 8
	ins	t6, \src, 4, 8
.endm

/* src_s is 1 when the word lives in reg, 0 when it was loaded into v1. */
.macro word_ins_src src_s, reg
	.if \src_s
	word_ins \reg
	.else
	word_ins v1
	.endif
.endm

/* Memory path only. The blocks path already holds the word in an s register. */
.macro load_word src_s, off
	.if \src_s
	.else
	lw	v1, \off(a0)
	.endif
.endm

.macro rows_fold c0, c1, c2, c3, into, dst
	.if \dst
	col_xor	\c0, 12288, 8192, 4096, 0, \into, s0
	col_xor	\c1, 12292, 8196, 4100, 4, \into, s1
	col_xor	\c2, 12296, 8200, 4104, 8, \into, s2
	col_xor	\c3, 12300, 8204, 4108, 12, \into, s3
	.else
	col_xor	\c0, 12288, 8192, 4096, 0, \into, \c0
	col_xor	\c1, 12292, 8196, 4100, 4, \into, \c1
	col_xor	\c2, 12296, 8200, 4104, 8, \into, \c2
	col_xor	\c3, 12300, 8204, 4108, 12, \into, \c3
	.endif
.endm

/*
 * n2 = x3 ^ (xd << 31) ^ (xd << 30) ^ (xd << 25)
 * n3 = xd ^ (xd >> 1) ^ (xd >> 2) ^ (xd >> 7)
 * Temps are t4 and t5 only. n3 may be xd: the last srl still reads it.
 * n2 must not be xd, x3, t4, or t5. n3 must not be t4 or t5.
 */
.macro x32_arith xd, x3, n2, n3
	sll	t4, \xd, 31
	sll	t5, \xd, 30
	xor	t4, t4, t5
	sll	t5, \xd, 25
	xor	t4, t4, t5
	xor	\n2, \x3, t4
	srl	t5, \xd, 1
	xor	t4, \xd, t5
	srl	t5, \xd, 2
	xor	t4, t4, t5
	srl	t5, \xd, 7
	xor	\n3, t4, t5
.endm

/*
 * src_s is 0 when the block is at a0, 1 when it is in s0-s3 (s0 is w[0]).
 * On the memory path the next lw is issued before x^32, so ins is not
 * the instruction after the load. The blocks path never loads.
 * into_s is 1 when the last fold writes s0-s3.
 */
.macro mul16k_run src_s, into_s
	.if \src_s
	word_ins s0
	.else
	lw	v1, 0(a0)
	move	a2, a1
	move	a3, a1
	move	t6, a1
	word_ins v1
	.endif
	rows_fold t0, t1, t2, t3, 1, 0
	load_word \src_s, 4
	x32_arith t0, t3, v0, t3
	word_ins_src \src_s, s1
	rows_fold t1, t2, v0, t3, 0, 0
	load_word \src_s, 8
	x32_arith t1, t3, t0, t1
	word_ins_src \src_s, s2
	rows_fold t2, v0, t0, t1, 0, 0
	load_word \src_s, 12
	x32_arith t2, t1, t3, t2
	word_ins_src \src_s, s3
	rows_fold v0, t0, t3, t2, 0, \into_s
.endm

	.text
	.align	5
LEAF(ghash_mips_mul_16k)
	.set	push
	.set	noreorder

	/*
	 * v0,t0,t3,t2  accumulator at the end (r0, r1, r2, r3)
	 * a1,a2,a3,t6  table pointers
	 * v1           loaded input word, then a column load
	 * t4,t5        x^32 temporaries
	 * a0 accumulator, a1 table on entry
	 */
	mul16k_run 0, 0

	sw	v0, 0(a0)
	sw	t0, 4(a0)
	sw	t3, 8(a0)
	jr	ra
	sw	t2, 12(a0)
	.set	pop
END(ghash_mips_mul_16k)

	.align	5
NESTED(ghash_mips_mul_16k_blocks, 24, ra)
	.set	push
	.set	noreorder

	/*
	 * a0 accumulator, a1 table, a2 src, a3 nblocks (>= 2).
	 * s0..s3 running block, s4 src, s5 end of src.
	 * The last fold writes the product into s0..s3. pref is in the
	 * delay slot after addiu, so 16(s4) is the block past the next
	 * iteration. This iteration's multiply has already finished.
	 */
	addiu	sp, sp, -24
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
	sll	a3, a3, 4
	addu	s5, a2, a3
	move	s4, a2
	move	a2, a1
	move	a3, a1
	move	t6, a1

1:
	lw	t4, 0(s4)
	lw	t5, 4(s4)
	lw	t8, 8(s4)
	lw	t7, 12(s4)
	xor	s3, s3, t4
	xor	s2, s2, t5
	xor	s1, s1, t8
	xor	s0, s0, t7
	mul16k_run 1, 1
	addiu	s4, s4, 16
	bne	s4, s5, 1b
	pref	0, 16(s4)

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
	addiu	sp, sp, 24
	.set	pop
END(ghash_mips_mul_16k_blocks)
