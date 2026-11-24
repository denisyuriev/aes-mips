/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
 *
 * AES ECB/CBC/CTR for big-endian MIPS32r2.
 *
 * A native lw has AES byte 0 in bits 31:24. The free ins therefore
 * indexes byte 3 (plane T3). Planes and the key schedule are stored
 * with that same lane order: aes_mips_be_tables swaps the planes once
 * before the first setkey, and aes_mips_setkey byte-swaps the expanded
 * key. Block, IV and CTR words are
 * plain lw/sw. The CTR counter word is already a big-endian integer.
 *
 * One issue, in-order, IPC close to 1: speed is the instruction count.
 *
 * The table base is aligned to 1024, so bits 0..9 of the address are zero.
 * t0-t3 hold that base for the whole call. ins rewrites bits 2..9 with the
 * byte index and leaves the base alone, so no copy per lookup. Table loads
 * land in other registers. The lw displacement selects the plane
 * (0 / 1024 / 2048 / 3072).
 *
 * The state alternates between s0-s3 and t5-t8, so a round has no moves.
 * The rounds are unrolled; the round key is a constant displacement from
 * t4. AES-256 leaves t4 on the schedule. AES-192 and AES-128 point 32 and
 * 64 bytes before it, so every key length enters the same body. The last
 * round loads the S-box byte at +1 inside ft, or byte 0 of the fifth plane
 * of it (the inverse S-box), through the same t0-t3.
 *
 * Core (aes_enc_rounds / aes_dec_rounds, entered with jalr t9 or bal):
 *   in   s0-s3 whitened state, t0-t3 table base, t4 key cursor
 *   out  s0-s3
 *   uses $1, v0, v1, t5-t8
 *
 * Mode loops keep a0 key schedule, a1 dst, a2 src, a3 end, t9 entry,
 * and s4-s7 the first round key. CTR keeps s4-s6 as counter words 0..2
 * whitened with round key 0. s7 is counter word 3 as loaded: a native
 * word is already the big-endian integer, and it is incremented in
 * place. A wrap of s7 carries into words 2, 1, 0 and rebuilds s4-s6.
 * Byte 15 is bits 7:0 of s7, so a run of 256 blocks changes only that
 * byte and CTR skips the first two rounds. The fast loop is a copy
 * per key length and enters at a label (.Le192, .Le128 or .Le128_r2)
 * with bal. One indirect jump per run selects the copy. s8 is the IV
 * pointer on the slow path and round-key byte 15 on that run; the
 * pointer is saved.
 * Blocks are 4-byte aligned. The last round has a DSP r1 copy (lbux);
 * init points the entry table at it when the CPU has DSP. No FPU, no
 * $gp, no $k0/$k1, no HI/LO. The first two rounds of each body stay
 * 512 bytes, so the fast-loop labels land where t9+512 used to.
 */

#include <asm/asm.h>
#include <asm/regdef.h>

.equ	FRAMESZ, 72
.equ	OFF_RA, 36
.equ	OFF_CL, 40
/* CTR only. CBC uses OFF_CL for the saved ciphertext block. */
.equ	OFF_A0, 40
.equ	OFF_I0, 44
.equ	OFF_I1, 48
.equ	OFF_I2, 52
.equ	OFF_IV, 56
.equ	OFF_Z3, 60
/* CTR fast-loop entry, or the CBC-MAC loop entry. Not key material. */
.equ	OFF_FAST, 64

	.macro	save_frame
	addiu	sp, sp, -FRAMESZ
	sw	s0, 0(sp)
	sw	s1, 4(sp)
	sw	s2, 8(sp)
	sw	s3, 12(sp)
	sw	s4, 16(sp)
	sw	s5, 20(sp)
	sw	s6, 24(sp)
	sw	s7, 28(sp)
	sw	s8, 32(sp)
	sw	ra, OFF_RA(sp)
	.endm

	.macro	restore_frame
	lw	ra, OFF_RA(sp)
	lw	s0, 0(sp)
	lw	s1, 4(sp)
	lw	s2, 8(sp)
	lw	s3, 12(sp)
	lw	s4, 16(sp)
	lw	s5, 20(sp)
	lw	s6, 24(sp)
	lw	s7, 28(sp)
	lw	s8, 32(sp)
	jr	ra
	addiu	sp, sp, FRAMESZ
	.endm

	/* One T-table column: dst = T0[w0.b0] ^ T1[w1.b1] ^ T2[w2.b2] ^ T3[w3.b3] ^ k. Byte 0 is bits 31:24. */
	.macro	tcol dst, w0, w1, w2, w3, koff
	srl	$1, \w0, 24
	ins	t0, $1, 2, 8
	srl	$1, \w1, 16
	ins	t1, $1, 2, 8
	srl	$1, \w2, 8
	ins	t2, $1, 2, 8
	ins	t3, \w3, 2, 8
	lw	\dst, 0(t0)
	lw	v0, 1024(t1)
	lw	$1, 2048(t2)
	lw	v1, 3072(t3)
	xor	\dst, \dst, v0
	lw	v0, \koff(t4)
	xor	\dst, \dst, $1
	xor	\dst, \dst, v1
	xor	\dst, \dst, v0
	.endm

	/*
	 * Last-round column: one S-box byte per input word, then the key.
	 * S[w0.b0] lands in bits 31:24 so sw matches memory order. w3's
	 * low byte is AES byte 3 and needs no shift.
	 */
	.macro	lcol dst, w0, w1, w2, w3, koff, boff
	srl	$1, \w0, 24
	ins	t0, $1, 2, 8
	srl	$1, \w1, 16
	ins	t1, $1, 2, 8
	srl	$1, \w2, 8
	ins	t2, $1, 2, 8
	ins	t3, \w3, 2, 8
	lbu	v1, \boff(t0)
	lbu	$1, \boff(t1)
	lbu	v0, \boff(t2)
	lbu	\dst, \boff(t3)
	ins	\dst, v0, 8, 8
	lw	v0, \koff(t4)
	ins	\dst, $1, 16, 8
	ins	\dst, v1, 24, 8
	xor	\dst, \dst, v0
	.endm

	.macro	enc_round i0, i1, i2, i3, o0, o1, o2, o3, r
	tcol	\o0, \i0, \i1, \i2, \i3, 16*\r+16
	tcol	\o1, \i1, \i2, \i3, \i0, 16*\r+20
	tcol	\o2, \i2, \i3, \i0, \i1, 16*\r+24
	tcol	\o3, \i3, \i0, \i1, \i2, 16*\r+28
	.endm

	.macro	dec_round i0, i1, i2, i3, o0, o1, o2, o3, r
	tcol	\o0, \i0, \i3, \i2, \i1, 16*\r+16
	tcol	\o1, \i1, \i0, \i3, \i2, 16*\r+20
	tcol	\o2, \i2, \i1, \i0, \i3, 16*\r+24
	tcol	\o3, \i3, \i2, \i1, \i0, 16*\r+28
	.endm

	.macro	enc_last i0, i1, i2, i3, o0, o1, o2, o3
	lcol	\o0, \i0, \i1, \i2, \i3, 224, 1
	lcol	\o1, \i1, \i2, \i3, \i0, 228, 1
	lcol	\o2, \i2, \i3, \i0, \i1, 232, 1
	lcol	\o3, \i3, \i0, \i1, \i2, 236, 1
	.endm

	.macro	dec_last i0, i1, i2, i3, o0, o1, o2, o3
	lcol	\o0, \i0, \i3, \i2, \i1, 224, 4096
	lcol	\o1, \i1, \i0, \i3, \i2, 228, 4096
	lcol	\o2, \i2, \i1, \i0, \i3, 232, 4096
	lcol	\o3, \i3, \i2, \i1, \i0, 236, 4096
	.endm

	.macro	load_addr reg, sym
	lui	\reg, %hi(\sym)
	addiu	\reg, \reg, %lo(\sym)
	.endm

	.macro	load_tables sym
	load_addr t0, \sym
	move	t1, t0
	move	t2, t0
	move	t3, t0
	.endm

	/*
	 * a0 = ctx on entry. Leaves a0 = schedule (ctx + koff), t4 = key cursor,
	 * t9 = round entry for the key length. fast, when not 0, is the byte
	 * offset of the AES-256 word of a second triple (the CTR loop or the
	 * CBC-MAC loop). The word for this key length is stored at OFF_FAST(sp).
	 *
	 * slot is 0 for encryption and 12 for decryption. Twelve words at
	 * aes_mips_round_entry: six round entries, three CTR loop entries,
	 * three CBC-MAC loop entries. A mode that is not built stores 0.
	 * init copies the DSP table over this one when the CPU has DSP r1.
	 */
	.macro	pick_entry koff, slot, fast=0
	lw	v0, 480(a0)
	addiu	a0, a0, \koff
	lui	t9, %hi(aes_mips_round_entry)
	addiu	t9, t9, %lo(aes_mips_round_entry)
	sltiu	v1, v0, 17
	bnez	v1, 101f
	sltiu	v1, v0, 25
	bnez	v1, 102f
	nop
	.if	\fast
	lw	v1, \fast+0(t9)
	sw	v1, OFF_FAST(sp)
	.endif
	lw	t9, \slot+0(t9)
	b	103f
	move	t4, a0
102:
	.if	\fast
	lw	v1, \fast+4(t9)
	sw	v1, OFF_FAST(sp)
	.endif
	lw	t9, \slot+4(t9)
	b	103f
	addiu	t4, a0, -32
101:
	.if	\fast
	lw	v1, \fast+8(t9)
	sw	v1, OFF_FAST(sp)
	.endif
	lw	t9, \slot+8(t9)
	addiu	t4, a0, -64
103:
	.endm

	.macro	load_round0_key
	lw	s4, 0(a0)
	lw	s5, 4(a0)
	lw	s6, 8(a0)
	lw	s7, 12(a0)
	.endm

	/* s0-s2 = block ^ round key 0 (s4-s6); s3 is left for the jalr slot */
	.macro	load_whiten base
	lw	s0, 0(\base)
	lw	s1, 4(\base)
	lw	s2, 8(\base)
	lw	s3, 12(\base)
	xor	s0, s0, s4
	xor	s1, s1, s5
	xor	s2, s2, s6
	.endm

	.macro	store_block base
	sw	s0, 0(\base)
	sw	s1, 4(\base)
	sw	s2, 8(\base)
	sw	s3, 12(\base)
	.endm

	/* s0-s3 ^= 16 bytes at \off(\base) */
	.macro	xor_mem base, off
	lw	v0, \off+0(\base)
	lw	v1, \off+4(\base)
	lw	$1, \off+8(\base)
	xor	s0, s0, v0
	lw	v0, \off+12(\base)
	xor	s1, s1, v1
	xor	s2, s2, $1
	xor	s3, s3, v0
	.endm

	/* tcol, but the round-key word is already in a register. Byte 0 is bits 31:24. */
	.macro	tcol_rk dst, w0, w1, w2, w3, rk
	srl	$1, \w0, 24
	ins	t0, $1, 2, 8
	srl	$1, \w1, 16
	ins	t1, $1, 2, 8
	srl	$1, \w2, 8
	ins	t2, $1, 2, 8
	ins	t3, \w3, 2, 8
	lw	\dst, 0(t0)
	lw	v0, 1024(t1)
	lw	$1, 2048(t2)
	lw	v1, 3072(t3)
	xor	\dst, \dst, v0
	xor	\dst, \dst, $1
	xor	\dst, \dst, v1
	xor	\dst, \dst, \rk
	.endm

	/* Column 0 of round 1 without T3[byte 15]: that term changes per block. */
	.macro	tcol3 dst, w0, w1, w2, rk
	srl	$1, \w0, 24
	ins	t0, $1, 2, 8
	srl	$1, \w1, 16
	ins	t1, $1, 2, 8
	srl	$1, \w2, 8
	ins	t2, $1, 2, 8
	lw	\dst, 0(t0)
	lw	v0, 1024(t1)
	lw	v1, 2048(t2)
	xor	\dst, \dst, v0
	xor	\dst, \dst, v1
	xor	\dst, \dst, \rk
	.endm

	/*
	 * Last-round column. Byte 0 stays in the T-table and is packed
	 * into bits 31:24. Bytes 1..3 are lbux; S[byte 3] lands in bits 7:0.
	 */
	.macro	lcol_dsp dst, w0, w1, w2, w3, koff, boff, sbox
	srl	$1, \w0, 24
	ins	t0, $1, 2, 8
	ext	$1, \w1, 16, 8
	ext	v0, \w2, 8, 8
	andi	v1, \w3, 0xff
	lbux	\dst, v1(\sbox)
	lbux	v0, v0(\sbox)
	lbux	$1, $1(\sbox)
	lbu	v1, \boff(t0)
	ins	\dst, v0, 8, 8
	lw	v0, \koff(t4)
	ins	\dst, $1, 16, 8
	ins	\dst, v1, 24, 8
	xor	\dst, \dst, v0
	.endm

	.text
	.set	push
	.set	noreorder
	.set	noat
	.set	mips32r2

	.align	5
aes_enc_rounds:
.Le256:
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 0
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 1
.Le192:
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 2
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 3
.Le128:
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 4
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 5
.Le128_r2:
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 6
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 7
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 8
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 9
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 10
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 11
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 12
	enc_last t5, t6, t7, t8, s0, s1, s2, s3
	jr	ra
	nop

	.align	5
aes_dec_rounds:
.Ld256:
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 0
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 1
.Ld192:
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 2
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 3
.Ld128:
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 4
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 5
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 6
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 7
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 8
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 9
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 10
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 11
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 12
	dec_last t5, t6, t7, t8, s0, s1, s2, s3
	jr	ra
	nop

#ifdef TOOLCHAIN_SUPPORTS_DSP
	.set	push
	.set	dsp

	.align	5
aes_enc_rounds_dsp:
.Le256d:
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 0
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 1
.Le192d:
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 2
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 3
.Le128d:
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 4
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 5
.Le128d_r2:
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 6
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 7
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 8
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 9
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 10
	enc_round t5, t6, t7, t8, s0, s1, s2, s3, 11
	enc_round s0, s1, s2, s3, t5, t6, t7, t8, 12
	lui	s3, %hi(crypto_aes_sbox)
	addiu	s3, s3, %lo(crypto_aes_sbox)
	lcol_dsp s0, t5, t6, t7, t8, 224, 1, s3
	lcol_dsp s1, t6, t7, t8, t5, 228, 1, s3
	lcol_dsp s2, t7, t8, t5, t6, 232, 1, s3
	srl	$1, t8, 24
	ins	t0, $1, 2, 8
	move	t8, s3
	ext	$1, t5, 16, 8
	ext	v0, t6, 8, 8
	andi	v1, t7, 0xff
	lbux	s3, v1(t8)
	lbux	v0, v0(t8)
	lbux	$1, $1(t8)
	lbu	v1, 1(t0)
	ins	s3, v0, 8, 8
	lw	v0, 236(t4)
	ins	s3, $1, 16, 8
	ins	s3, v1, 24, 8
	xor	s3, s3, v0
	jr	ra
	nop

	.align	5
aes_dec_rounds_dsp:
.Ld256d:
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 0
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 1
.Ld192d:
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 2
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 3
.Ld128d:
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 4
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 5
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 6
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 7
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 8
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 9
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 10
	dec_round t5, t6, t7, t8, s0, s1, s2, s3, 11
	dec_round s0, s1, s2, s3, t5, t6, t7, t8, 12
	lui	s3, %hi(crypto_aes_inv_sbox)
	addiu	s3, s3, %lo(crypto_aes_inv_sbox)
	lcol_dsp s0, t5, t8, t7, t6, 224, 4096, s3
	lcol_dsp s1, t6, t5, t8, t7, 228, 4096, s3
	lcol_dsp s2, t7, t6, t5, t8, 232, 4096, s3
	srl	$1, t8, 24
	ins	t0, $1, 2, 8
	move	t8, s3
	ext	$1, t7, 16, 8
	ext	v0, t6, 8, 8
	andi	v1, t5, 0xff
	lbux	s3, v1(t8)
	lbux	v0, v0(t8)
	lbux	$1, $1(t8)
	lbu	v1, 4096(t0)
	ins	s3, v0, 8, 8
	lw	v0, 236(t4)
	ins	s3, $1, 16, 8
	ins	s3, v1, 24, 8
	xor	s3, s3, v0
	jr	ra
	nop

	.set	pop
#endif

	.data
	.align	2
	.globl	aes_mips_round_entry
aes_mips_round_entry:
	.word	.Le256
	.word	.Le192
	.word	.Le128
	.word	.Ld256
	.word	.Ld192
	.word	.Ld128
#ifdef AES_MIPS_CTR_ASM
	.word	.Lctr_fast256
	.word	.Lctr_fast192
	.word	.Lctr_fast128
#else
	.word	0
	.word	0
	.word	0
#endif
#ifdef AES_MIPS_CCM
	.word	.Lmac256
	.word	.Lmac192
	.word	.Lmac128
#else
	.word	0
	.word	0
	.word	0
#endif
#ifdef TOOLCHAIN_SUPPORTS_DSP
	.globl	aes_mips_round_entry_dsp
aes_mips_round_entry_dsp:
	.word	.Le256d
	.word	.Le192d
	.word	.Le128d
	.word	.Ld256d
	.word	.Ld192d
	.word	.Ld128d
#ifdef AES_MIPS_CTR_ASM
	.word	.Lctr_fast256d
	.word	.Lctr_fast192d
	.word	.Lctr_fast128d
#else
	.word	0
	.word	0
	.word	0
#endif
#ifdef AES_MIPS_CCM
	.word	.Lmac256d
	.word	.Lmac192d
	.word	.Lmac128d
#else
	.word	0
	.word	0
	.word	0
#endif
#endif
	.text

	/*
	 * Next source line, hint 4 (load_streamed, way 0). For a 16-byte
	 * block, 32(a2) names the same line as ((a2 + 64) & ~31) - 32.
	 * Hint 0 and 4 do not take a bounds check on 4K, 24K, 74K, 1004K.
	 */
	.macro	pref_fwd
	pref	4, 32(a2)
	.endm

	/*
	 * CBC decrypt walks down. -32(a2) names the same previous line as
	 * (a2 & ~31) - 32 when the block is 16-byte aligned.
	 */
	.macro	pref_back
	pref	4, -32(a2)
	.endm

	.align	5
NESTED(aes_mips_ecb_encrypt, FRAMESZ, ra)
	save_frame
	beqz	a3, .Lecb_enc_out
	nop
	pick_entry 0, 0
	load_round0_key
	load_tables aes_mips_ft_tab
	sll	a3, a3, 4
	addu	a3, a2, a3
.Lecb_enc_loop:
	pref_fwd
	load_whiten a2
	jalr	t9
	xor	s3, s3, s7
	store_block a1
	addiu	a2, a2, 16
	bne	a2, a3, .Lecb_enc_loop
	addiu	a1, a1, 16
.Lecb_enc_out:
	restore_frame
END(aes_mips_ecb_encrypt)

	.align	5
NESTED(aes_mips_ecb_decrypt, FRAMESZ, ra)
	save_frame
	beqz	a3, .Lecb_dec_out
	nop
	pick_entry 240, 12
	load_round0_key
	load_tables aes_mips_it_tab
	sll	a3, a3, 4
	addu	a3, a2, a3
.Lecb_dec_loop:
	pref_fwd
	load_whiten a2
	jalr	t9
	xor	s3, s3, s7
	store_block a1
	addiu	a2, a2, 16
	bne	a2, a3, .Lecb_dec_loop
	addiu	a1, a1, 16
.Lecb_dec_out:
	restore_frame
END(aes_mips_ecb_decrypt)

#ifdef AES_MIPS_CBC
	/*
	 * The IV is loaded into s0-s3 below. After the first block the
	 * chain is the previous ciphertext, still in those registers.
	 */
	.align	5
NESTED(aes_mips_cbc_encrypt, FRAMESZ, ra)
	save_frame
	beqz	a3, .Lcbc_enc_out
	lw	s8, FRAMESZ+16(sp)
	pick_entry 0, 0
	load_round0_key
	load_tables aes_mips_ft_tab
	sll	a3, a3, 4
	addu	a3, a2, a3
	lw	s0, 0(s8)
	lw	s1, 4(s8)
	lw	s2, 8(s8)
	lw	s3, 12(s8)
.Lcbc_enc_loop:
	pref_fwd
	xor_mem	a2, 0
	xor	s0, s0, s4
	xor	s1, s1, s5
	xor	s2, s2, s6
	jalr	t9
	xor	s3, s3, s7
	store_block a1
	addiu	a2, a2, 16
	bne	a2, a3, .Lcbc_enc_loop
	addiu	a1, a1, 16
	store_block s8
.Lcbc_enc_out:
	restore_frame
END(aes_mips_cbc_encrypt)
#endif

#ifdef AES_MIPS_CCM
	/*
	 * One copy per key length. bal is predicted; the indirect jump that
	 * picks the copy runs once per call. The bne slot stays empty: filling
	 * it would move the source pointer or the prefetch address.
	 */
	.macro	mac_loop target
.Lml_\@:
	pref_fwd
	xor_mem	a2, 0
	xor	s0, s0, s4
	xor	s1, s1, s5
	xor	s2, s2, s6
	bal	\target
	xor	s3, s3, s7
	addiu	a2, a2, 16
	bne	a2, a3, .Lml_\@
	nop
	b	.Lcbc_mac_store
	nop
	.endm

	/* Same chain as CBC encrypt. Ciphertext is not stored. */
	.align	5
NESTED(aes_mips_cbc_mac, FRAMESZ, ra)
	save_frame
	beqz	a3, .Lcbc_mac_out
	move	s8, a1
	pick_entry 0, 0, 36
	load_round0_key
	load_tables aes_mips_ft_tab
	sll	a3, a3, 4
	addu	a3, a2, a3
	lw	s0, 0(s8)
	lw	s1, 4(s8)
	lw	s2, 8(s8)
	lw	s3, 12(s8)
	lw	v0, OFF_FAST(sp)
	jr	v0
	nop
.Lmac256:
	mac_loop .Le256
.Lmac192:
	mac_loop .Le192
.Lmac128:
	mac_loop .Le128
#ifdef TOOLCHAIN_SUPPORTS_DSP
.Lmac256d:
	mac_loop .Le256d
.Lmac192d:
	mac_loop .Le192d
.Lmac128d:
	mac_loop .Le128d
#endif
.Lcbc_mac_store:
	store_block s8
.Lcbc_mac_out:
	restore_frame
END(aes_mips_cbc_mac)
#endif


#ifdef AES_MIPS_CBC
	/*
	 * Last block first: block i takes its chain from src[i - 1], which is
	 * still ciphertext even in place. Block 0 takes the IV. The last
	 * ciphertext block, the next IV, is copied to the stack before any
	 * store.
	 */
	.align	5
NESTED(aes_mips_cbc_decrypt, FRAMESZ, ra)
	save_frame
	beqz	a3, .Lcbc_dec_out
	lw	s8, FRAMESZ+16(sp)
	pick_entry 240, 12
	load_round0_key
	load_tables aes_mips_it_tab
	addiu	a3, a3, -1
	sll	a3, a3, 4
	move	v0, a2
	addu	a2, a2, a3
	addu	a1, a1, a3
	move	a3, v0
	lw	v0, 0(a2)
	lw	v1, 4(a2)
	sw	v0, OFF_CL+0(sp)
	sw	v1, OFF_CL+4(sp)
	lw	v0, 8(a2)
	lw	v1, 12(a2)
	sw	v0, OFF_CL+8(sp)
	beq	a2, a3, .Lcbc_dec_first
	sw	v1, OFF_CL+12(sp)
.Lcbc_dec_loop:
	pref_back
	load_whiten a2
	jalr	t9
	xor	s3, s3, s7
	xor_mem	a2, -16
	store_block a1
	addiu	a2, a2, -16
	bne	a2, a3, .Lcbc_dec_loop
	addiu	a1, a1, -16
.Lcbc_dec_first:
	load_whiten a2
	jalr	t9
	xor	s3, s3, s7
	xor_mem	s8, 0
	store_block a1
	lw	v0, OFF_CL+0(sp)
	lw	v1, OFF_CL+4(sp)
	sw	v0, 0(s8)
	sw	v1, 4(s8)
	lw	v0, OFF_CL+8(sp)
	lw	v1, OFF_CL+12(sp)
	sw	v0, 8(s8)
	sw	v1, 12(s8)
.Lcbc_dec_out:
	restore_frame
END(aes_mips_cbc_decrypt)
#endif

#ifdef AES_MIPS_CTR_ASM
	/*
	 * s4-s6 = counter words 0..2 (as loaded) ^ round key 0.
	 * s7 = counter word 3 as loaded. A native word is already the
	 * big-endian integer, incremented per block. A wrap of s7 carries
	 * into words 2, 1, 0; that path rebuilds s4-s6.
	 *
	 * Byte 15 is bits 7:0 of s7. It is the only counter byte that
	 * changes inside a run of 256 blocks, so rounds 1 and 2 collapse to
	 * one T3 lookup and four more. The run enters a per-key copy of the
	 * loop and that copy branches to the label two rounds in (.Le192,
	 * .Le128 or .Le128_r2). Fewer than two blocks left in the request or
	 * in the run stay on the full entry, jalr t9. Across that run
	 * a0/s4-s6/s8 hold X0/Z0-Z2/K; the schedule, the whitened words, the
	 * IV pointer and the loop entry sit in the frame. Z3 is loaded per
	 * block.
	 */
	.macro	ctr_carry sreg, koff
	lw	v1, \koff(a0)
	xor	v0, \sreg, v1
	addiu	v0, v0, 1
	xor	\sreg, v0, v1
	.endm

	.macro	ctr_store
	lw	v0, 0(a2)
	lw	v1, 4(a2)
	lw	$1, 8(a2)
	xor	v0, v0, s0
	sw	v0, 0(a1)
	lw	v0, 12(a2)
	xor	v1, v1, s1
	sw	v1, 4(a1)
	xor	$1, $1, s2
	sw	$1, 8(a1)
	xor	v0, v0, s3
	sw	v0, 12(a1)
	.endm

	.macro	ctr_fast target
.Lcf_\@:
	pref_fwd
	lw	t8, OFF_Z3(sp)
	andi	v0, s7, 0xff
	xor	v0, v0, s8
	ins	t3, v0, 2, 8
	lw	v0, 3072(t3)
	xor	v0, v0, a0
	srl	$1, v0, 24
	ins	t0, $1, 2, 8
	srl	$1, v0, 16
	ins	t1, $1, 2, 8
	srl	$1, v0, 8
	ins	t2, $1, 2, 8
	ins	t3, v0, 2, 8
	lw	s0, 0(t0)
	lw	s3, 1024(t1)
	lw	s2, 2048(t2)
	lw	s1, 3072(t3)
	xor	s0, s0, s4
	xor	s2, s2, s6
	xor	s3, s3, t8
	bal	\target
	xor	s1, s1, s5
	ctr_store
	addiu	s7, s7, 1
	andi	v0, s7, 0xff
	beqz	v0, .Lfast_wrap
	addiu	a2, a2, 16
	bne	a2, a3, .Lcf_\@
	addiu	a1, a1, 16
	b	.Lctr_finish
	nop
	.endm

	.align	5
NESTED(aes_mips_ctr_crypt, FRAMESZ, ra)
	save_frame
	beqz	a3, .Lctr_out
	lw	s8, FRAMESZ+16(sp)
	pick_entry 0, 0, 24
	load_tables aes_mips_ft_tab
	sll	a3, a3, 4
	addu	a3, a2, a3
	lw	v0, 0(s8)
	lw	v1, 0(a0)
	lw	$1, 4(s8)
	xor	s4, v0, v1
	lw	v0, 4(a0)
	lw	v1, 8(s8)
	xor	s5, $1, v0
	lw	$1, 8(a0)
	lw	s7, 12(s8)
	xor	s6, v1, $1
	sw	s8, OFF_IV(sp)
	sw	a0, OFF_A0(sp)
	sw	s4, OFF_I0(sp)
	sw	s5, OFF_I1(sp)
	sw	s6, OFF_I2(sp)
.Lctr_dispatch:
	subu	v0, a3, a2
	srl	v0, v0, 4
	sltiu	v1, v0, 2
	bnez	v1, .Lslow_one
	andi	v0, s7, 0xff
	xori	v0, v0, 0xff
	bnez	v0, .Lprecompute
	nop
.Lslow_one:
	beq	a2, a3, .Lctr_finish
	nop
	lw	v0, 12(a0)
	move	s0, s4
	move	s1, s5
	move	s2, s6
	jalr	t9
	xor	s3, s7, v0
	ctr_store
	addiu	s7, s7, 1
	beqz	s7, .Lslow_carry
	addiu	a2, a2, 16
	b	.Lctr_dispatch
	addiu	a1, a1, 16
.Lslow_carry:
	addiu	a1, a1, 16
.Lctr_carry:
	ctr_carry s6, 8
	bnez	v0, .Lcarry_spill
	nop
	ctr_carry s5, 4
	bnez	v0, .Lcarry_spill
	nop
	ctr_carry s4, 0
.Lcarry_spill:
	sw	s4, OFF_I0(sp)
	sw	s5, OFF_I1(sp)
	sw	s6, OFF_I2(sp)
	b	.Lctr_dispatch
	nop

	/*
	 * i0-i2 are s4-s6, i3 is the whitened counter word 3. Y1-Y3 are
	 * round-1 columns 1-3. X0 is column 0 without T3[byte 15].
	 * Z0-Z3 are round-2 columns with the one lookup that depends on
	 * that byte left out. K, the key's byte 15, is the low byte of
	 * that key word and is kept in s8. s4-s6 already match OFF_I0..I2:
	 * the prologue, .Lcarry_spill and .Lfast_wrap keep them.
	 */
.Lprecompute:
	lw	v1, 12(a0)
	xor	s0, s7, v1
	andi	s8, v1, 0xff
	lw	s1, 20(a0)
	tcol_rk	s2, s5, s6, s0, s4, s1
	lw	s1, 24(a0)
	tcol_rk	s3, s6, s0, s4, s5, s1
	lw	s1, 28(a0)
	tcol_rk	t5, s0, s4, s5, s6, s1
	lw	t8, 16(a0)
	tcol3	s1, s4, s5, s6, t8
	srl	$1, s2, 16
	ins	t1, $1, 2, 8
	srl	$1, s3, 8
	ins	t2, $1, 2, 8
	ins	t3, t5, 2, 8
	lw	s4, 1024(t1)
	lw	v0, 2048(t2)
	lw	v1, 3072(t3)
	xor	s4, s4, v0
	lw	v0, 32(a0)
	xor	s4, s4, v1
	xor	s4, s4, v0
	srl	$1, s2, 24
	ins	t0, $1, 2, 8
	srl	$1, s3, 16
	ins	t1, $1, 2, 8
	srl	$1, t5, 8
	ins	t2, $1, 2, 8
	lw	s5, 0(t0)
	lw	v0, 1024(t1)
	lw	v1, 2048(t2)
	xor	s5, s5, v0
	lw	v0, 36(a0)
	xor	s5, s5, v1
	xor	s5, s5, v0
	srl	$1, s3, 24
	ins	t0, $1, 2, 8
	srl	$1, t5, 16
	ins	t1, $1, 2, 8
	ins	t3, s2, 2, 8
	lw	s6, 0(t0)
	lw	v0, 1024(t1)
	lw	v1, 3072(t3)
	xor	s6, s6, v0
	lw	v0, 40(a0)
	xor	s6, s6, v1
	xor	s6, s6, v0
	srl	$1, t5, 24
	ins	t0, $1, 2, 8
	srl	$1, s2, 8
	ins	t2, $1, 2, 8
	ins	t3, s3, 2, 8
	lw	t8, 0(t0)
	lw	v0, 2048(t2)
	lw	v1, 3072(t3)
	xor	t8, t8, v0
	lw	v0, 44(a0)
	xor	t8, t8, v1
	xor	t8, t8, v0
	sw	t8, OFF_Z3(sp)
	move	a0, s1
	lw	v0, OFF_FAST(sp)
	jr	v0
	nop
.Lctr_fast256:
	ctr_fast .Le192
.Lctr_fast192:
	ctr_fast .Le128
.Lctr_fast128:
	ctr_fast .Le128_r2
#ifdef TOOLCHAIN_SUPPORTS_DSP
.Lctr_fast256d:
	ctr_fast .Le192d
.Lctr_fast192d:
	ctr_fast .Le128d
.Lctr_fast128d:
	ctr_fast .Le128d_r2
#endif
.Lfast_wrap:
	addiu	a1, a1, 16
	lw	a0, OFF_A0(sp)
	lw	s4, OFF_I0(sp)
	lw	s5, OFF_I1(sp)
	lw	s6, OFF_I2(sp)
	beqz	s7, .Lctr_carry
	nop
	bne	a2, a3, .Lctr_dispatch
	nop
.Lctr_finish:
	lw	a0, OFF_A0(sp)
	lw	s4, OFF_I0(sp)
	lw	s5, OFF_I1(sp)
	lw	s6, OFF_I2(sp)
	lw	s8, OFF_IV(sp)
	sw	$0, OFF_I0(sp)
	sw	$0, OFF_I1(sp)
	sw	$0, OFF_I2(sp)
	sw	$0, OFF_Z3(sp)
	lw	v0, 0(a0)
	lw	v1, 4(a0)
	lw	$1, 8(a0)
	xor	v0, v0, s4
	sw	v0, 0(s8)
	xor	v1, v1, s5
	sw	v1, 4(s8)
	xor	$1, $1, s6
	sw	$1, 8(s8)
	sw	s7, 12(s8)
.Lctr_out:
	restore_frame
END(aes_mips_ctr_crypt)
#endif

	.set	pop
