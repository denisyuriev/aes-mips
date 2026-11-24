# Changelog

## 2026-11-24

GCM and CCM share one CTR scatterlist walk in `aes-ctr-walk.c`; the duplicated `ctr_sg` and the former inline helpers leave the glue. `AES_MIPS_CTR_ASM` follows CTR alone (GCM and CCM still select CTR). Big-endian T-tables are swapped once in `aes_mips_mod_init` before the selftest, not lazily on the first setkey. The CTR fast path no longer spills `s4`–`s6` again in `.Lprecompute`: the prologue already keeps them.

## 2026-11-23

CBC-MAC and the fast CTR loop call the AES rounds with `bal` on a label, one copy per key length and per body (base and DSP r1). One indirect jump per call picks the copy. A single block stays on `jalr`. A partial CCM block goes through `aes_mips_cbc_mac` too. On the 74Kc, AES-128 CTR at 1420 bytes is 24.2 MB/s (+2.3% over the previous build) and CCM (`rfc4309`) is 10.6 (+1.9%). On the MT7621 the same points are +0.8% and +1.1%.

## 2026-11-22

OpenWrt feed in this repository. `kmod-crypto-aes-mips` shows up in `make menuconfig` on any MIPS32r2 target (`4kec`, `24kc`, `34kc`, `74kc`, `1004kc`, `mips32r2`), little-endian or big-endian. The module is built out of tree; the OpenWrt kernel tree is not patched.

ECB, CBC, CTR, GCM and CCM can be left out. The cipher stays. GCM and CCM select CTR. CCM also builds CBC-MAC. `make modules AES_MIPS_GCM=n` or the package menu.

## 2026-11-21

Speed on a cold source. ECB, CBC, CBC-MAC and CTR (`aes-mips-core.S`, both endians) issue `pref 4` of the next 32-byte source line. CBC decrypt walks backward and prefetches the previous line. Hint 0 and 4 do not check the cache line against the buffer: on 4K, 24K, 74K and 1004K they do not fault and do not change memory. On a 4 MiB cold buffer, AES-128 at 1420/1424 bytes: CTR +8.8%, ECB +8.0%, CBC +7.8%, GCM encrypt +5.8%, CCM +3.5%. Warm tcrypt drops at most 1.3%. GCM decrypt does not gain: GHASH already prefetches that buffer. Warm tcrypt on MT7621: AES-128 CTR 1420 is 24.8 MB/s, ECB 1424 is 21.3, CBC 1424 is 21.2, GCM 1420 is 17.4, CCM 1420 is 11.0.

## 2026-11-20

Safety and stability. GHASH prefetch of the next block (`mul8k.S`, `mul16k.S`, both endians) runs only when that block's 32-byte cache line lies inside the source buffer. The one-block multiply no longer prefetches past the 16-byte accumulator, and `pref` is no longer in the `bne` delay slot. A prefetch past the buffer can fault on some MIPS32r2 CPUs.
