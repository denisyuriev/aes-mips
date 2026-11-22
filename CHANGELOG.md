# Changelog

## 2026-11-22

OpenWrt feed in this repository. `kmod-crypto-aes-mips` shows up in `make menuconfig` on any MIPS32r2 target (`4kec`, `24kc`, `34kc`, `74kc`, `1004kc`, `mips32r2`), little-endian or big-endian. The module is built out of tree; the OpenWrt kernel tree is not patched.

## 2026-11-21

Speed on a cold source. ECB, CBC, CBC-MAC and CTR (`aes-mips-core.S`, both endians) issue `pref 4` of the next 32-byte source line. CBC decrypt walks backward and prefetches the previous line. Hint 0 and 4 do not check the cache line against the buffer: on 4K, 24K, 74K and 1004K they do not fault and do not change memory. On a 4 MiB cold buffer, AES-128 at 1420/1424 bytes: CTR +8.8%, ECB +8.0%, CBC +7.8%, GCM encrypt +5.8%, CCM +3.5%. Warm tcrypt drops at most 1.3%. GCM decrypt does not gain: GHASH already prefetches that buffer. Warm tcrypt on MT7621: AES-128 CTR 1420 is 24.8 MB/s, ECB 1424 is 21.3, CBC 1424 is 21.2, GCM 1420 is 17.4, CCM 1420 is 11.0.

## 2026-11-20

Safety and stability. GHASH prefetch of the next block (`mul8k.S`, `mul16k.S`, both endians) runs only when that block's 32-byte cache line lies inside the source buffer. The one-block multiply no longer prefetches past the 16-byte accumulator, and `pref` is no longer in the `bne` delay slot. A prefetch past the buffer can fault on some MIPS32r2 CPUs.
