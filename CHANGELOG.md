# Changelog

## 2026-11-20

Safety and stability. GHASH prefetch of the next block (`mul8k.S`, `mul16k.S`, both endians) runs only when that block's 32-byte cache line lies inside the source buffer. The one-block multiply no longer prefetches past the 16-byte accumulator, and `pref` is no longer in the `bne` delay slot. A prefetch past the buffer can fault on some MIPS32r2 CPUs.
