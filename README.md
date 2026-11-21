# aes-mips

[Русский](README.ru.md)

Copyright (C) 2026 Denis Iurev &lt;denis.yuriev@icloud.com&gt;

Software AES for MIPS32r2. Kernel module `aes-mips` (`CONFIG_CRYPTO_AES_MIPS32R2`), [GPL-2.0](LICENSE) (see also [COPYING](COPYING)).

Written and tested against Linux 6.18.

Registers:
- `cipher` (priority 200)
  - `aes` / `aes-mips`
- `skcipher` (priority 300)
  - `ecb(aes)` / `ecb-aes-mips`
  - `cbc(aes)` / `cbc-aes-mips`
  - `ctr(aes)` / `ctr-aes-mips`
- `AEAD` (priority 400)
  - `gcm(aes)` / `gcm-aes-mips`
  - `ccm(aes)` / `ccm-aes-mips`

AES rounds use Gladman T-tables in assembly; little-endian (`mipsel/`) and big-endian (`mips/`) builds are included.

GHASH uses a 16 KiB table when L1 D is at least 32 KiB, otherwise 8 KiB (chosen at load time).

A small last-round AES tweak for DSPr1 (`LBUX`) when the ASE is present on the CPU.

Sources are meant for `arch/mips/crypto/` in the kernel tree. `Makefile` and `Kconfig` are in-tree style.

Primary development platform: MediaTek MT7621 (1004Kc).
BE checks: qemu (`-M malta -cpu 24Kc`).

## Performance on MT7621 (1004Kc)

Kernel 6.18.60. `aes-mips` column: 21 November 2026, three runs, median. `generic` is the 20 November session and was not remeasured.

### `tcrypt` (MB/s)

Encryption.

ECB/CBC — 1424-byte blocks;
CTR/GCM/CCM — 1420-byte blocks.

`generic` — the kernel’s default software AES;
`aes-mips` — this module.

| | generic | aes-mips | Δ |
|---|---:|---:|---:|
| AES-128-ECB | 15.1 | 21.3 | +41% |
| AES-192-ECB | 12.8 | 17.8 | +39% |
| AES-256-ECB | 11.1 | 15.3 | +38% |
| AES-128-CBC | 13.0 | 21.2 | +63% |
| AES-192-CBC | 11.2 | 17.7 | +58% |
| AES-256-CBC | 9.9 | 15.3 | +55% |
| AES-128-CTR | 13.6 | 24.8 | +82% |
| AES-192-CTR | 11.6 | 20.2 | +74% |
| AES-256-CTR | 10.2 | 17.0 | +67% |
| AES-128-GCM | 7.3 | 17.4 | +138% |
| AES-192-GCM | 6.7 | 15.0 | +124% |
| AES-256-GCM | 6.2 | 13.2 | +113% |
| AES-128-CCM (`rfc4309`) | 6.5 | 11.0 | +69% |

### OpenVPN DCO (AES-128-GCM)

Measured with iperf3 TCP (three 10-second runs), Mbit/s.

`generic` — the kernel’s default software AES;
`aes-mips` — this module.

`send` — encryption on the router;
`reverse` — decryption on the router.

| | generic | aes-mips | Δ |
|---|---:|---:|---:|
| reverse | 41.2 | 66.7 | +62% |
| send | 30.5 | 50.6 | +66% |
