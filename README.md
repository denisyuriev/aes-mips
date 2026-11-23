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

First board: TP-Link Archer C6U v1, MediaTek MT7621 (MIPS 1004Kc little-endian).

Second board: MikroTik RB951Ui-2HnD, Atheros AR9344 (MIPS 74Kc, big-endian).

Both byte orders are also checked in qemu (`-M malta -cpu 24Kc`).

## OpenWrt

The module is not in the OpenWrt tree.

This repository is an external feed. The package appears in `make menuconfig` only for these OpenWrt CPU types: `4kec`, `24kc`, `34kc`, `74kc`, `1004kc`, `mips32r2`.

1. Add to `feeds.conf` (the feed name may not contain `-`):

       src-git aes_mips https://github.com/denisyuriev/aes-mips.git

2. `./scripts/feeds update aes_mips`
3. `./scripts/feeds install -p aes_mips -a`
4. Select a MIPS32r2 target.
5. Kernel modules → Cryptographic API modules → `kmod-crypto-aes-mips` as `<*>`.
6. Build the image as usual.

`<*>` puts `aes-mips.ko` into the image. The module loads on boot. `/proc/crypto` then lists `aes-mips`, `ecb-aes-mips`, `cbc-aes-mips`, `ctr-aes-mips`, `gcm-aes-mips`, and `ccm-aes-mips`.

## Performance

`generic` — the kernel’s default software AES;
`aes-mips` — this module.
Three runs, median.

### `tcrypt` (MB/s)

Encryption. ECB/CBC — 1424-byte blocks; CTR/GCM/CCM — 1420-byte blocks.

<table>
<thead>
<tr>
<th rowspan="2"></th>
<th colspan="3" align="center">MT7621 (1004Kc)</th>
<th colspan="3" align="center">AR9344 (74Kc)</th>
</tr>
<tr>
<th align="right">generic</th>
<th align="right">aes-mips</th>
<th align="right">Δ</th>
<th align="right">generic</th>
<th align="right">aes-mips</th>
<th align="right">Δ</th>
</tr>
</thead>
<tbody>
<tr><td>AES-128-ECB</td><td align="right">15.1</td><td align="right">21.3</td><td align="right">+41%</td><td align="right">11.9</td><td align="right">20.4</td><td align="right">+72%</td></tr>
<tr><td>AES-192-ECB</td><td align="right">12.8</td><td align="right">17.8</td><td align="right">+39%</td><td align="right">10.2</td><td align="right">17.2</td><td align="right">+69%</td></tr>
<tr><td>AES-256-ECB</td><td align="right">11.1</td><td align="right">15.3</td><td align="right">+38%</td><td align="right">8.9</td><td align="right">14.9</td><td align="right">+67%</td></tr>
<tr><td>AES-128-CBC</td><td align="right">13.0</td><td align="right">21.2</td><td align="right">+63%</td><td align="right">10.3</td><td align="right">20.4</td><td align="right">+97%</td></tr>
<tr><td>AES-192-CBC</td><td align="right">11.2</td><td align="right">17.7</td><td align="right">+58%</td><td align="right">9.0</td><td align="right">17.2</td><td align="right">+91%</td></tr>
<tr><td>AES-256-CBC</td><td align="right">9.9</td><td align="right">15.3</td><td align="right">+55%</td><td align="right">8.0</td><td align="right">14.8</td><td align="right">+85%</td></tr>
<tr><td>AES-128-CTR</td><td align="right">13.6</td><td align="right">24.9</td><td align="right">+83%</td><td align="right">10.8</td><td align="right">24.2</td><td align="right">+124%</td></tr>
<tr><td>AES-192-CTR</td><td align="right">11.6</td><td align="right">20.3</td><td align="right">+75%</td><td align="right">9.4</td><td align="right">19.8</td><td align="right">+111%</td></tr>
<tr><td>AES-256-CTR</td><td align="right">10.2</td><td align="right">17.1</td><td align="right">+68%</td><td align="right">8.3</td><td align="right">16.7</td><td align="right">+101%</td></tr>
<tr><td>AES-128-GCM</td><td align="right">7.3</td><td align="right">17.3</td><td align="right">+137%</td><td align="right">6.8</td><td align="right">15.5</td><td align="right">+128%</td></tr>
<tr><td>AES-192-GCM</td><td align="right">6.7</td><td align="right">15.0</td><td align="right">+124%</td><td align="right">6.2</td><td align="right">13.6</td><td align="right">+119%</td></tr>
<tr><td>AES-256-GCM</td><td align="right">6.2</td><td align="right">13.2</td><td align="right">+113%</td><td align="right">5.7</td><td align="right">12.1</td><td align="right">+112%</td></tr>
<tr><td>AES-128-CCM (<code>rfc4309</code>)</td><td align="right">6.5</td><td align="right">11.1</td><td align="right">+71%</td><td align="right">5.3</td><td align="right">10.6</td><td align="right">+100%</td></tr>
</tbody>
</table>

### OpenVPN DCO (AES-128-GCM)

iperf3 TCP, three 10-second runs, Mbit/s.

`send` — encryption on the router;
`reverse` — decryption on the router.

`generic` — the kernel’s default software AES;
`aes-mips` — this module.

<table>
<thead>
<tr>
<th rowspan="2"></th>
<th colspan="3" align="center">MT7621 (1004Kc)</th>
<th colspan="3" align="center">AR9344 (74Kc)</th>
</tr>
<tr>
<th align="right">generic</th>
<th align="right">aes-mips</th>
<th align="right">Δ</th>
<th align="right">generic</th>
<th align="right">aes-mips</th>
<th align="right">Δ</th>
</tr>
</thead>
<tbody>
<tr><td>reverse</td><td align="right">42.0</td><td align="right">72.4</td><td align="right">+72%</td><td align="right">38.8</td><td align="right">58.3</td><td align="right">+50%</td></tr>
<tr><td>send</td><td align="right">35.1</td><td align="right">57.2</td><td align="right">+63%</td><td align="right">25.2</td><td align="right">31.2</td><td align="right">+24%</td></tr>
</tbody>
</table>
