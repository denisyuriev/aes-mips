# aes-mips

[English](README.md)

Copyright (C) 2026 Denis Iurev &lt;denis.yuriev@icloud.com&gt;

Программный AES для MIPS32r2. Модуль ядра `aes-mips` (`CONFIG_CRYPTO_AES_MIPS32R2`), [GPL-2.0](LICENSE) (см. также [COPYING](COPYING)).

Код написан и проверен под ядро Linux 6.18

Регистрирует 
- `cipher` ( priority 200 )
  - `aes` / `aes-mips`
- `skcipher` ( priority 300 )
  - `ecb(aes)` / `ecb-aes-mips`
  - `cbc(aes)` / `cbc-aes-mips`
  - `ctr(aes)` / `ctr-aes-mips`
- `AEAD` ( priority 400 )
  - `gcm(aes)` / `gcm-aes-mips`
  - `ccm(aes)` / `ccm-aes-mips`

Реализация AES — Gladman T-tables в ассемблере; есть little-endian (`mipsel/`) и big-endian (`mips/`).

GHASH — таблицы 16 КиБ при L1 D ≥ 32 КиБ, иначе 8 КиБ (выбор при загрузке).

Небольшая оптимизация последнего раунда AES на DSPr1 (`LBUX`), если ASE есть на CPU.

Исходники рассчитаны на `arch/mips/crypto/` в дереве ядра. `Makefile` и `Kconfig` — in-tree.

Основная платформа разработки — MediaTek MT7621 (1004Kc).
Проверка BE — в qemu (`-M malta -cpu 24Kc`).

## Скорость на MT7621 (1004Kc)

Ядро 6.18.60. ECB, CBC, CTR и CCM — 17 ноября 2026.
GCM и OpenVPN DCO — 20 ноября 2026, одна сессия, сначала `generic`, затем `aes-mips`. 

### `tcrypt` (МБ/с)

Шифрование.

ECB/CBC — блок 1424 байт; 
CTR/GCM/CCM — блок 1420 байт.

`generic` — дефолтный модуль aes-шифрования ядра
`aes-mips` — этот модуль.

| | generic | aes-mips | Δ |
|---|---:|---:|---:|
| AES-128-ECB | 15,2 | 21,3 | +40% |
| AES-192-ECB | 12,8 | 17,9 | +40% |
| AES-256-ECB | 11,1 | 15,3 | +38% |
| AES-128-CBC | 13,0 | 21,2 | +63% |
| AES-192-CBC | 11,2 | 17,8 | +59% |
| AES-256-CBC | 9,9 | 15,3 | +55% |
| AES-128-CTR | 13,6 | 24,8 | +82% |
| AES-192-CTR | 11,6 | 20,2 | +74% |
| AES-256-CTR | 10,2 | 17,1 | +68% |
| AES-128-GCM | 7,3 | 17,2 | +135% |
| AES-192-GCM | 6,7 | 14,8 | +122% |
| AES-256-GCM | 6,2 | 13,0 | +110% |
| AES-128-CCM (`rfc4309`) | 6,5 | 11,0 | +69% |

### OpenVPN DCO (AES-128-GCM)

Замеры с помощью iperf3 TCP, (три прогона по 10 секунд), Мбит/с.

`generic` - дефолтный модуль aes-шифрования ядра
`aes-mips` - текущий

`send` — шифрование на роутере, 
`reverse` — расшифрование на роутере.

| | generic | aes-mips | Δ |
|---|---:|---:|---:|
| reverse | 38,9 | 66,7 | +71% |
| send | 26,0 | 45,0 | +73% |
