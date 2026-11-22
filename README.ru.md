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

Первый стенд — TP-Link Archer C6U v1, MediaTek MT7621 (MIPS 1004Kc, little-endian).

Второй стенд — MikroTik RB951Ui-2HnD, Atheros AR9344 (MIPS 74Kc, big-endian).

Матрица обоих порядков байт — qemu (`-M malta -cpu 24Kc`).

## OpenWrt

Модуля нет в дереве OpenWrt.

Этот репозиторий — внешний фид. Пакет появится в `make menuconfig` только для следующих типов CPU OpenWrt: `4kec`, `24kc`, `34kc`, `74kc`, `1004kc`, `mips32r2`.

1. В `feeds.conf` (в имени ленты нельзя `-`):

       src-git aes_mips https://github.com/denisyuriev/aes-mips.git

2. `./scripts/feeds update aes_mips`
3. `./scripts/feeds install -p aes_mips -a`
4. Выбрать цель MIPS32r2.
5. Kernel modules → Cryptographic API modules → `kmod-aes-mips` в `<*>`.
6. Собрать образ как обычно.

`<*>` кладёт `aes-mips.ko` в образ. Модуль загружается при старте. В `/proc/crypto` появляются `aes-mips`, `ecb-aes-mips`, `cbc-aes-mips`, `ctr-aes-mips`, `gcm-aes-mips` и `ccm-aes-mips`.

## Скорость

`generic` — дефолтный модуль AES ядра;
`aes-mips` — этот модуль.
Три прогона, медиана.

### `tcrypt` (МБ/с)

Шифрование. ECB/CBC — блок 1424 байт; CTR/GCM/CCM — блок 1420 байт.

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
<tr><td>AES-128-ECB</td><td align="right">15,1</td><td align="right">21,3</td><td align="right">+41%</td><td align="right">11,9</td><td align="right">20,4</td><td align="right">+72%</td></tr>
<tr><td>AES-192-ECB</td><td align="right">12,8</td><td align="right">17,8</td><td align="right">+39%</td><td align="right">10,2</td><td align="right">17,2</td><td align="right">+69%</td></tr>
<tr><td>AES-256-ECB</td><td align="right">11,1</td><td align="right">15,3</td><td align="right">+38%</td><td align="right">8,9</td><td align="right">14,9</td><td align="right">+67%</td></tr>
<tr><td>AES-128-CBC</td><td align="right">13,0</td><td align="right">21,2</td><td align="right">+63%</td><td align="right">10,3</td><td align="right">20,4</td><td align="right">+97%</td></tr>
<tr><td>AES-192-CBC</td><td align="right">11,2</td><td align="right">17,7</td><td align="right">+58%</td><td align="right">9,0</td><td align="right">17,2</td><td align="right">+91%</td></tr>
<tr><td>AES-256-CBC</td><td align="right">9,9</td><td align="right">15,3</td><td align="right">+55%</td><td align="right">8,0</td><td align="right">14,8</td><td align="right">+85%</td></tr>
<tr><td>AES-128-CTR</td><td align="right">13,6</td><td align="right">24,8</td><td align="right">+82%</td><td align="right">10,8</td><td align="right">23,7</td><td align="right">+118%</td></tr>
<tr><td>AES-192-CTR</td><td align="right">11,6</td><td align="right">20,2</td><td align="right">+74%</td><td align="right">9,4</td><td align="right">19,4</td><td align="right">+107%</td></tr>
<tr><td>AES-256-CTR</td><td align="right">10,2</td><td align="right">17,0</td><td align="right">+67%</td><td align="right">8,3</td><td align="right">16,5</td><td align="right">+99%</td></tr>
<tr><td>AES-128-GCM</td><td align="right">7,3</td><td align="right">17,4</td><td align="right">+138%</td><td align="right">6,8</td><td align="right">15,3</td><td align="right">+124%</td></tr>
<tr><td>AES-192-GCM</td><td align="right">6,7</td><td align="right">15,0</td><td align="right">+124%</td><td align="right">6,2</td><td align="right">13,4</td><td align="right">+116%</td></tr>
<tr><td>AES-256-GCM</td><td align="right">6,2</td><td align="right">13,2</td><td align="right">+113%</td><td align="right">5,7</td><td align="right">11,9</td><td align="right">+109%</td></tr>
<tr><td>AES-128-CCM (<code>rfc4309</code>)</td><td align="right">6,5</td><td align="right">11,0</td><td align="right">+69%</td><td align="right">5,3</td><td align="right">10,4</td><td align="right">+94%</td></tr>
</tbody>
</table>

### OpenVPN DCO (AES-128-GCM)

iperf3 TCP, три прогона по 10 секунд, Мбит/с.

`send` — шифрование на роутере;
`reverse` — расшифрование на роутере.

`generic` — дефолтный модуль AES ядра;
`aes-mips` — этот модуль.

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
<tr><td>reverse</td><td align="right">42,0</td><td align="right">72,4</td><td align="right">+72%</td><td align="right">38,8</td><td align="right">58,3</td><td align="right">+50%</td></tr>
<tr><td>send</td><td align="right">35,1</td><td align="right">57,2</td><td align="right">+63%</td><td align="right">25,2</td><td align="right">31,2</td><td align="right">+24%</td></tr>
</tbody>
</table>
