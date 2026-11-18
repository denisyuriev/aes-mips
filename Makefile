# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>

obj-$(CONFIG_CRYPTO_AES_MIPS32R2) += aes-mips.o
aes-mips-y := aes-mips-tables.o aes-mips-glue.o aes-gcm-glue.o aes-ccm-glue.o \
	ghash-tab.o
aes-mips-$(CONFIG_CPU_LITTLE_ENDIAN) += mipsel/aes-mips-core.o \
	mipsel/mul8k.o mipsel/mul16k.o
aes-mips-$(CONFIG_CPU_BIG_ENDIAN) += mips/aes-mips-core.o \
	mips/mul8k.o mips/mul16k.o
