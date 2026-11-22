# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>

ifneq ($(KERNELRELEASE),)

ccflags-y += -mips32r2 -mtune=1004kc -mno-branch-likely

# In-tree this follows Kconfig. The OpenWrt feed is not in the kernel tree,
# so the package passes CONFIG_CRYPTO_AES_MIPS32R2=m on the kbuild command line.
obj-$(CONFIG_CRYPTO_AES_MIPS32R2) += aes-mips.o
aes-mips-y := aes-mips-tables.o aes-mips-glue.o aes-gcm-glue.o aes-ccm-glue.o \
	ghash-tab.o
aes-mips-$(CONFIG_CPU_LITTLE_ENDIAN) += mipsel/aes-mips-core.o \
	mipsel/mul8k.o mipsel/mul16k.o
aes-mips-$(CONFIG_CPU_BIG_ENDIAN) += mips/aes-mips-core.o \
	mips/mul8k.o mips/mul16k.o

# Kernel `make clean` descends here and deletes `clean-files` from each Makefile.
subdir- += mips mipsel

else

KDIR ?= /lib/modules/$(shell uname -r)/build

CLEAN_NAMES := *.o *.ko *.a *.mod *.mod.c .*.cmd .*.d *.symtypes \
	modules.order Module.symvers compile_commands.json

.PHONY: modules clean

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) CONFIG_CRYPTO_AES_MIPS32R2=m modules

clean:
	@if [ -d "$(KDIR)" ]; then \
		$(MAKE) --no-print-directory -C $(KDIR) M=$(CURDIR) clean; \
	else \
		printf '  CLEAN   %s\n' .; \
		find . \( $(foreach n,$(CLEAN_NAMES),-name '$(n)' -o) -false \) -delete; \
		rm -rf .tmp_versions .tmp_*; \
	fi

endif
