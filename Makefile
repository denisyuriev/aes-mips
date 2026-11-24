# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>

ifneq ($(KERNELRELEASE),)

ccflags-y += -mips32r2 -mtune=1004kc -mno-branch-likely

# Positive macros select what is built. Unset is off here: `make modules`
# in the else branch passes y or n. GCM and CCM select CTR. CBC-MAC stays
# for CCM. The ECB loop stays always: one-block encrypt and decrypt call it.
# Linux 6.18 passes ccflags-y to C and asflags-y to .S.

ifneq ($(filter y,$(CONFIG_CRYPTO_AES_MIPS_GCM) $(CONFIG_CRYPTO_AES_MIPS_CCM)),)
override CONFIG_CRYPTO_AES_MIPS_CTR := y
endif

aes-mips-defs :=
ifeq ($(CONFIG_CRYPTO_AES_MIPS_ECB),y)
aes-mips-defs += -DAES_MIPS_ECB
endif
ifeq ($(CONFIG_CRYPTO_AES_MIPS_CBC),y)
aes-mips-defs += -DAES_MIPS_CBC
endif
ifeq ($(CONFIG_CRYPTO_AES_MIPS_CTR),y)
aes-mips-defs += -DAES_MIPS_CTR
aes-mips-defs += -DAES_MIPS_CTR_ASM
endif
ifeq ($(CONFIG_CRYPTO_AES_MIPS_GCM),y)
aes-mips-defs += -DAES_MIPS_GCM
endif
ifeq ($(CONFIG_CRYPTO_AES_MIPS_CCM),y)
aes-mips-defs += -DAES_MIPS_CCM
endif
ccflags-y += $(aes-mips-defs)
asflags-y += $(aes-mips-defs)

# In-tree this follows Kconfig. The OpenWrt feed is not in the kernel tree,
# so the package passes CONFIG_CRYPTO_AES_MIPS32R2=m and the five mode
# symbols on the kbuild command line.
obj-$(CONFIG_CRYPTO_AES_MIPS32R2) += aes-mips.o
aes-mips-y := aes-mips-tables.o aes-mips-glue.o
aes-mips-$(CONFIG_CRYPTO_AES_MIPS_GCM) += aes-gcm-glue.o ghash-tab.o
aes-mips-$(CONFIG_CRYPTO_AES_MIPS_CCM) += aes-ccm-glue.o
ifneq ($(filter y,$(CONFIG_CRYPTO_AES_MIPS_GCM) $(CONFIG_CRYPTO_AES_MIPS_CCM)),)
aes-mips-y += aes-ctr-walk.o
endif
aes-mips-$(CONFIG_CPU_LITTLE_ENDIAN) += mipsel/aes-mips-core.o
aes-mips-$(CONFIG_CPU_BIG_ENDIAN) += mips/aes-mips-core.o
ifeq ($(CONFIG_CRYPTO_AES_MIPS_GCM),y)
aes-mips-$(CONFIG_CPU_LITTLE_ENDIAN) += mipsel/mul8k.o mipsel/mul16k.o
aes-mips-$(CONFIG_CPU_BIG_ENDIAN) += mips/mul8k.o mips/mul16k.o
endif

# Kernel `make clean` descends here and deletes `clean-files` from each Makefile.
subdir- += mips mipsel

else

KDIR ?= /lib/modules/$(shell uname -r)/build

# Unset means y. A command-line AES_MIPS_GCM=n overrides that one mode.
AES_MIPS_ECB ?= y
AES_MIPS_CBC ?= y
AES_MIPS_CTR ?= y
AES_MIPS_GCM ?= y
AES_MIPS_CCM ?= y

# GCM and CCM register ctr(aes). A command line that names only GCM still
# builds CTR.
ifneq ($(filter y,$(AES_MIPS_GCM) $(AES_MIPS_CCM)),)
override AES_MIPS_CTR := y
endif

CLEAN_NAMES := *.o *.ko *.a *.mod *.mod.c .*.cmd .*.d *.symtypes \
	modules.order Module.symvers compile_commands.json

.PHONY: modules clean

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) \
		CONFIG_CRYPTO_AES_MIPS32R2=m \
		CONFIG_CRYPTO_AES_MIPS_ECB=$(AES_MIPS_ECB) \
		CONFIG_CRYPTO_AES_MIPS_CBC=$(AES_MIPS_CBC) \
		CONFIG_CRYPTO_AES_MIPS_CTR=$(AES_MIPS_CTR) \
		CONFIG_CRYPTO_AES_MIPS_GCM=$(AES_MIPS_GCM) \
		CONFIG_CRYPTO_AES_MIPS_CCM=$(AES_MIPS_CCM) \
		modules

clean:
	@if [ -d "$(KDIR)" ]; then \
		$(MAKE) --no-print-directory -C $(KDIR) M=$(CURDIR) clean; \
	else \
		printf '  CLEAN   %s\n' .; \
		find . \( $(foreach n,$(CLEAN_NAMES),-name '$(n)' -o) -false \) -delete; \
		rm -rf .tmp_versions .tmp_*; \
	fi

endif
