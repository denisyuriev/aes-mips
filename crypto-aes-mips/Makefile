# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Denis Iurev <denis.yuriev@icloud.com>
#
# External OpenWrt feed. The module is not in the OpenWrt tree, so this
# package does not set KCONFIG: that symbol is absent and a forced
# KCONFIG line would fail the build. The .ko is built out of tree.

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=aes-mips
PKG_VERSION:=2026.11.22
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=../LICENSE

include $(INCLUDE_DIR)/package.mk

define KernelPackage/crypto-aes-mips
  SUBMENU:=Cryptographic API modules
  TITLE:=AES for MIPS32r2
  DEPENDS:=@(mips||mipsel) \
	@(CPU_TYPE="4kec"||CPU_TYPE="24kc"||CPU_TYPE="34kc"||CPU_TYPE="74kc"||CPU_TYPE="1004kc"||CPU_TYPE="mips32r2") \
	+kmod-crypto-manager \
	+AES_MIPS_GCM:kmod-crypto-aead \
	+AES_MIPS_CCM:kmod-crypto-aead
  FILES:=$(PKG_BUILD_DIR)/aes-mips.ko
  AUTOLOAD:=$(call AutoLoad,49,aes-mips)
endef

define KernelPackage/crypto-aes-mips/description
  AES cipher for MIPS32r2, little-endian or big-endian. ECB, CBC, CTR,
  GCM and CCM are selected below and are on by default. Built from this
  feed; the OpenWrt kernel tree is not patched. aes_expandkey comes
  from CRYPTO_LIB_AES, which OpenWrt builds into the kernel.
endef

define KernelPackage/crypto-aes-mips/config
	if PACKAGE_kmod-crypto-aes-mips

		config AES_MIPS_ECB
			bool "ECB"
			default y
			help
			  Register skcipher ecb(aes) / ecb-aes-mips.

		config AES_MIPS_CBC
			bool "CBC"
			default y
			help
			  Register skcipher cbc(aes) / cbc-aes-mips.

		config AES_MIPS_CTR
			bool "CTR"
			default y
			help
			  Register skcipher ctr(aes) / ctr-aes-mips.

		config AES_MIPS_GCM
			bool "GCM"
			default y
			select AES_MIPS_CTR
			help
			  Register AEAD gcm(aes). Builds the GHASH tables.
			  Selects CTR.

		config AES_MIPS_CCM
			bool "CCM"
			default y
			select AES_MIPS_CTR
			help
			  Register AEAD ccm(aes). Builds CBC-MAC.
			  Selects CTR.

	endif
endef

# Command line wins. A saved choice is y only when its symbol is set.
# No symbol at all is a .config from before these options: keep every mode.
AES_MIPS_SEEN := $(CONFIG_AES_MIPS_ECB)$(CONFIG_AES_MIPS_CBC)$(CONFIG_AES_MIPS_CTR)$(CONFIG_AES_MIPS_GCM)$(CONFIG_AES_MIPS_CCM)
ifeq ($(AES_MIPS_SEEN),)
  AES_MIPS_ECB ?= y
  AES_MIPS_CBC ?= y
  AES_MIPS_CTR ?= y
  AES_MIPS_GCM ?= y
  AES_MIPS_CCM ?= y
else
  AES_MIPS_ECB ?= $(if $(CONFIG_AES_MIPS_ECB),y,n)
  AES_MIPS_CBC ?= $(if $(CONFIG_AES_MIPS_CBC),y,n)
  AES_MIPS_CTR ?= $(if $(CONFIG_AES_MIPS_CTR),y,n)
  AES_MIPS_GCM ?= $(if $(CONFIG_AES_MIPS_GCM),y,n)
  AES_MIPS_CCM ?= $(if $(CONFIG_AES_MIPS_CCM),y,n)
endif

ifneq ($(filter y,$(AES_MIPS_GCM) $(AES_MIPS_CCM)),)
  override AES_MIPS_CTR := y
endif

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/../Makefile $(PKG_BUILD_DIR)/
	$(CP) $(CURDIR)/../*.c $(CURDIR)/../*.h $(PKG_BUILD_DIR)/
	$(CP) $(CURDIR)/../mips $(CURDIR)/../mipsel $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" \
		CONFIG_CRYPTO_AES_MIPS32R2=m \
		CONFIG_CRYPTO_AES_MIPS_ECB=$(AES_MIPS_ECB) \
		CONFIG_CRYPTO_AES_MIPS_CBC=$(AES_MIPS_CBC) \
		CONFIG_CRYPTO_AES_MIPS_CTR=$(AES_MIPS_CTR) \
		CONFIG_CRYPTO_AES_MIPS_GCM=$(AES_MIPS_GCM) \
		CONFIG_CRYPTO_AES_MIPS_CCM=$(AES_MIPS_CCM) \
		modules
endef

$(eval $(call KernelPackage,crypto-aes-mips))
