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
	+kmod-crypto-aead +kmod-crypto-manager
  FILES:=$(PKG_BUILD_DIR)/aes-mips.ko
  AUTOLOAD:=$(call AutoLoad,49,aes-mips)
endef

define KernelPackage/crypto-aes-mips/description
  AES cipher, ECB, CBC, CTR, GCM and CCM for MIPS32r2, little-endian
  or big-endian. Built from this feed; the OpenWrt kernel tree is not
  patched. aes_expandkey comes from CRYPTO_LIB_AES, which OpenWrt
  builds into the kernel.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/../Makefile $(PKG_BUILD_DIR)/
	$(CP) $(CURDIR)/../*.c $(CURDIR)/../*.h $(PKG_BUILD_DIR)/
	$(CP) $(CURDIR)/../mips $(CURDIR)/../mipsel $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" \
		CONFIG_CRYPTO_AES_MIPS32R2=m \
		modules
endef

$(eval $(call KernelPackage,crypto-aes-mips))
