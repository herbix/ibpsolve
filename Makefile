
include $(TOPDIR)/rules.mk

PKG_NAME:=ibpsolve
PKG_VERSION:=0.2.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/ibpsolve
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=ibpsolve -- find out how many i, b, p frames are in a h.264 video
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

TARGET_CFLAGS += $(FPIC)

define Package/ibpsolve/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ibpsolve $(1)/bin/
endef

$(eval $(call BuildPackage,ibpsolve))
