include $(TOPDIR)/rules.mk

PKG_NAME:=udpcwmp
PKG_RELEASE:=1.14

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/udpcwmp
  SECTION:=sinzuo
  CATEGORY:=SINZUO
  TITLE:=udpcwmp for SZTozed's Router and AP
  DEPENDS:=+lua +luci-lib-json +libjson-c +libuci +libpthread
  
endef

define Package/udpcwmp/description
  udpcwmp for SZTozed's Gateway 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

#define Package/udpcwmp/conffiles
#/etc/config/udpcwmp
#endef

define Package/udpcwmp/install
	$(INSTALL_DIR)  $(1)/usr/sbin
	$(INSTALL_BIN)  $(PKG_BUILD_DIR)/udpreport $(1)/usr/sbin
	$(INSTALL_BIN)  $(PKG_BUILD_DIR)/freecwmp.sh $(1)/usr/sbin/freecwmp
	$(INSTALL_BIN)  $(PKG_BUILD_DIR)/getopt $(1)/usr/sbin/getopt
	$(INSTALL_DIR)  $(1)/usr/lib/js
	$(INSTALL_BIN)  $(PKG_BUILD_DIR)/js/* $(1)/usr/lib/js/
	$(INSTALL_DIR) $(1)/usr/share/freecwmp
	$(CP) $(PKG_BUILD_DIR)/scripts/defaults $(1)/usr/share/freecwmp
	$(CP) $(PKG_BUILD_DIR)/scripts/functions $(1)/usr/share/freecwmp	
	$(INSTALL_DIR)  $(1)/etc/init.d
	$(INSTALL_BIN)  $(PKG_BUILD_DIR)/udpreport-init $(1)/etc/init.d/udpreport
	$(INSTALL_DIR)  $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/freecwmp-conf $(1)/etc/config/freecwmp
endef

$(eval $(call BuildPackage,udpcwmp))

