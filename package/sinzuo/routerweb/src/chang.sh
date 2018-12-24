#!/bin/sh
cp peizhi/index.lua squashfs-root/usr/lib/lua/luci/controller/admin/
cp peizhi/relay.lua squashfs-root/usr/lib/lua/luci/
cp peizhi/api.lua squashfs-root/usr/lib/lua/luci/
cp peizhi/account squashfs-root/etc/config/
cp peizhi/idcard squashfs-root/etc/config/
cp peizhi/wifi_status.htm squashfs-root/usr/lib/lua/luci/view/admin_network/
cp peizhi/wifi_overview.htm squashfs-root/usr/lib/lua/luci/view/admin_network/
rm -rf squashfs-root/www/images
rm -rf squashfs-root/www/js
rm -rf squashfs-root/www/css
#mv  squashfs-root/www/index.html   squashfs-root/www/top.html
cp peizhi/zhejiangxiugai/*  squashfs-root/www  -a

