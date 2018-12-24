local pcall, dofile, _G = pcall, dofile, _G

module "luci.version"


if pcall(dofile, "/etc/device_info") and _G.DEVICE_PRODUCT then
        distname    = _G.DEVICE_PRODUCT
       -- distversion = _G.DEVICE_REVISION
else
        distname    = " "
        --distversion = "Development Snapshot"
end

if pcall(dofile, "/etc/openwrt_release") and _G.DISTRIB_DESCRIPTION then
        distversion = _G.DISTRIB_RELEASE
else
        distversion = " "
end

luciname    = ""
luciversion = ""
