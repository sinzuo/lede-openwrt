#!/usr/bin/lua

local util = require("luci.util")
require "luci.model.uci"
local uci = luci.model.uci.cursor()
local json = require("luci.json")
------debug function start-----
local g_debug_flag = 1
local g_fireware_log = "/tmp/firewareupdate.log"
function DEBUG_INFO(info)
    if g_debug_flag then
        if not info then info = "nil" end
        if "table" == type(info) then info = json.encode(info) end
        if 0 == g_debug_flag + 0 then
            local str_time = os.date("%Y-%m-%d %H:%M:%S",os.time())
            os.execute("echo \'"..str_time.." -->> "..info.."\' >> "..g_fireware_log)
        else
            print(info)
        end
    end
end

function call_no_stdout(cmd)
    require "luci.sys"
    cmd = cmd .. " >/dev/null"
    return luci.sys.call(cmd)
end


------debug function end-----
function iwpriv_get_site_survey(set)
    local ret = {}

    if set then call_no_stdout("iwpriv ra0 set SiteSurvey=1") end
    local fd = io.popen("iwpriv ra0 get_site_survey")
    local _ = fd and fd:read("*l")
    local header = fd and fd:read("*l")
    header = header and header:gsub("[^%w-]", " ")
    if header then
        local ssid_pos, ssid_end
        ssid_pos = header:find("SSID")
        ssid_end = header:find("BSSID") - 1
        while true do
            local line = fd:read("*l")
            if not line or #line<=0 then break end

            local channel = tonumber(line:match("^%d+"))
            local ssid = line:sub(ssid_pos, ssid_end)
            local space_start = ssid:find(" *$")
            ssid = ssid:sub(1, space_start-1)
            local bssid, security, siganl, mode =
                    line:sub(ssid_end):match("([%x:]+) +([%w/]+) +(%d+) +([%w/]+)")
            if ssid:match("^0x") then
                ssid = ssid:sub(3):gsub("%x%x", function(e)
                            return string.char(tonumber(e,16))
                        end)
            end
            print(channel, ssid, bssid, security, siganl, mode)
            ret[ssid] = {
                security = security,
                siganl = tonumber(siganl),
                channel = tonumber(channel),
		        bssid = bssid,
            }
        end
    end
    return ret
end

function get_encr_and_auth(ssid)
    local scan = iwpriv_get_site_survey()
    local encr, algo
    if scan[ssid] then
        local security = scan[ssid].security
        local e = security:match("^%w+")
        if e == "NONE" then encr = 0
        elseif e == "WEP" then encr = 1
	elseif e:match("WPA1PSKWPA2PSK") then encr = 4
        elseif e:match("WPA2") then encr = 3
        else encr = 2 end
        algo = security:match("/(%w+)$") or ""
        return encr, algo, scan[ssid].channel,scan[ssid].bssid
    end
end

function encrtonum( ss )
    if not ss then return end
    ss = ss:match("^%w+")
    local inf = { ["none"]=0, ["wep"]=1, ["psk"]=2, ["psk2"]=3,["psk+psk2"]=4,}
    return inf[ss] or 0
end
function numtoencr( nn )
    nn = tonumber(nn)
    if not nn then return end
    local inf = { "none", "wep", "psk", "psk2","psk+psk2",}
    return inf[nn+1] or "none"
end

function api_relay_set(ssid,key)
    
    require "luci.sys"
    if not args then args = {} end

    local status = 0


    local _, v
    repeat
        local uci = luci.model.uci.cursor()
        local fname, section = "wireless", "relay"

        -- long operation handling start
        local lastatus = ( uci:get( fname, section, "_lastatus" ) or -1 ) + 0


        if not ssid then status = 2 break end
        local encr, algo, ch ,bssid = get_encr_and_auth(ssid)



        if not encr then status = 2 break end
        local lkey = key and #key or 0
        if encr==1 and (lkey~=5 and lkey~=13 and lkey~=10 and lkey~=26) then status=2 break end
        if (encr==2 or encr==3 or encr==4) and lkey<8 then status=2 break end

        if encr==4 then
           encr = numtoencr(encr)
	    else
	       encr = numtoencr(encr)
               if #algo>0 then encr = encr .. "+" .. algo:lower() end
        end


        uci:set( fname, section, "device"  , "ra0"     )
        uci:set( fname, section, "_lastatus"  , 1     )
        uci:set( fname, section, "ssid"       , ssid  )
        uci:set( fname, section, "mode"       , "sta" )
	    uci:set( fname, section, "network"       , "bridge" )
	    uci:set( fname, section, "bssid"       , bssid )
        uci:set( fname, section, "encryption" , encr  )
	    uci:commit(fname)
        uci:set( fname, "ra0", "channel"   , ch    )
        if key then
			uci:set( fname, section, "key" , key )
        else
		     uci:delete( fname, section, "key" )
		end

        uci:delete( "wireless", "relay", "disabled" )

        local stat = uci:commit( fname ) and uci:commit( "network" )


	    luci.sys.call("sleep 10")

	    luci.sys.call( "/sbin/wifi" )

    until true
end

local bridge = uci:get( "network", "bridge", "proto" ) or ""
local wantype = uci:get( "network", "wan", "_wantype" ) or ""
local wbssid = uci:get( "wireless", "relay", "bssid" ) or ""
if bridge == "" and wantype == "wifi" and wbssid == "" then

--		print("jiangyibo")
		uci:set( "network", "wan", "ifname","eth0.2" )
		uci:set( "network", "wan", "proto","dhcp")
		uci:set( "network", "bridge", "interface")
        uci:set( "network", "bridge", "proto","dhcp")
		uci:set( "network", "bridge","delegate", "0")
		uci:commit( "network" )

    	local inssid = uci:get( "wireless", "relay", "ssid" ) or ""
		local inkey = uci:get( "wireless", "relay", "key" ) or ""
		if inssid ~= "" then
            api_relay_set(inssid,inkey)
		end
end

