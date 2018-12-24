module( "luci.relay", package.seeall )

local lmc = require "luci.model.uci"
local uci = lmc.cursor()
local fs = require "nixio.fs"
local api = require "luci.api"

local _sl = api.shell_string

local ssid, key, ifname, enc, driver, freq

function logwrite(str, ...)
    function shell_string(str)
        if not str then return "''" end
        local sl = str:gsub("'", "'\\''")
        return "'" .. sl .. "'"
    end
    local log = string.format(str, ...)
    local cmd = "/usr/bin/logger -t RelayEvent  " .. shell_string(log)
    os.execute(cmd)
end


function is_wanrelay()
    local wantype = uci:get("network", "wan", "_wantype")
    return wantype == "wifi"
end

function getiwinfo()
    return {}
end
function available_channel()
    return {1,2,3,4,5,6,7,8,9,10,11,12,13,14}
end
function best_channel()
    return 1
end

function get_phy_channel(phy)
    require "luci.util"
    local body = luci.util.exec("/usr/sbin/iwconfig ra0")
    local ch = body and body:match("Channel=(%d+)")
    return ch and tonumber(ch)
end

function get_current_channel()
    local phy0c = get_phy_channel(0)
    local api = require "luci.api"
    local wifidev2g = api.uci_cfg_get("idcard", "baseinfo", "wifidev2g")
    local cfg0c = uci:get("wireless", wifidev2g, "channel")
    return phy0c or cfg0c
end


function hexstring(str)
    return str:gsub(".", function(e)
        return string.format("%02x", e:byte(1))
    end)
end


function get_wificlient_list_by_ifname( ifname )
    local api = require "luci.api"
    local cmd = string.format("iwpriv %s get_mac_table", api.shell_string(ifname))
    local fd = io.popen(cmd, "r");
    local ret = {}
    if fd then
        fd:read("*l")
        fd:read("*l")
        while true do
            local line = fd:read("*l")
            if not line or #line==0 then break end
            -- MAC                AP  AID PSM AUTHCTxR  LTxR  LDT       RxB       TxB
            -- 24:69:a5:43:3b:a7  0   1   1   1   54    0     0         0         0
            local mac = line:sub(1,17):upper()
            ret[mac] = {}
        end
    end
    return ret
end

function wificlient_list()
    local ifname, ifname_guest = "ra0", "ra0"
--    local ifname, ifname_guest = "ra0", "ra1"

    local k, v
    local ret = get_wificlient_list_by_ifname(ifname)
    local ret_guest = get_wificlient_list_by_ifname(ifname_guest)
    for k, v in pairs(ret_guest) do
        ret[k] = v
    end
    return ret
end



function iwpriv_get_site_survey(set)
    local api = require "luci.api"
    local ret = {}

    if set then api.call_no_stdout("iwpriv ra0 set SiteSurvey=1") end
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
            --print(channel, ssid, bssid, security, siganl, mode)
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

function wifilist(args)
    local api = require "luci.api"
	local relay = require "luci.relay"

    local ret = {}
    local _, k, v

	function get_encryption_from_security( s )
		if s=="NONE" then return 0
		elseif s=="WEP" then return 1
		elseif s:match("WPA1PSKWPA2PSK") then encr = 4
		elseif s:match("WPA2") then return 3
		else return 2
        end
	end

    local raw = iwpriv_get_site_survey(true)
    for k, v in pairs(raw) do
        ret[#ret+1] = {
            ssid = k,
            encryption = get_encryption_from_security(v.security),
			percent = tonumber(v.siganl),
        }
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

function api_relay_set_yu(args)
    local api = require "luci.api"
    if not args then args = {} end
    local hwrite = api.GetParam(args, "hwrite", "1")

    local status = 0
    local ssid = api.GetParam(args, "ssid")
    local key = api.GetParam(args, "key")
    --local encr = api.GetParam(args, "encryption")
    local remember = api.GetParam( args, "record", "1" )
    local query = api.GetParam( args, "query" )

    local _, v
    repeat
        local uci = luci.model.uci.cursor()
        local fname, section = "wireless", "relay"

        -- long operation handling start
        local lastatus = ( uci:get( fname, section, "_lastatus" ) or -1 ) + 0
        if query == "1" then status = lastatus break end
        --if lastatus == 1 then status = 9 break end



        api.InitConfigNameSection( fname, section, "wifi-iface", uci )


        if not ssid then status = 2 break end
        local encr, algo, ch ,bssid = get_encr_and_auth(ssid)



        if not encr then status = 2 break end
        local lkey = key and #key or 0
        if encr==1 and (lkey~=5 and lkey~=13 and lkey~=10 and lkey~=26) then status=2 break end
        if (encr==2 or encr==3 or encr==4) and lkey<8 then status=2 break end

        if encr==4 then
           encr = api.numtoencr(encr)
	else
	   encr = api.numtoencr(encr)
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
        if key then uci:set( fname, section, "key" , key )
        else uci:delete( fname, section, "key" ) end
        api.config_reset(uci, "network", "wan", {
            _wantype = "wifi",
            proto = "dhcp",
        })
        uci:delete( "wireless", "relay", "disabled" )

        local stat = uci:commit( fname ) and uci:commit( "network" )
        if not stat then status = 3 break end

        local pid = nixio.fork()
        if pid < 0 then
            status = 3
        elseif pid > 0 then
            status = 1
        else
               local o = nixio.open("/dev/null", "w")

               nixio.dup(o, nixio.stdout)

               o:close()

            local logfile = "/tmp/log/ng/wlanerr"
            nixio.fs.writefile(logfile, "")

            stat = uci:apply( fname )
	    luci.sys.call("sleep 1")

	    luci.sys.call( "/etc/init.d/wifi" )
            if stat ~= 0 then status = 5 end
            local real
            if status == 0 then
                real = api.wan_realip(7) or {}
                local logline = tail_log(logfile)
                if logline and is_recent_log(logline, 10)
                        and logline:match(" 2%)$") then
                    status = 401
                elseif (not real.ifname) or real.proto=="none" then
                    status=7
                else
                    status = 0
                    if remember=="1" then
                        local nar = {
                            ssid = ssid,
                            encryption = encr,
                            default = "1",
                            key = key,
                        }
                        record_set(nar)
                    end
                end
            end
            uci:set( fname, section, "_lastatus", status )
            uci:commit( fname )
            os.exit(status)
        end
    until true

    local ret = {}
    local real
    if query=="1" then
        --if (status==1 or status==0) then
            real = api.wan_realip() or {}
            ret = { ip = real.ip or "", mask = real.mask or "", gw = real.gw or "" }
        --end
    end
    ret.status = status

    if 1==1 then
        luci.http.prepare_content( "application/json" )
        luci.http.write_json(ret)
    end
    return ret
end

function api_relay_set(data)
    local api = require "luci.api"
    if not args then args = {} end
    local hwrite = api.GetParam(args, "hwrite", "1")

    local status = 0
    local ssid = api.GetParam(args, "ssid")
    local key = api.GetParam(args, "key")
    --local encr = api.GetParam(args, "encryption")
    local remember = api.GetParam( args, "record", "1" )
    local query = api.GetParam( args, "query" )
    local nk = "network"    

    local enable = 1
    local wire = "wireless"
	local section = "relay"
        uci:load(wire)
        local flag = false
        uci:foreach(wire, "wifi-iface", function(s)
             if "sta" == s["mode"] then
                section = s[".name"]
                flag = true
             end
        end)

    if enable == 0 then
	   if flag then
	   	uci:set( wire, section, "disabled", 1)
        uci:set(nk,"wan","proto","dhcp")
        uci:set(nk,"wan","type","dhcp")
		uci:commit(wire)
        uci:commit(nk)
		os.execute([[wifi >/dev/null 2>&1 &]])
           end
	elseif enable == 1 then

           function get_encr_from_secretType(encr)
		local e
		if encr == 0 then e = "none"                                                            
        	elseif encr==1 then e = "wep"                                                        
        	elseif encr ==4 then e = "psk"                                         
        	elseif encr == 5 then e = "psk2"
                elseif encr == 6 then e = "psk+psk2"                                                   
       		else encr = 0 end 
        	return e      
       end
       
       if not ssid then status = 2  end
       local encr, algo, ch , bssid = get_encr_and_auth(ssid)
       if not encr then status = 2  end
       local lkey = key and #key or 0
       if encr==1 and (lkey~=5 and lkey~=13 and lkey~=10 and lkey~=26) then status=2  end
       if (encr==2 or encr==3) and lkey<8 then status=2  end

       encr = api.numtoencr(encr)
       if #algo>0 then encr = encr .. "+" .. algo:lower() end



           if not flag  then
             --section = uci:add(wire,section)
             if key then  uci:section( wire, "wifi-iface", nil, {device = "ra0",_lastatus = 1,ssid= ssid,mode="sta",network="bridge",bssid=bssid,encryption=encr,key=key,} )
             else uci:section( wire, "wifi-iface", nil, {device = "ra0",_lastatus = 1,ssid= ssid,mode="sta",network="bridge",bssid=bssid,encryption=encr,} ) end
           else
	     uci:delete( wire, section, "disabled" )
             uci:set( wire, section, "device"  , "ra0"     )
             uci:set( wire, section, "_lastatus"  , 1     )
             uci:set( wire, section, "ssid"       , ssid  )
             uci:set( wire, section, "mode"       , "sta" )
             uci:set( wire, section, "network"       , "bridge" )
             uci:set( wire, section, "bssid"       , bssid )
             uci:set( wire, section, "encryption" , encr  )
             --uci:set( wire, "ra0", "channel"   , ch    )
	     --uci:set( wire, "ra0", "txpower"   , power    )
             if key then uci:set( wire, section, "key" , key )
             else uci:delete( wire, section, "key" ) end
           end
	    uci:set( wire, "ra0", "channel"   , ch  ) 
        uci:set(nk,"wan","proto","dhcp")
--        uci:set(nk,"wan","type","bridge")
        uci:set(nk,"wan","ipaddr","")
        uci:set(nk,"wan","netmask","")
        uci:set(nk,"wan","gateway","")
        uci:set(nk,"wan","dns","")

	   uci:commit(wire)	   
           uci:commit(nk)	   
	   os.execute([[wifi >/dev/null 2>&1 &]])
	end
    local ret = {}                                                                                                                  
    local real                                                                                                                      
    if query=="1" then                                                                                                              
        --if (status==1 or status==0) then                                                                                          
            real = api.wan_realip() or {}                                                                                           
            ret = { ip = real.ip or "", mask = real.mask or "", gw = real.gw or "" }                                                
        --end                                                                                                                       
    end                                                                                                                             
    ret.status = status                                                                                                             
                                                                                                                                    
    if 1==1 then                                                                                                                    
        luci.http.prepare_content( "application/json" )                                                                             
        luci.http.write_json(ret)                                                                                                   
    end                                                                                                                             
    return ret  
end

