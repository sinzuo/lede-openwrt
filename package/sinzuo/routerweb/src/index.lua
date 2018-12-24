--[[
LuCI - Lua Configuration Interface

Copyright 2008 Steven Barth <steven@midlink.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

$Id$
]]--

--local io    = require "io"


module("luci.controller.admin.index", package.seeall)

function index()
--[[
	local tian = node()

	if not tian.target then
		tian.target = alias("tianya")
		tian.index = true
	end
	local page   = node("tianya")
	page.target  = firstchild()
]]--


	local root = node()
	if not root.target then
		root.target = alias("admin")
		root.index = true
	end

	local page   = node("admin")
	page.target  = firstchild()
	page.title   = _("Administration")
	page.order   = 10
	page.sysauth = "admin"
	page.sysauth_authenticator = "htmlauth"
	page.ucidata = true
	page.index = true

	-- Empty services menu to be populated by addons
	entry({"admin", "services"}, firstchild(), _("Services"), 40).index = true

       page = entry({"admin", "login_in"}, call("action_Id"))
       page.dependent = false
       page.sysauth = false
        page = entry( {"admin", "sys_info"}, call("Api_sys_info") )               
        page.dependent = false                                                    
        page.sysauth = false   
       page = entry( {"admin", "timeout_get"}, call("Api_timeout_get") )
	page.dependent = false
	page.sysauth = false
    page = entry( {"admin", "wan_ip_set"}, call("Api_wip_set") )
	page.dependent = false
	page.sysauth = false
	page = entry(  {"admin", "wan_ip_get"},call("Api_wip_get") )
	page.dependent = false
	page.sysauth = false
        page = entry(  {"admin", "http_set_register"},call("http_set_register") )              
        page.dependent = false                                                    
        page.sysauth = false 
        page = entry(  {"admin", "http_check_pass"},call("http_check_pass") )              
        page.dependent = false                                                    
        page.sysauth = false
	page = entry( {"admin", "wifi_scan_get"}, call("Api_wifi_scan") )
	page.dependent = false
	page.sysauth = false
    page = entry( {"admin", "sys_password_set"}, call("ApiPassword") )
	page.dependent = false
	page.sysauth = false
	page = entry( {"admin", "sys_hostname_get"}, call("ApiWifinameGet") )
	page.dependent = false
	page.sysauth = false
    page = entry( {"admin", "sys_hostname_set"}, call("ApiWifinameSet") )
    page.dependent = false
    page.sysauth = false
    page = entry( {"admin", "wan_relay_set"}, call("Api_relay_set") )
    page.dependent = false
    page.sysauth = false
    page = entry( {"admin", "wan_relay_get"}, call("Api_relay_get") )
    page.dependent = false
    page.sysauth = false
    page = entry( {"admin", "sys_mode_set"}, call("Api_mode_set") )
    page.dependent = false
    page.sysauth = false
    page = entry( {"admin", "sys_mode_get"}, call("Api_mode_get") )
    page.dependent = false
    page.sysauth = false

	page = entry( {"admin", "device_relay_get"}, call("device_cur_get_now") )
        page.dependent = false
        page.sysauth = false

	page = entry(  {"admin", "url_admin"},call("Api_url_admin") )
	page.dependent = false
	page.sysauth = false
	page = entry(  {"admin", "sys_set_ipaddr"},call("Api_sys_set_ipaddr") )
	page.dependent = false
	page.sysauth = false
	page = entry(  {"admin", "sys_upgrade"},call("Api_sys_upgrade") )
	page.dependent = false
	page.sysauth = false
	page = entry( {"admin", "sys_factory"}, call("Api_sys_factory") )
	page.dependent = false
	page.sysauth = false
        page = entry( {"admin", "sys_reboot"}, call("Api_sys_reboot") )
	page.dependent = false
	page.sysauth = false
	page = entry( {"admin", "traffic_set"}, call("Api_traffic_set") )
	page.dependent = false
	page.sysauth = false
	page = entry( {"admin", "traffic_get"}, call("Api_traffic_get") )
	page.dependent = false
	page.sysauth = false
	page = entry( {"admin", "black_mac_set"}, call("Api_black_mac_set") )
	page.dependent = false
	page.sysauth = false
	page = entry( {"admin", "black_mac_get"}, call("Api_black_mac_get") )
	page.dependent = false
	page.sysauth = false
	page = entry( {"admin", "black_url_set"}, call("Api_black_url_set") )
	page.dependent = false
	page.sysauth = false
	page = entry( {"admin", "black_url_get"}, call("Api_black_url_get") )
	page.dependent = false
	page.sysauth = false
	page = entry( {"admin", "session_clear"}, call("Api_session_clear") )
	page.dependent = false
	page.sysauth = false

       page = entry( {"admin", "activeH"}, call("Api_ActiveH") )
       page.dependent = false
       page.sysauth = false

       page = entry( {"admin", "activeM"}, call("Api_ActiveM") )
       page.dependent = false
       page.sysauth = false

       -- modify by pixiaocong in 20160229
       page = entry( {"admin", "active"}, call("Api_Active") )
       page.dependent = false
       page.sysauth = false
       -- modify end
	entry({"admin", "logout"}, call("action_logout"), _("Logout"), 90)

end

function get_device_version()
   local ver = require("luci.version")
   --local util = require("luci.util")
   --local ver = util.exec("cat /etc/sysinfo.conf | grep soft_version | cut -d '=' -f2 2> /dev/null") or ""
   return ver.distversion
end


function get_device_mac()
   local util = require("luci.util")
   local mac = util.exec("echo -n $(ifconfig ra0 | grep HWaddr | awk \'{print $5}\')")
   return string.upper(string.gsub(mac,":",""))
end

function get_device_arp_num()
   local util = require("luci.util")
   local mac = util.exec("cat /proc/net/arp|grep br-lan| awk '{ print $3 }'| grep 0x2 | wc -l")
   return mac - 0

--   local util = require("luci.util")
--   local mac = util.exec("iwinfo ra0 assoclist | grep -E \".{2}:.{2}:.{2}:.{2}:.{2}:.{2}\" | wc -l")
--   return mac - 0

end

function get_assoclist()
    DEBUG_INFO("enter get_assoclist()")
    local cmd = "iwinfo wlan assoclist | grep -E \".{2}:.{2}:.{2}:.{2}:.{2}:.{2}\""
    local fd = io.popen(cmd, "r");
    local res = {}
    local row = nil
    if fd then
        while true do
            local line = nil
            local cli = {}
            line = fd:read("*l")
            if not line or #line==0 then break end
            row=pifii.split(line," ")
            cli["mac"] = string.upper(string.gsub(row[1],":",""))
            cli["uptime"] = row[9]
			res[ cli["mac"] ] = cli
        end
    end
    fd:close()
    return res
end

function get_device_quality()
    local util = require("luci.util")
    local var = util.exec("tail -n 5 /tmp/pppoe.log 2>/dev/null | grep \"Unable to complete PPPoE Discovery\"|wc -l")
    if (var + 0)>0 then
        var="651"
    else
        var="691"
    end
    return var
end


function get_device_port_up()
        local util = require("luci.util")
        local ret = {}
		 ret["port1"] = 0
		 ret["port2"] = 0
		 ret["port3"] = 0
		 ret["port4"] = 0
		 ret["port5"] = 0
		 local index = 0

                local swc = io.popen("swconfig dev switch0 show 2>/dev/null")

                if swc then
                        while true do
                                local line = swc:read("*l")

                                if not line then break end
                                local   port = line:match("link: port:(%d+) link:up")
                                if port ~= nil  then
								   index = port+ 1
                                   --ret[#ret+1] = port + 1
								    ret["port"..index] = 1
                                end
                        end
                end

   return ret
end

function firmware_request()


end


function do_firmware_update()


end


function Api_sys_info( args )                                                    
    local uci = luci.model.uci.cursor()                                          
    local api = require "luci.api"                                               
    local util = require("luci.util")                                            
    if not args then args = {} end                                               
    local hwrite = api.GetParam( args, "hwrite", "1" )                           
    local flag = uci:get( "qos_auth", "upload", "total_bandwidth" ) or ""        
    local upload = uci:get( "qos_auth", "upload", "total_bandwidth" ) or ""       
    local download = uci:get( "qos_auth", "download", "total_bandwidth" ) or ""   
    local memleft = util.exec("cat /proc/meminfo |grep MemAvailable|awk '{print $2}'")
    local upsum,downsum = util.exec("ifconfig br-lan|grep bytes|awk -F 'bytes:' '{print $2,$3}'|awk '{print $1,$5}'")
    if flag == "" then                                                            
        flag = 0                                                                  
    else                                                                          
        flag = 1                                                                  
    end                                                                           
    local ret = {                                                                 
             memall = "30M",                                                          
             memleft = memleft,                                                   
             cpu =  11,                                                           
             runtime = nixio.sysinfo().uptime,                                    
             users = get_device_arp_num(),                                        
             connects = "110",                                                    
             upsum = upsum,                                                                    
             downsum = downsum,                                                   
             upspeed = "1.4",                                                     
             downspeed = "30.5",                                                  
    }                                                                                                 
    if hwrite == "1" then                                                         
        luci.http.prepare_content( "text/html; charset=utf-8" )                   
        luci.http.write_json( ret )                                               
    end                                                                           
    return ret                                                                    
end   



function get_dhcp_leases()
    local cmd = "cat /tmp/dhcp.leases | awk \'{print $1\"|\"$2\"|\"$3\"|\"$4}\'"
    local fd = io.popen(cmd, "r");
    local res = {}
    local line = nil
    if fd then
        while true do
            local cli = {}
            line = fd:read("*l")
            if not line or #line==0 then break end
            row=string.split(line,"|")
            cli["time"] = 31
            cli["mac"] = string.upper(string.gsub(row[2],":",""))
            cli["ip"] = row[3]
            cli["type"] = "WIFI 2.4G"
			cli["device"] = row[4]
            --res[cli["mac"]] = cli
			res[#res+1] = cli
        end
    end
    return res
end


function get_Wifiname()
    local uci = luci.model.uci.cursor()

    local jss
    local fname = "wireless"
    local section = "wifi-iface"
    uci:foreach( fname, section, function(s)

         jss = s["ssid"]
        if s["device"] == "ra0" or s["device"] == "mt7603e" then
            return false
        else
                return true
        end
    end)

    return jss
end

function get_Wifiname5g()
    local uci = luci.model.uci.cursor()

    local jss
    local fname = "wireless"
    local section = "wifi-iface"
    uci:foreach( fname, section, function(s)

         jss = s["ssid"]
         if s["device"] == "mt7612e" then
            return false
        else
                return true
        end
    end)

    return jss
end

function get_Wifihidden()
    local uci = luci.model.uci.cursor()

    local jss
    local fname = "wireless"
    local section = "wifi-iface"
    uci:foreach( fname, section, function(s)

         jss = s["hidden"] or "0"
         if s["device"] == "ra0" or s["device"] == "mt7603e" then
            return false
        else
                return true
        end
    end)

    return jss
end

function get_Wifihidden5g()
    local uci = luci.model.uci.cursor()

    local jss
    local fname = "wireless"
    local section = "wifi-iface"
    uci:foreach( fname, section, function(s)

         jss = s["hidden"] or "0"
         if s["device"] == "mt7612e" then
            return false
        else
                return true
        end
    end)

    return jss
end


function get_dhcp_num()

   local util = require("luci.util")
   local cmd  = util.exec("cat /tmp/dhcp.leases | wc -l")

    return cmd - 0
end



function action_logout()
        local dsp = require "luci.dispatcher"
        local utl = require "luci.util"
        local sid = dsp.context.authsession

        if sid then
                utl.ubus("session", "destroy", { ubus_rpc_session = sid })

                dsp.context.urltoken.stok = nil

                luci.http.header("Set-Cookie", "sysauth=%s; expires=%s; path=%s/" %{
                        sid, 'Thu, 01 Jan 1970 01:00:00 GMT', dsp.build_url()
                })
        end

        luci.http.redirect(luci.dispatcher.build_url())
end


function Api_mode_set( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"
    local status = 0

    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local query = api.GetParam( args, "mode","router" )

    if query == "ap" then
        query = "ap"
    else
        query = "router"
    end

	local pid = nixio.fork()
    if pid < 0 then
        status = 3
    elseif pid > 0 then
        status = 1
    else
        local o = nixio.open("/dev/null", "w")
        nixio.dup(o, nixio.stdout)
        o:close()
        status = luci.sys.call( "setdevmode mode=" .. query)
        os.exit( status )
    end
    local ret = {
           state  = "ok",
    }
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( ret )
    end
    return ret
end

function Api_mode_get( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"
    local util = require("luci.util")
    local str = util.exec("ubus call network.interface.lan status|grep 'proto\": \"static'") or "proto"
    local mode = "router"
    if string.find(str,"static") == nil then
        mode = "ap"
    end

    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local ret = {
           mode  = mode,
    }
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( ret )
    end
    return ret
end


function Api_relay_get(args)
    local api = require "luci.api"
    if not args then args = {} end

    local uci = luci.model.uci.cursor()
    local fname, section = "wireless", "relay"
    local ifname = uci:get( "network", "wan", "ifname" )
    local real = api.wan_realip() or {}

    local ret = {
        disabled = uci:get( "wireless", "relay", "disabled" ) or "0",
        quality = api.qualitylevel(100),
        ssid = uci:get( "wireless", "relay", "ssid" ) or "",
        realip   = real.ip   or "",
        realmask = real.mask or "",
        realgw   = real.gw   or "",
    }
    if "1"=="1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json(api.wan_realip())
    end
    return ret
end
--[[
function Api_relay_get(args)
    local api = require "luci.api"
    if not args then args = {} end

    local uci = luci.model.uci.cursor()
    local fname, section = "wireless", "relay"
    local ifname = uci:get( "network", "wan", "ifname" )
    local ret = api.wan_realip()

    if "1"=="1" then
        luci.http.prepare_content( "application/json" )
        luci.http.write_json(ret)
    end
    return ret
end
]]--



function Api_relay_set(args)
    local relay = require "luci.relay"
    return relay.api_relay_set(args)
end

function Api_timeout_get(args)
    local api = require "luci.api"
    local uci = luci.model.uci.cursor()
    if not args then args = {} end
    local hwrite = api.GetParam(args, "hwrite", "1")
    local token = api.GetParam(args, "token", "1")
    local pass = uci:get( "account", "account", "pass" ) or "" 
    local t1=0
    local cookieid = uci:get( "account", "account", "cookieid" ) or "" 
    local cookietime = uci:get( "account", "account", "cookietime" ) or "0" 
    local diff = os.time() - cookietime - 900                        
     
    if  token == cookieid and diff <= 0 then
	t1 = 3600
    end

    local fname, section = "ifidc", "ipset"
    local ret = {
 --        timeout  = uci:get(fname, section, "timeout"),
           timeout  = t1,
    }

 --   if hwrite=="1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json(ret)
 --   end
 --   return ret
end

function Api_url_admin( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"

	if not args then args = {} end
    local query  = api.GetParam( args, "query" )
    local status = 0

    local record = {}
    uci:foreach( "url", "urlbalck", function(e)
        local ssid = api.ucidecode(e[".name"])
        record[ssid] = e
    end)



    local jss  = record
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( jss )
    end
    return jss
end

--[[
			if(data.status == 1){
				alert("�汾�����ɹ���");
				$(".current_version").text(version.newversion);
				return;
			}else if(data.status == 2){
				alert("ϵͳ����û�ҵ�ָ���汾��Դ�ļ���");
				$(".current_version").text(version.curversion);
				return;
			}else if(data.status == 3){
				alert("����汾��Դ�ļ�ʧ�ܣ�");
				$(".current_version").text(version.curversion);
				return;
			}else if(data.status == 4){
				alert("�汾��������������������");
				$(".current_version").text(version.curversion);
				return;
			}
]]--

function get_Wifipass()
    local uci = luci.model.uci.cursor()

    local jss
    local fname = "wireless"
    local section = "wifi-iface"
    uci:foreach( fname, section, function(s)
        
         if s["key"] ~= nil   then
                 jss = s["key"]
         else
              jss = "N/A"
         end
         if s["device"] == "ra0" or s["device"] == "mt7603e" then
            return false
        else
                return true
        end
    end)

    return jss
end

function get_Wifipass5g()
    local uci = luci.model.uci.cursor()

    local jss
    local fname = "wireless"
    local section = "wifi-iface"
    uci:foreach( fname, section, function(s)
         if s["key"] ~= nil   then
                 jss = s["key"]
         else
              jss = "N/A"
         end
        if s["device"] == "mt7612e" then
                return false
        else
                return true
        end
    end)

    return jss
end



function device_cur_get_now( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"
	require("luci.json")

    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )
    local pifii = require("pifii")
    local ret = pifii.get_wifi_client()
    local jss = {}

    jss["devicelist"] = ret

	   local blackmac = uci:get( "pifii", "server", "black_mac" ) or ""


	 jss["blackmac"] = luci.json.decode(blackmac)

    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( jss )
    end
    return jss
end


function device_cur_get( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"
    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local jss = {}

    jss["devicelist"] = get_dhcp_leases()

    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( jss )
    end
    return jss
end

function Api_traffic_set( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"

    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )
	local flag = api.GetParam( args, "flag" )
    local upload = api.GetParam( args, "upload" ) or "10000"
    local download = api.GetParam( args, "download" ) or "10000"
    if flag == "0" then
         uci:delete( "qos_auth","upload", "total_bandwidth" )
	 uci:delete( "qos_auth","download", "total_bandwidth" )
    else
	    uci:set( "qos_auth", "upload", "total_bandwidth", upload )
	    uci:set( "qos_auth", "download", "total_bandwidth", download )
    end
    local stat = uci:commit( "qos_auth" )
    local ret = {
           ok  = stat,
    }
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( ret )
    end
    return ret
end

function Api_traffic_get( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"

    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )
    local flag = uci:get( "qos_auth", "upload", "total_bandwidth" ) or ""
    local upload = uci:get( "qos_auth", "upload", "total_bandwidth" ) or ""
    local download = uci:get( "qos_auth", "download", "total_bandwidth" ) or ""
    if flag == "" then
	flag = 0
    else
	flag = 1
    end
    local ret = {
	     flag = flag,
             upload = upload,
	     download = download,
    }
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( ret )
    end
    return ret
end

function Api_black_mac_set( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"
	local json = require ("luci.json")
    local firew = require "luci.model.firewall".init()
    local status = 0
    jss =    firew:get_zone("lan")


    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local query = api.GetParam( args, "blackmac" )

	uci:foreach("firewall", "rule",
			function(s)
					if s.src_mac  then
							uci:delete("firewall", s['.name'])
					end
			end)
    uci:commit("firewall")



    uci:set( "pifii", "server", "black_mac", query )
    local stat = uci:commit( "pifii" )
    local obj = json.decode(query)
	local name

	for i = 1,#obj do
     	  mac =	obj[i].mac
		  if mac then
			jss:add_rule({enable=1,dest='wan',src_mac=mac,target='REJECT'})
			firew:commit("firewall")
     	   end
	end

	local pid = nixio.fork()
    if pid < 0 then
        status = 3
    elseif pid > 0 then
        status = 1
    else
--        nixio.stdclose( "oe" )
               local o = nixio.open("/dev/null", "w")

               nixio.dup(o, nixio.stdout)

               o:close()

        status = luci.sys.call( "/etc/init.d/firewall restart" )

        os.exit( status )
    end




    local ret = {
           ok  = name,
    }
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( ret )
    end
    return ret
end

function Api_black_mac_get( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"

    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local blackmac = uci:get( "pifii", "server", "black_mac" ) or ""

 --[[   local res = {}
	local cli = {}
	cli["Mac"] = "11:22:33:44:55:66"
    cli["Host"] = "Jiang"
	res[#res+1] = cli
	cli["Mac"] = "00:22:33:44:55:66"
    cli["Host"] = "bbbb"
	res[#res+1] = cli
]]--


    require("luci.json")
    local blackmacs = luci.json.decode(blackmac)
    local ret = {
           blackmac  = blackmacs,

    }
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( ret )
    end
    return ret
end

function Api_black_url_set( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"

    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local query = api.GetParam( args, "blackurl" )

    uci:set( "pifii", "server", "black_url", query )
    local stat = uci:commit( "pifii" )
	local obj = json.decode(query)
	local name

--	luci.sys.call( "/etc/init.d/firewall restart" )

	for i = 1,#obj do
     	  mac =	obj[i].host
		  if mac then
			urlacl = "iptables -I FORWARD -s " .. mac .. " -m state --state NEW,RELATED,ESTABLISHED -j DROP"
			luci.sys.call( urlacl )
     	   end
	end


    local ret = {
           ok  = stat,
    }
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( ret )
    end
    return ret
end

function Api_black_url_get( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"

    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local blackurl = uci:get( "pifii", "server", "black_url" ) or ""
    require("luci.json")

	local blackurls = luci.json.decode(blackurl)

    local ret = {
           blackurl  = blackurls,
    }
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( ret )
    end
    return ret
end

function Api_session_clear( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"

    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )
    local session = api.GetParam( args, "session", "0" )

    local ret = {
           result  = 1,
    }
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( ret )
    end
    return ret
end


function Api_sys_upgrade( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"

	if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local query = api.GetParam( args, "query" )
    local status = 0

    local pid = nixio.fork()
    if pid < 0 then
        status = 3
    elseif pid > 0 then
        status = 1
    else
--        nixio.stdclose( "oe" )
               local o = nixio.open("/dev/null", "w")

               nixio.dup(o, nixio.stdout)

               o:close()

        status = luci.sys.call( "/usr/bin/pifiiFirmwareUpdate" )

        os.exit( status )
    end


    local jss  = status
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( jss )
    end
    return jss
end

function Api_sys_set_ipaddr( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"

	if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local ipaddr = api.GetParam( args, "ipaddr","192.168.2.1" )
    local network = api.GetParam( args, "network","255.255.255.0" )
    local status = 0
    local tempV = "uci set network.lan.ipaddr=" .. ipaddr
    luci.sys.call( tempV )
    tempV = "uci set network.lan.netmask=" .. network
    luci.sys.call( tempV )



    stat = uci:commit( "network" )

    local pid = nixio.fork()
    if pid < 0 then
        status = 3
    elseif pid > 0 then
        status = 1
    else
--        nixio.stdclose( "oe" )
               local o = nixio.open("/dev/null", "w")

               nixio.dup(o, nixio.stdout)

               o:close()

        status = luci.sys.call( "/etc/init.d/network restart" )
        
	status = luci.sys.call( "sleep 5&&wifi" )

        os.exit( status )
    end


    local jss  = status
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( jss )
    end
    return jss
end

function Api_sys_factory( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"

	if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local query = api.GetParam( args, "query" )
    local status = 0

    local pid = nixio.fork()
    if pid < 0 then
        status = 3
    elseif pid > 0 then
        status = 1
    else
--        nixio.stdclose( "oe" )
               local o = nixio.open("/dev/null", "w")

               nixio.dup(o, nixio.stdout)

               o:close()

        status = luci.sys.call( "rm -rf /overlay/*&&reboot" )

        os.exit( status )
    end



    local jss  = status
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( jss )
    end
    return jss


end

function Api_sys_reboot( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"

	if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local query = api.GetParam( args, "query" )
    local status = 0

    local pid = nixio.fork()
    if pid < 0 then
        status = 3
    elseif pid > 0 then
        status = 1
    else
--        nixio.stdclose( "oe" )
               local o = nixio.open("/dev/null", "w")

               nixio.dup(o, nixio.stdout)

               o:close()

        status = luci.sys.call( "/sbin/reboot" )

        os.exit( status )
    end



    local jss  = status
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( jss )
    end
    return jss
end



function action_Id()
         --luci.http.prepare_content("text/html; charset=utf-8")
         --luci.http.write_json({token='safdfdsfa'})
        --luci.http.write_json({})
  --      return
    local http  = require "luci.http"
    local api   = require "luci.api"
    local uci   = luci.model.uci.cursor()
    local sys   = require "luci.sys"                          
                                                              

    local status, stat = 0, 0

    -- get value
    local pass = http.formvalue( "pass" ) or ""
    local pars_data = require("socket.url")
    pass = pars_data.unescape(pass)
    local p = uci:get( "account", "account", "pass" ) or ""
    local token = http.formvalue( "token" ) or ""
    local t = uci:get( "idcard", "idcard", "token" ) or ""
    local keep = http.formvalue( "keep" )
    local sess = uci:get( "idcard", "idcard", "session" ) or ""
    local ua = uci:get( "idcard", "idcard", "user_agent" ) or ""
    local savecookie = sys.uniqueid( 16 ) 
    repeat

    -- check value
    if( keep and not api.ValidEnable(keep) ) then
        status = 2 break
    end

    if pass ~= p then
        status = 101; break
    end

    -- prepare value
    local stime = ( keep=="1" ) and 3600*24*31 or 3600

    -- set value
    if keep ~= nil then
        local fname = "account"
        local secname = fname
        uci:set( fname, secname, "keep", keep )
        stat = uci:commit( fname )
        if not stat then status = 3 break end

        fname = "luci"
        secname = "sauth"
        uci:set( fname, secname, "sessiontime", stime )
        stat = uci:commit( fname )
        if not stat then status = 3 break end
    end
        local savetime = os.time()
	uci:set( "account", "account", "cookieid", savecookie ) 
        uci:set( "account", "account", "cookietime", savetime )         
        stat = uci:commit( "account" ) 	
	-- local diff = os.time() - savetime                            
        -- return diff>=0

    --api.SessionCreate( true )

    until true

    -- return value
    if status ~= 0 then t = "" sess = "" ua = "" end
    local jss = {
        ["status"] = status,
        ["token"] =  savecookie,
        ["session"] = sess,
        ["user_agent"] = ua
    }
    luci.http.prepare_content( "text/html; charset=utf-8" )
    luci.http.write_json( jss )
end


function ApiPassword( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"
    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local query = api.GetParam( args, "query" )
    local status = 0
    local pw = api.GetParam( args, "pw", "" )

	local oldpw = api.GetParam( args, "oldpw", "" )
    local tempV
    repeat

    local lfname = "account"
    local lsection = lfname

    local savepw = uci:get( "account", "account", "pass" ) or ""
    if oldpw ~= savepw then

        luci.http.prepare_content( "text/html; charset=utf-8" )
	local jzz = {                                          
            status = 0                              
           } 
        luci.http.write_json( jzz )
	return 
    end


    status = api.NamePwSet( nil, pw )


    uci:set( lfname, lsection, "_lastatus_pw", 1 )
    stat = uci:commit( lfname )


    local pid = nixio.fork()
    if pid < 0 then
        status = 3
    elseif pid > 0 then
        status = 1
    else
--        nixio.stdclose( "oe" )

               local o = nixio.open("/dev/null", "w")

               nixio.dup(o, nixio.stdout)

               o:close()


        status = api.NamePwApply( nil, pw )
        status =  1000
        uci:set( lfname, lsection, "_lastatus_pw", status )
        uci:commit( lfname )
        os.exit( status )
    end

    until true

    local jss = {
        status = status,
        token = uci:get( "idcard", "idcard", "token" ) or ""
    }
    if "1" == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( jss )
    end
    return jss
end

function ApiHostnameSet( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"
    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local query = api.GetParam( args, "query" )
    local status = 0
    local hostname = api.GetParam( args, "hostname", "" )

    repeat

    local lfname = "account"
    local lsection = lfname

    -- long operation handling start
    local lastatus = ( uci:get( lfname, lsection, "_lastatus_rb" ) or -1 ) + 0

    if query == "1" then status = lastatus break end
    if lastatus == 1 then status = 9 break end

    uci:set( lfname, lsection, "_lastatus_rb", -1 )
    local stat = uci:commit( lfname )
    if not stat then status = 3 break end
    -- long operation handling end

    status = api.NamePwSet( hostname, nil )
    if status ~= 0 then
        if status == 102 then status = 2 end
        break
    end

    uci:set( lfname, lsection, "_lastatus_rb", 1 )
    stat = uci:commit( lfname )
    if not stat then status = 3 break end

    local pid = nixio.fork()
    if pid < 0 then
        status = 3
    elseif pid > 0 then
        status = 1
    else
--        nixio.stdclose( "oe" )
               local o = nixio.open("/dev/null", "w")

               nixio.dup(o, nixio.stdout)

               o:close()

        status = api.NamePwApply( hostname, nil )

        uci:set( lfname, lsection, "_lastatus_rb", status )
        stat = uci:commit( lfname )
        os.exit( status )
    end

    until true

    local jss = api.Status( status )
    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( jss )
    end
    return jss


end

function ApiWifinameSet( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"
    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local query = api.GetParam( args, "query" )
    local status = 0
    local type = api.GetParam( args, "type", "1" )
    local hidden = api.GetParam( args, "hidden", "0" )
    local hostname = api.GetParam( args, "hostname", "" )
	    local pass = api.GetParam( args, "pass", "N/A" )
	local pars_data = require("socket.url")
	pass = pars_data.unescape(pass)
    local fname = "wireless"
    local section = "wifi-iface"
    local tempV
    local pos = 0
    local apos = 0
    local  wpos = "1"
    uci:foreach( fname, section, function(s)
        if s["device"] == "ra0" or s["device"] == "mt7603e" then
            wpos = "0"
            return false
        else
            wpos = "1"
            return false
        end
    end
    )
    if type == "1" then
        if wpos == "0" then
            pos = 0
        else
            pos = 1
        end
    else
        if wpos == "0" then
            pos = 1
        else
            pos = 0
        end
    end   

    tempV = "uci set wireless.@wifi-iface[" .. pos  .. "].ssid=" .. hostname
    luci.sys.call( tempV )

	if pass == "N/A" then
      tempV = "uci set wireless.@wifi-iface[" .. pos .. "].encryption=none"
      luci.sys.call( tempV )
      tempV = "uci delete wireless.@wifi-iface[" .. pos .. "].key"
      luci.sys.call( tempV )
    else
        tempV = "uci set wireless.@wifi-iface[" .. pos .. "].encryption=psk2"
        luci.sys.call( tempV )
        tempV = "uci set wireless.@wifi-iface[" .. pos .. "].key=" .. pass
        luci.sys.call( tempV )
    end

    tempV = "uci set wireless.@wifi-iface[" .. pos .. "].hidden=" .. hidden
    luci.sys.call( tempV )

    stat = uci:commit( fname )
    local pid = nixio.fork()
    if pid < 0 then
        status = 3
    elseif pid > 0 then
        status = 1
    else
--        nixio.stdclose( "oe" )
               local o = nixio.open("/dev/null", "w")

               nixio.dup(o, nixio.stdout)

               o:close()
        wantype = uci:get("network", "wan", "_wantype")

        status = luci.sys.call( "/sbin/wifi" )


        os.exit( status )
    end


    local jss  = hostname
    if hwrite == "1" then

        luci.http.prepare_content( "text/html; charset=utf-8" )

	luci.http.write_json( jss )
    end
    return jss


end


function ApiWifinameGet( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"
    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local jss = {}
    local fname = "wireless"
    local section = "wifi-iface"
    uci:foreach( fname, section, function(s)

        jss["hostname"] = get_Wifiname()
        jss["wifipass"] = get_Wifipass()
        jss["wifihidden"]= get_Wifihidden()
        if s["device"] == "ra0" or s["device"] == "mt7603e" then
            return false
        else
                    return true
        end
    end
    )

   uci:foreach( fname, section, function(s)



        jss["hostname5g"] = get_Wifiname5g()
        jss["wifipass5g"] = get_Wifipass5g()
        jss["wifihidden5g"]= get_Wifihidden5g()
	if s["device"] == "mt7612e" then
		return false
	else
                return true
        end
    end
    )
    

    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
	luci.http.write_json( jss )
    end
    return jss
end



function ApiHostnameGet( args )
    local uci = luci.model.uci.cursor()
    local api = require "luci.api"
    if not args then args = {} end
    local hwrite = api.GetParam( args, "hwrite", "1" )

    local jss = {}
    local fname = "system"
    local section = fname
    uci:foreach( fname, section, function(s)
        jss["hostname"] = s["hostname"]
        jss["apply"] = api.unity( s["_apply"] )
    end
    )

    if hwrite == "1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json( jss )
    end
    return jss
end

function tail_log(logfile)
    local api = require "luci.api"
    local cmd = string.format("/usr/bin/tail -n1 %s", api.shell_string(logfile))
    local fd = io.popen(cmd, "r")
    if fd then
        local line = fd:read("*l")
        fd:close()
        return line
    end
end

function is_recent_log(line, limit)
    if not line then return end
    local month, day, hour, min, sec = line:match("^(%d+)|(%d+)|(%d+)|(%d+)|(%d+)")
    local logtime = os.time( {
        year = os.date("%Y"),
        month = month,
        day=day,
        hour=hour,
        min=min,
        sec=sec,
        isdst=false,
    } )
    local diff = os.time() - logtime
    return diff>=0 and diff<=limit
end


function wan_clear( uci )
    local api = require "luci.api"
    local fname, section = "network", "wan"
 --   uci:delete( fname, section )
 --   api.InitConfigNameSection( fname, section, "interface", uci )
 --   uci:set( fname, section )
    uci:set( fname, section, "proto", "dhcp" )
    uci:set( fname, section, "ifname", "eth0.2" )
    uci:set( "wireless", "relay", "disabled", "1" )
end

function dns_check(dns)
    local api = require "luci.api"
    local dt = require "luci.cbi.datatypes"
    local tbdns = api.split(dns, " ")
    local k, v
    for k, v in pairs(tbdns) do
        if not dt.ipaddr(v) then return false end
    end
    return true
end

function Api_wip_set(args)
    local dt = require "luci.cbi.datatypes"
    local api = require "luci.api"
    if not args then args = {} end
    local hwrite = api.GetParam(args, "hwrite", "1")

    require "nixio.fs"

    local status = 0
    local proto = api.GetParam(args, "proto")
    local query = api.GetParam(args, "query")

    local uci = luci.model.uci.cursor()
    local fname, section = "network", "wan"
    local hname, hsection = "history_wan"


    local relayflag = false
    local relaytype = "normal"
    local relaysection = "relay"
    local wtype = uci:get( fname, section, "proto" ) or "dhcp"
    uci:foreach("wireless", "wifi-iface", function(s)
         if "sta" == s["mode"] then
            relaysection = s[".name"]
            if s["disabled"] or "0" == "0" then
               relayflag = true
            end
         end
    end)
    if relayflag == true  then
        uci:set( "wireless", "ra0", "channel"   , "auto"    )
        uci:set( "wireless", relaysection , "disabled"   , "1"    )
        uci:commit("wireless")
    end


    function wan_static_set()
        local ip = api.GetParam(args, "ip")
        local mask = api.GetParam(args, "mask")
        local gw = api.GetParam(args, "gw")
        local dns = api.GetParam(args, "dns")

        if not dt.ipaddr(ip) then return 2 end
        if not dt.ip6prefix(mask) and not dt.ipaddr(mask) then return 2 end
        if not dt.ipaddr(gw) then return 2 end

        wan_clear(uci, "wan")
        uci:set( fname, section, "ipaddr", ip )
        if tonumber(mask) then mask=api.ntomask(mask) end
        uci:set( fname, section, "netmask", mask )
        if gw then uci:set( fname, section, "gateway", gw ) end
        uci:set( fname, section, "_wantype", "static" )
        uci:set( fname, section, "proto", "static" )
        if dns then uci:set( fname, section, "dns", dns ) end

        uci:delete( fname, "static" )
        uci:section( fname, "record", "static", {
            ip = ip,
            mask = mask,
            gw = gw,
            dns = dns,
        } )
        hsection = string.format("S%s", ip)
        return 0
    end
    function wan_dhcp_set()
        wan_clear(uci, "wan")
        local dns = api.GetParam(args, "dns")
        uci:set( fname, section, "_wantype", "dhcp" )
	    uci:set( fname, section, "proto", "dhcp" )
        if dns then uci:set( fname, section, "dns", dns ) end
        uci:delete( fname, "dns" )
        uci:section( fname, "record", "dhcp", {
            dns = dns,
        } )
        hsection = string.format("D%s", dns or "")
        return 0
    end
    function wan_pppoe_set()
        local user = api.GetParam(args, "user", "")
        local pass = api.GetParam(args, "pass", "")
        local auto = api.GetParam(args, "auto", "1")
        local demand = api.GetParam(args, "demand", "0")
        local dns = api.GetParam(args, "dns")
        if not dt.bool(auto) or not dt.bool(demand) then return 2 end
        wan_clear(uci, "wan")
        uci:set( fname, section, "username", user )
        uci:set( fname, section, "password", pass )
        uci:set( fname, section, "demand", demand )
        if auto=="1" then uci:set( fname, section, "keepalive", "10" )
        else uci:delete( fname, section, "keepalive" ) end
        if dns then uci:set( fname, section, "dns", dns ) end
        uci:set( fname, section, "_wantype", "pppoe" )
	uci:set( fname, section, "proto", "pppoe" )
        uci:delete( fname, "zpppoe" )
        uci:section( fname, "record", "zpppoe", {
            user = user,
            pass = pass,
            auto = auto,
            demand = demand,
            dns = dns,
        } )
        hsection = string.format("P%s", user)
        return 0
    end
    function wan_3g_set()
        local name = api.GetParam(args, "name")
        local adv = api.GetParam(args, "adv", "0")
        local dns = api.GetParam(args, "dns")
        local iag
        if adv=="1" then
            iag = {
                adv      = 1,
                username = api.GetParam(args, "user"),
                password = api.GetParam(args, "pass"),
                device   = api.GetParam(args, "device"),
                apn      = api.GetParam(args, "apn"),
                service  = api.GetParam(args, "service"),
            }
        else
            available_3g( function(e)
                if name == e.name then
                    iag = {
                        device   = e.device,
                        service  = e.service,
                        username = e.username,
                        password = e.password,
                        apn      = e.apn,
                    }
                end
            end)
            if not iag then return 2 end
        end
        --wan_clear(uci, "3g")
        uci:delete( fname, section, "ifname" )
        for k, v in pairs(iag) do
            uci:set( fname, section, k, v )
        end
        if dns then uci:set( fname, section, "dns", dns ) end
        uci:set( fname, section, "_wantype", "3g" )
	uci:set( fname, section, "proto", "3g" )
        uci:delete( fname, "w3g" )
        uci:section( fname, "record", "w3g", {
            name = name,
            adv = adv,
            user = username,
            pass = password,
            device = device,
            apn = apn,
            service = service,
            dns = dns,
        } )
        hsection = string.format("G%s", name)
        return 0
    end

    local protohandle = {
        ["static"] = wan_static_set,
        ["pppoe"] = wan_pppoe_set,
        ["dhcp"] = wan_dhcp_set,
        ["3g"] = wan_3g_set,
    }

    repeat
        -- long operation handling start
        local lastatus = ( uci:get( fname, section, "_lastatus" ) or -1 ) + 0
        if query == "1" then status = lastatus break end
        --if lastatus == 1 then status = 9 break end

        local rs
        local dns = api.GetParam(args, "dns")
        if dns and not dns_check(dns) then
            rs = 2
        elseif protohandle[proto] then
            rs = protohandle[proto]()
        else
            status = 2 break
        end
        if rs==2 then status = 2 break end
        uci:set( fname, section, "proto", proto )

        uci:set( fname, section, "_lastatus", 1 )

        local stat = uci:commit( fname ) and uci:commit( "wireless" )
        if not stat then status = 3 break end

        api.to_history(uci, fname, section, hname, api.uciencode(hsection), true )

        local pid = nixio.fork()
        if pid < 0 then status = 3
        elseif pid > 0 then status = 1
        else
--            nixio.stdclose("oe")
               local o = nixio.open("/dev/null", "w")

               nixio.dup(o, nixio.stdout)

               o:close()

            local logfile = "/tmp/log/ng/ppperr"
            nixio.fs.writefile(logfile, "")
            if relayflag == true  then
	      luci.sys.call( "/sbin/wifi" )  
	    end        
            stat = uci:apply( fname )
            if stat ~= 0 then status = 5 end
            local real
            if status == 0 then
                real = api.wan_realip(8) or {}

                if proto == "pppoe" then
                    local logline = tail_log(logfile)
                    if logline and is_recent_log(logline, 10)
                            and logline:match("Password error!") then
                        status = 401
                    end
                end

                if status == 401 then
                elseif (not real.ifname) or real.proto=="none" then status=7
                else status = 0 end
            end
            uci:set( fname, section, "_lastatus", status )   uci:commit( fname )
            os.exit(status)
        end

    until true

    local ret = {
        status = status,
        ip="", mask="", gw="",
    }
    if query=="1" and status == 0 then
        local real = api.wan_realip() or {}
        ret.ip = real.ip or ""
        ret.mask = real.mask or ""
        ret.gw = real.gw or ""
    end

    if hwrite=="1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
        luci.http.write_json(ret)
    end
    return ret
end

function http_set_register(args)                                                                                       
    local api = require "luci.api"                                                                               
    local sys =  require "luci.sys"                                                                              
    if not args then args = {} end 
    local util = require("luci.util")                                              
    local ver = util.exec("touch /tmp/httpreg")
    local hwrite = "1"
    local ret = {                                                                                                
        wantype = "1"                                             
    } 
    if hwrite=="1" then                                                                                          
        luci.http.prepare_content( "text/html; charset=utf-8" )                                            
        luci.http.write_json(ret)                                                                                
    end                                                                                                          
    return ret 
end

function http_check_pass(args)                                                                                       
    local api = require "luci.api"                                                                               
    local sys =  require "luci.sys"                                                                              
    if not args then args = {} end 
    local util = require("luci.util") 
        local uci = luci.model.uci.cursor()
    local pass = api.GetParam(args, "password", "1")
    local pars_data = require("socket.url")
    pass = pars_data.unescape(pass)
    local p = uci:get( "account", "account", "pass" ) or ""
    local status = 0
    if pass == p then
        status = 1
    end    

    local hwrite = "1"

    local ret = {                                                                                                
        checkpass = status                                             
    } 
    if hwrite=="1" then                                                                                          
        luci.http.prepare_content( "text/html; charset=utf-8" )                                            
        luci.http.write_json(ret)                                                                                
    end                                                                                                          
    return ret 
end
function Api_wip_get(args)
    local api = require "luci.api"
    local sys =  require "luci.sys"
    if not args then args = {} end
    local hwrite = api.GetParam(args, "hwrite", "1")

    local util = require("luci.util")                                              
    local uci = luci.model.uci.cursor()
    local fname, section = "network", "wan"

    local relayflag = false
    local relaytype = "normal"
    local relaysection = "relay"
    local wtype = uci:get( fname, section, "proto" ) or "dhcp"
    local testV = "0"
    uci:foreach("wireless", "wifi-iface", function(s)
         if "sta" == s["mode"] then
            relaysection = s[".name"]
            testV = s["disabled"] or "0"
            if testV == "0" then
               relayflag = true
            end
         end
    end)
    if relayflag == true  then
        relaytype = "wifi"
        wtype = "wifi"
    end
    local ret = {
        wantype = wtype,
        relay = relaytype,
    }

    local real = {}
    if relayflag == true then
	 real = api.relay_realip() or {}
        -- real = api.wan_realip() or {}
    else
       real = api.wan_realip() or {}
    end
    local s = require "luci.tools.status"
    local wifidev2g = api.uci_cfg_get("idcard", "baseinfo", "wifidev2g")
    local rinfo = s.wifi_network(wifidev2g .. ".network3")
    local regS = uci:get( "pifii", "register", "device_id") or "wifi"
    local tempReg = "1"
    if regS == "wifi" then
       tempReg = "0"
    end

    ret.dhcp = {
        dns  = uci:get( fname, "dhcp", "dns"     ) or "",
    }
    ret.static = {
        ip   = uci:get( fname, "static", "ip"   ) or "",
        gw   = uci:get( fname, "static", "gw"   ) or "",
        mask = uci:get( fname, "static", "mask" ) or "",
        dns  = uci:get( fname, "static", "dns"  ) or "",
    }
    ret.pppoe = {
        user   = uci:get( fname, "zpppoe", "user"   ) or "",
        pass   = uci:get( fname, "zpppoe", "pass"   ) or "",
        auto   = tonumber( uci:get( fname, "zpppoe", "auto"   ) or 1 ),
        demand = tonumber( uci:get( fname, "zpppoe", "demand" ) or 0 ),
        dns    = uci:get( fname, "zpppoe", "dns"    ) or "",
        reg    = tempReg,
    }
    ret["3g"] = {
        name = uci:get( fname, "w3g", "name" ) or "",
        adv = tonumber( uci:get( fname, "w3g", "adv" ) or "0" ),
        user = uci:get( fname, "w3g", "user" ) or "",
        pass = uci:get( fname, "w3g", "pass" ) or "",
        device  = uci:get( fname, "w3g", "device"   ) or "",
        service = uci:get( fname, "w3g", "service"  ) or "",
        apn     = uci:get( fname, "w3g", "apn"      ) or "",
        dns     = uci:get( fname, "w3g", "dns"      ) or "",
    }
    local encr = uci:get( "wireless", relaysection, "encryption" ) or "none"
    ret.wifi = {
        disabled = tonumber( uci:get( "wireless", relaysection, "disabled" ) or "0" ),
        ssid = uci:get( "wireless", relaysection, "ssid" ) or "",
        key  = uci:get( "wireless", relaysection, "key"  ) or "",
        encryption = api.encrtonum(encr),
        --dns = uci:get( "wireless", "relay", "dns" ) or "",
    }
    local    fdName = uci:get_first( "pifii", "device", "factory" ,"")
        if "" == fdName then
            fdName = uci:get_first( "freecwmp", "device", "manufacturer" ,"")
        end
    local    fdHard = uci:get_first( "pifii", "device", "model","")
        if "" == fdHard then
            fdHard = uci:get_first( "freecwmp", "device", "hardware_version","")
        end

    local active_url = "http://192.168.2.1/cgi-bin/luci/admin/activeH?return"
    local gateway = uci:get( "network", "lan", "ipaddr")
    if gateway and "" ~= string.gsub(gateway," ","") then
       active_url = "http://"..gateway.."/cgi-bin/luci/admin/activeH?return"
    end
   local curHttpRegister = string.trim(util.exec("/bin/httpreg"))
   local str = util.exec("ubus call network.interface.lan status|grep 'proto\": \"static'") or "proto"
   local mode = "router"
   if string.find(str,"static") == nil then
       mode = "ap"
   end
    ret.real = {
        --quality = api.qualitylevel(rinfo and rinfo.quality) or 0,
	quality = get_device_quality(),
        ip   = real.ip   or "",
        mask = real.mask or "",
        gw   = real.gw   or "",
        dns  = real.dns  or "",
        dName = fdName,
        dHard = fdHard,
		curversion = get_device_version(),
        httpreg = curHttpRegister,
        mac = get_device_mac(),
		wifiname = get_Wifiname(),
		wifipass = get_Wifipass(),
                wifihidden=get_Wifihidden(),
		--wifinum  = get_dhcp_num(),
		wifinum = get_device_arp_num(),
		port = get_device_port_up(),
		--actUrl = uci:get( "pifii", "active", "url") or "http://192.168.1.1/cgi-bin/luci/admin/activeH",
		actUrl = active_url,
        regUrl = uci:get( "pifii", "server", "url") .. "/toRegisterH" or "",
        mode = mode,

    }

    if hwrite=="1" then
        luci.http.prepare_content( "text/html; charset=utf-8" )
	    luci.http.write_json(ret)
    end
    return ret
end

function Api_wifi_scan(args)
    local api = require "luci.api"
    if not args then args = {} end
    local hwrite = api.GetParam(args, "hwrite", "1")

    local sys = require "luci.sys"
    local utl = require "luci.util"
    local relay = require "luci.relay"

    local iw = relay.wifilist()

    local uci = luci.model.uci.cursor()

    local record = {}
    record.default = api.ucidecode(uci:get("wifirecord", "default", "default"))
    uci:foreach( "wifirecord", "record", function(e)
        local ssid = api.ucidecode(e[".name"])
        record[ssid] = e
    end)

    local ret = {}
    local _, net

    if iw then
        for _, net in pairs(iw) do
            net.encryption = net.encryption
            ret[#ret+1] = {
                ssid = net.ssid,
                encryption = net.encryption,
                quality = api.qualitylevel(net.percent),
                record = {}
            }

            local rsd = record[net.ssid]
            if rsd then
                ret[#ret].record = {
                    key = rsd.key,
                    channel = rsd.channel,
                    encryption = api.encrtonum(rsd.encryption),
                    default = record.default==net.ssid and 1 or 0,
                }
            end
        end
    end

    if hwrite=="1" then
        luci.http.prepare_content("text/html; charset=utf-8")
        luci.http.write_json(ret)
    end
    return ret
end

function Api_ActiveH(args)
    require "luci.model.uci"
    local api = require "luci.api"
    if not args then args = {} end
    local type = api.GetParam(args, "return", "0")
    local uci = luci.model.uci.cursor()
    local dev_id = "pifiiok"
    local token = uci:get("account","account","cookieid") or ""
    if type=="1" then                                                                                                 
        os.execute("echo 'jiang' > /tmp/testok")
	luci.http.redirect("/index.html?token="..token)
    	return 
    end 
    local flag = uci:set("pifii","register","device_id",dev_id)
    flag = uci:commit("pifii")


    local html_1 = '<div style="text-align:center"><h4>'.."Register OK!"..'</h4><a href="../../..">OK</a></div>'
    luci.http.prepare_content("text/html")
    luci.http.write(html_1)
    return ret
end

function Api_ActiveM(args)
    require "luci.model.uci"
    local api = require "luci.api"
    if not args then args = {} end
    local type = api.GetParam(args, "return", "0")
    local uci = luci.model.uci.cursor()
    local dev_id = "pifiiok"
    local token = uci:get("account","account","cookieid") or ""
    if type=="1" then                                                                                                 
        os.execute("echo 'jiang' > /tmp/testok")
	luci.http.redirect("/phone.html?token="..token)
    	return 
    end 
    local flag = uci:set("pifii","register","device_id",dev_id)
    flag = uci:commit("pifii")


    local html_1 = '<div style="text-align:center"><h4>'.."Register OK!"..'</h4><a href="../../..">OK</a></div>'
    luci.http.prepare_content("text/html")
    luci.http.write(html_1)
    return ret
end

-- modify by pixiaocong in 20160229
function Api_Active(args)
    require "luci.model.uci"
    local uci = luci.model.uci.cursor()
    local pifii = require("pifii")
    local json = require("luci.json")
    local function DEBUG_INFO(info)
        local debug_flag = pifii.debug
        local active_log = "/tmp/active.log"
        if debug_flag then
            if not info then info = "nil" end
            if "table" == type(info) then info = json.encode(info) end
            local str_time = os.date("%Y-%m-%d %H:%M:%S",os.time())
            os.execute("echo \'"..str_time.." -->> "..info.."\' >> "..active_log)
        end
    end
    local function active_request(p_json_t)
        local resp_result_t = nil
        local http_url = uci:get("pifii","server","url").."/active"
        local http_headers = pifii.http_header()
        local resp_code = nil
        local resp_json_str = nil
        local is_ssl = string.find(http_url,"^https:")
        if is_ssl then
            resp_code, resp_json_str = pifii.https_request_post(http_url,p_json_t)
        else
            resp_code, resp_json_str = pifii.http_request_post(http_url,g_http_headers,p_json_t)
        end
        --local resp_code, resp_json_str = pifii.https_request_post(http_url,http_headers,p_json_t)
        DEBUG_INFO(resp_json_str)
        if resp_code and 200 == resp_code and resp_json_str then
            local resp_json_t = json.decode(resp_json_str)
            if resp_json_t and "table" == type(resp_json_t["result"]) then
                resp_result_t = resp_json_t["result"]
            end
        end
        return resp_code,resp_result_t --return a response code and a table
    end
    --get args
    local api = require "luci.api"
    if not args then args = {} end
    local hwrite = api.GetParam(args, "hwrite", "1")
    local ret = {result="failed"}
    repeat
        local token = api.GetParam(args,"token","")
        --local http_url = uci:get("pifii","server","url")
        --local url = "http://10.18.18.1/cgi-bin/luci/admin/active?token=12323123"
        --http_url="http://10.18.18.1/cgi-bin/luci/admin"
        --local token="1234567890"
        local proto = uci:get("network","wan","proto")
        --pppoe_username=wifitest002&pppoe_password=782374
        --local username = "wifitest002" --uci:get("network","wan","username")
        --local password = "782374"--uci:get("network","wan","password")
        local username = uci:get("network","wan","username")
        local password = uci:get("network","wan","password")
        if not proto or "pppoe" ~= proto or not username or not password then
            ret["result"]="register data is wrong"
            break
        end
        local sys = require("luci.sys")
        local router_pw = sys.user.getpasswd("root")
        local request_json_t = {
            id = pifii.get_jsonid(),
            method = "active",
            jsonrpc = pifii.get_jsonrpc()
        }

        local params_json_t = {
             pppoe_username = username,
             pppoe_password = password,
             router_password = router_pw,
             token = token
        }
        request_json_t["params"] = params_json_t
        DEBUG_INFO(request_json_t)
        local resp_code,resp_result_t = active_request(request_json_t)
        --local resp_code,resp_result_t = active_request()
        --test data end--
        if not resp_code then
            ret["result"] = "response code is null"
            break
        elseif 200 ~= resp_code then
            ret["result"] = "response code: "..resp_code
            break
        elseif not resp_result_t then
            ret["result"] = "response result is null"
            break
        end
        local dev_id = resp_result_t["dev_id"]
        if not dev_id or "" == string.gsub(dev_id," ","") then
            ret["result"] = "device id is null"
            break
        end
        local flag = uci:set("pifii","register","device_id",dev_id)
        if not flag then
            uci:revert("pifii")
            break
        end
        flag = uci:commit("pifii")
        if not flag then
            uci:revert("pifii")
            break
        end
        ret["result"]= "Register OK!"
        --local url=http_url.."/active?token="..token
        --local r, c, h, body = http.get(url)
        --[[
        if c and 200 == c + 0 then
           local json = require("luci.json")
           local resp = json.decode(body)
           if resp and resp["result"] then
               local ret_code =  resp["result"]["ret_code"]
               local dev_id = resp["result"]["dev_id"]
               if ret_code and "OK" == string.upper(ret_code) and dev_id then
                    local flag = uci:set("pifii","register","device_id",dev_id)
                    if not flag then
                       uci:revert("pifii")
                    else
                       uci:commit("pifii")
                       ret["result"]="Register OK"
                    end
                else
                    ret["result"]="device id error"
                end
            else
                ret["result"]="json error"
            end
        else
            ret["result"]="server error:"..c
        end
        --]]
    until true
    if hwrite=="1" then
        local html_1 = '<div style="text-align:center"><h4>'..ret["result"]..'</h4><a href="../../.."><input type="button" value="OK"></input></a></div>'
        luci.http.prepare_content("text/html")
        luci.http.write(html_1)
    end
    return ret
end


