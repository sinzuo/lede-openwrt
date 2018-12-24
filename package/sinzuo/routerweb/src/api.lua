module( "luci.api", package.seeall )

flowfile = {
    pre = "/tmp/flow",
    now = "/proc/net/dev",
}

apipre = {"api", "0"}
defuser = "panda"
official_bin = "/usr/sbin/wftoken"

MOUNTROOT = "/tmp/mpbase/storageroot"
MOUNTAPP  = "/tmp/mpbase/app"
MOUNTSELF = "Data"

DOWNLOAD = {
    tmproot = "/tmp/torrent-to-do/",
}

BLKID = "/tmp/blkid"

function call_no_stdout(cmd)
    require "luci.sys"
    cmd = cmd .. " >/dev/null"
    return luci.sys.call(cmd)
end

function uci_cfg_get(fname, section, option)
    local uci = (require "luci.model.uci").cursor()
    return uci:get(fname, section, option)
end

function get_comm_by_pidfile(fpid)
    local fs = require "nixio.fs"
    local pid = fs.readfile("/var/run/" .. fpid)
    if not pid then return end
    pid = pid:match("%d+")
    local path = string.format("/proc/%s/comm", pid)
    local ret = fs.readfile(path)
    return ret and ret:match("[^\n]+")
end

function apiuri( funn, mode )
    if mode == nil then
        mode = "module"
    end
    uri = { apipre[1], apipre[2], mode, funn}
    return uri
end

function dir_base(ss)
    local s, e = ss:find("[^/]+$")
    if not s then return ss, nil
    else return ss:sub(1, s-1), ss:sub(s, e) end
end

function byte_format( nb )
    if not nb then return end
    local wa  = require "luci.tools.webadmin"
    return wa.byte_format(nb)
end

function digit_format( num )
    if not num then return end
    local units = { "K", "M", "G", "T", }
    local base = 1000
    local u = ""
    for _, v in pairs(units) do
        if num >= base then
            num = num/1000
            u = v
        end
    end
    if u == "" then ret = tostring(num)
    else
        ret = string.format("%.2f %s", num, u)
    end
    return ret
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

function flowformat( xx )
    xx = tonumber(xx)
    if xx == nil then return { 0, "0" } end
    xx = string.format( "%.0f", xx )
    return { xx, xx and byte_format(tonumber(xx)) or "0" }
end
function bagformat( xx )
    xx = tonumber(xx)
    if xx == nil then return { 0, "0" } end
    xx = string.format( "%.0f", xx )
    return { xx, xx and digit_format(tonumber(xx)) or "0" }
end
function uciencode(str, div)
    if not div then div="_" end
    if not str then return end
    local ret = str:gsub("[^%w]", function(e)
        return string.format("%s%X", div, e:byte())
    end)
    return ret
end

function ucidecode(str, div)
    if not str then return end
    if not div then div = "_" end
    local pat = div .. "%x%x"
    local ret = str:gsub(pat, function(e)
        return string.char(tonumber(e:sub(2),16))
    end)
    return ret
end


function split(str, char)
    local tab = {};
    while str and str~="" do
        local pos = string.find(str, char, 1, true);
        if (not pos) then
            tab[#tab + 1] = str
            break
        end
        if pos > 1 then
            local sub = string.sub(str, 1, pos - 1);
            tab[#tab + 1] = sub;
        end
        str = string.sub(str, pos + 1, #str);
    end
    return tab;
end

function ntomask( nl )
    nl = tonumber(nl)
    if not nl then return end
    function getbyte()
        local r
        if nl>=8 then
            nl = nl - 8
            r = 8
        else
            r = nl
            nl = 0
        end
        return 8-r
    end
    ret = ""
    for i=1,4 do
        ret = ret .. "." .. (256-2^getbyte())
    end
    return string.sub(ret, 2, #ret)
end

function maskton( mask )
    if not mask then return end
    local units = {
        ["0"]   = 0,
        ["128"] = 1,
        ["192"] = 2,
        ["224"] = 3,
        ["240"] = 4,
        ["248"] = 5,
        ["252"] = 6,
        ["254"] = 7,
        ["255"] = 8,
    }
    local tab = split(mask, ".")
    local ret = 0
    local s, e = 1, #tab
    while s<=e do
        if tab[s] == "255" then ret = ret+8  s=s+1
        else break end
    end
    while s<=e do
        if tab[e] == "0" then e=e-1
        else break end
    end
    local lst = tab[s]
    if s<e or not lst or not units[lst] then return end
    ret = ret + units[lst]
    if ret>0 then return ret end
end

function reach_arp( func, dev )
    if not dev then dev="br-lan" end
    local pcmd = string.format("ip neigh show dev %s", dev)
    local pf = io.popen(pcmd)
    local ret = {}
    if pf then
        while true do
            local ln = pf:read("*l")
            if not ln then break end
            local ay = split(ln, " ")
            if #ay < 3 then break end
            local e = { ip = ay[1], mac = ay[3] }
            ret[#ret+1] = e
            if type(func)=="function" then func(e) end
        end
        pf:close()
    end
    return ret
end

function sysblkid( update )
    local fs = require "nixio.fs"
    local json = require "luci.json"
    local ret = {}
    if update then
        local pf = io.popen("/usr/sbin/blkid")
        if pf then
            while true do
                local ln = pf:read("*l")
                if not ln then break end
                local fs = ln:match("^([%w/]+):")
                if not fs:match("^/dev/loop") and not fs:match("^/dev/mtd") then
                    local e = {
                        fs = ln:match("^([%w/]+):"),
                        uuid = ln:match("UUID=\"([%x-]+)\""),
                        label = ln:match("LABEL=\"([%w]+)\""),
                        fstype = ln:match("TYPE=\"([%w_]+)\""),
                    }
                    ret[#ret+1] = e
                end
            end
            pf:close()
        end
        fs.writefile(BLKID, json.encode(ret))
    else
        local body = fs.readfile(BLKID)
        if body then
            ret = json.decode(body)
        else
            ret = sysblkid(true)
        end
    end
    return ret
end

function unity( zo, def )
    if def and not zo then zo=def end
    if zo==true or zo==1 or zo=="1" then
        return 1
    else return 0 end
end

function set_mac_factory( mtb )
    local ubus = require "ubus"
    local conn = ubus.connect()
    if not conn then return mtb end

    local k, v
    local ref = {}
    for k, v in pairs(mtb) do
        ref[#ref+1] = v.mac
    end
    local hwf = conn:call("evenprime", "hwfactory", { hwarray=ref })
    if type(hwf) == "table" then
        for k, v in pairs(mtb) do
            v.factory = hwf[v.mac] or ""
        end
    end

    return mtb
end

function to_history( puci, fname, fsection, hname, hsection, default )
    require "luci.model.uci"
    require "nixio.fs"
    local config = GetConfigPath( hname )
    local uci = puci or luci.model.uci.cursor()

    if not nixio.fs.access( config ) then
        nixio.fs.writefile( config, "" )
    end

    local fvalue = uci:get_all(fname, fsection)
    fvalue["__name"] = fvalue[".name"]
    fvalue["__type"] = fvalue[".type"]
    fvalue["_lastatus"] = nil
    uci:delete( hname, hsection )
    uci:section( hname, "history", hsection, fvalue )

    if default then
        uci:set( hname, "default", hsection )
    end

    uci:commit( hname )

    return uci
end

function from_history( puci, hname, hsection, fname, fsection )
    require "luci.model.uci"
    require "nixio.fs"
    local config = GetConfigPath( fname )
    local uci = puci or luci.model.uci.cursor()
    if not nixio.fs.access( config ) then
        nixio.fs.writefile( config, "" )
    end
    local hvalue = uci:get_all( hname, hsection )
    if hvalue then
        local sname = fsection or hvalue["__name"]
        local stype = hvalue["__type"]
        hvalue["__name"] = nil
        hvalue["__type"] = nil
        uci:delete(fname, sname)
        uci:section(fname, stype, sname, hvalue)
        uci:commit(fname)
    end
end

function delete_history( puci, hname, hsection )
    require "luci.model.uci"
    require "nixio.fs"
    local uci = puci or luci.model.uci.cursor()
    uci:delete(hname, hsection)
    local index = uci:get(hname, "default") or ""
    if index==hsection then
        uci:delete(hname, "default")
    end
    return uci:commit(hname)
end

function Status( status )
    local s = { ["status"] = status }
    return s
end

function GetConfigPath( fname )
    fname = fname or ""
    --local config = os.getenv( "LUCI_SYSROOT" ) .. "/etc/config/" .. fname
    local config = "/etc/config/" .. fname
    return config
end

function InitConfigNameSection( fname, secname, sectype, uci )
    local config = GetConfigPath( fname )
    local l_uci = uci or luci.model.uci.cursor()
    local l_type = sectype or string.upper( secname )

    if not nixio.fs.access( config ) then
        nixio.fs.writefile( config, "" )
    end
    l_uci:set( fname, secname, l_type )
    return l_uci
end

function InitConfigTypeSection( fname, section, uci )
    local config = GetConfigPath( fname )
    local l_uci = uci or luci.model.uci.cursor()

    if not nixio.fs.access( config ) then
        nixio.fs.writefile( config, "" )
        --l_uci:add( fname, section )
    end
    return l_uci
end

function NewSectionName( fname, section, uci )
    local sys = require "luci.sys"
    local l_uci = uci or luci.model.uci.cursor()

    local n, retry = 0, 3
    local id = nil
    local typen = nil

    while n <= retry do
        id = sys.uniqueid( 8 )
        typen = l_uci:get( fname, id )
        if not typen then break end
        id = nil
        n = n + 1
    end

    return id;
end

function GetParam( args, name, def )
    local val = args[ name ] or luci.http.formvalue( name )
    if not val or val == "" then val = def end
    if type(val) == "number" then val = tostring(val) end
    return val
end

function HandleAction( args, name )
    local action = GetParam( args, "action", "" )
    local a1, a2

    repeat

        if type( action ) == "string" then
            a1, a2 = action, ""
            break
        end

        if type( action ) ~= "table" then
            a1, a2 = "", ""
            break
        end

        -- From now on, handle table
        if #action ~= 2 then
            a1, a2 = "", ""
            break
        end

        if action[1] == "apply" then
            a1, a2 = action[2], action[1]
        else
            a1, a2 = action[1], action[2]
        end

    until true

    return a1,a2
end

function ValidFirstBoot()
    local uci = luci.model.uci.cursor()
    local p = uci:get( "account", "account", "pass" ) or nil
    local ret = false

    if p == "88888888" then ret = true end

    return ret
end


function _SessionValid( utoken, cookie, chklist )
    local sauth = require "luci.sauth"
    local uci = luci.model.uci.cursor()

    local ret = false

    repeat

    local token = uci:get( "idcard", "idcard", "token" ) or ""
    if utoken ~= "" and token ~= "" then
        ret = ( utoken == token ) and true or false
        break
    end

    cookie = cookie and cookie:match( "^[a-f0-9]*$" )
    if not cookie then break end

    local session = sauth.read( cookie )
    if not session then break end

    local ok = true
    for k,v in pairs( chklist ) do
        if not session[k] or session[k] ~= v then
            ok = false break
        end
    end
    if not ok then break end

    ret = true

    until true

    return ret
end

function SessionValid( token, cookie )
    local chklist = {
        ["ip"] = luci.http.getenv( "REMOTE_ADDR" ),
        ["agent"] = luci.http.getenv( "HTTP_USER_AGENT" )
    }

    local ret = _SessionValid( token, cookie, chklist )

    return ret, cookie
end

function SessionCreate( setclient )
    local http  = require "luci.http"
    local sys   = require "luci.sys"
    local sauth = require "luci.sauth"
    local dsp   = require "luci.dispatcher"

    local sid    = sys.uniqueid( 16 )
    local secret = sys.uniqueid( 16 )
    sauth.reap()
    sauth.write( sid, {
            ip     = http.getenv( "REMOTE_ADDR" ),
            agent  = http.getenv( "HTTP_USER_AGENT" ),
            secret = secret
        }
    )

    if setclient == true then
        http.header( "Set-Cookie", "sysauth=" ..sid.. "; path=" ..dsp.build_url() )
    end

    return sid;
end


function SambaReload()
    local sys = require "luci.sys"
    local stat = 0
    local out = sys.exec( "/bin/pidof smbd" ) or nil
    if out and out:match( "^%d+" ) then
        stat = luci.sys.call( "/etc/init.d/samba reload 1>/dev/null 2>&1" )
    end

    return stat
end


function _NameSet( name )
    local uci = luci.model.uci.cursor()

    local status, stat = 0, 0
    local fname, section = "", ""


    repeat

    -- system, namely name itself
    fname = "system"
    section = fname

    local idname = ""
    InitConfigTypeSection( fname, section, uci )
    uci:foreach( fname, section, function(s)
        idname = s[ ".name" ]
    end
    )

    uci:set( fname, idname, "hostname", name )
    local stat = uci:commit( fname )
    if not stat then status = 3 break end

    -- wifi
    fname = "wireless"
    section = "wifiap"
    uci:set( fname, section, "ssid", name )

    section = "guest"
    uci:set( fname, section, "ssid", name.."-Guest" )

    stat = uci:commit( fname )
    if not stat then status = 3 break end

    -- idcard
    fname = "idcard"
    section = fname
    uci:set( fname, section, "sync", 0 )
    stat = uci:commit( fname )
    if not stat then status = 3 break end

    -- samba
    --[[
    fname = "samba"
    section = fname
    uci:set( fname, section, "name", name )
    stat = uci:commit( fname )
    if not stat then status = 3 break end

    local cmd = "/bin/sed -r -i -e '/:1000:/ s/^[^:]+:/"..name..":/' " ..
                "/etc/passwd /etc/samba/smbpasswd"
    stat = luci.sys.call( cmd )
    if stat ~= 0 then status = 3 break end
    ]]--

    until true

    return status;
end

function _PwSet( pw )
    local uci = luci.model.uci.cursor()

    local status, stat = 0, 0
    local fname, section = "", ""

    repeat

    -- account, namely pw itself
    fname = "account"
    section = fname

    InitConfigNameSection( fname, section, nil, uci )

    uci:set( fname, section, "pass", pw )
    local stat = uci:commit( fname )
    if not stat then status = 3 break end

    -- wifi
    --fname = "wireless"
    --section = "wifiap"
    --uci:set( fname, section, "encryption", "psk2" )
    --uci:set( fname, section, "key", pw )

    --stat = uci:commit( fname )
    --if not stat then status = 3 break end

    -- samba
    local name = "witfii"
    local cmd = "/bin/echo -e '"..pw.."\n"..pw.."' | /usr/sbin/smbpasswd -s -a "..name
    stat = luci.sys.call( cmd )
    if stat ~= 0 then status = 3 break end

    until true

    return status;
end

function NamePwSet( name, pw )
    local uci = luci.model.uci.cursor()
    local dt = require "luci.cbi.datatypes"
    local util = require "luci.util"

    local status, stat = 0, 0

    repeat

    -- check value

    --local excludes = { "root", "daemon", "ftp", "network", "nobody" }
    local excludes = { "" }
    if name and
       (
         not ( 1<= #name and #name <= 25 ) or
         luci.util.contains( excludes, name )
       )
    then
        status = 102 break
    end

    if pw and not dt.wpakey( pw ) then
        status = 103 break
    end

    -- set value
    if name then status = _NameSet( name ) end
    if status ~= 0 then break end

    if pw then _PwSet( pw ) end
    if status ~= 0 then break end

    until true

    return status
end

function NamePwApply( name, pw )
    local uci = luci.model.uci.cursor()
    local sys = require( "luci.sys" )

    local status, stat = 0, 0

    -- begin to reload service
    repeat

    if name or pw then
        -- restart wifi
        stat = uci:apply( "wireless" )
        if stat ~= 0 then status = 5 break end

        -- restart samba
        stat = SambaReload()
        if stat ~= 0 then status = 5 break end
    end

    if name then
        sys.hostname( name )

        -- restart minidlna
        stat = sys.call( "/etc/init.d/minidlna reload 1>/dev/null 2>&1" )

        -- restart dnsmasq
    end

    until true

    return status
end


function samba_internaldev(idf)
    require "luci.model.uci"
    local uci = luci.model.uci.cursor()
    local fname = "samba"
    local section = "sambashare"
    local path = ""

    local k, v
    local interdir = { "Photo", "Document", "Music", "Video", "Data" }
    local path = idf.mountpoint .. "/"
    for k, v in pairs(interdir) do
        local uname = v
        uci:set( fname, uname, section )
        uci:set( fname, uname, "_fs", idf.fs )
        uci:set( fname, uname, "name", v )
        uci:set( fname, uname, "path", path .. v )
        uci:set( fname, uname, "read_only", "no" )
        --uci:set( fname, uname, "guest_ok", "no" )
        uci:set( fname, uname, "create_mask", "0644" )
        uci:set( fname, uname, "dir_mask", "0755" )
    end

    local stat = uci:commit( fname )
    return stat
end


function samba_add( dfinfo )
    require "luci.model.uci"
    local uci = luci.model.uci.cursor()
    local fname = "samba"
    local section = "sambashare"
    local path = ""

    local k, v
    for k, v  in pairs(dfinfo) do
        local path = v.mountpoint
        local dir, base = dir_base(path)
        if dir == (MOUNTROOT .. "/") then
            local uname = uciencode( base )

            uci:set( fname, uname, section )
            uci:set( fname, uname, "_fs", v.fs )
            uci:set( fname, uname, "name", base )
            uci:set( fname, uname, "path", path )
            uci:set( fname, uname, "read_only", "no" )
            --uci:set( fname, uname, "guest_ok", "no" )
            uci:set( fname, uname, "create_mask", "0644" )
            uci:set( fname, uname, "dir_mask", "0755" )
        end
    end

    local stat = uci:commit( fname )
    return stat
end

function samba_delete( bdev )
    require "luci.model.uci"
    require "luci.sys"
    local uci = luci.model.uci.cursor()
    local fname = "samba"
    local section = "sambashare"

    --local df = luci.sys.mounts()
    local rdf = {}
    local pat = bdev .. "[%d]*$"
    --for k, v in pairs(df) do
        --if v.fs:match(pat) then
            --rdf[v.fs] = v.mountpoint
        --end
    --end

    uci:delete_all( fname, section, function(s)
        --return rdf[s["_fs"]]
        return s["_fs"] and s["_fs"]:match(pat)
    end)

    local stat = uci:commit( fname )
    return stat
end



function ValidEnable( val )
    val = tonumber( val )

    if val ~= nil and ( val == 0 or val == 1 ) then
        return true
    else
        return false
    end
end

function UpdateDownloading()
    local sys = require "luci.sys"
    local cmd = '/bin/ps | /bin/grep "/usr/bin/wget -q -O .*firmware.bin" | /bin/grep -q -v grep'
    local stat = sys.call( cmd )
    return stat == 0 and true or false
end



-- 根据实际另外分配power 大小
function powertolevel( p )
    if not p then return end
    p = tonumber(p) or 9
    if p>20 then return 3
    elseif p>15 then return 2
    elseif p>5 then return 1
    else return 0; end
end
function leveltopower( l )
    l = tonumber(l)
    if not l then return end
    local lv = { 0, 9, 18, 27 }
    return lv[l+1]
end


function mount(fs, mp, ft)
    local opt, own = "uid=1000,gid=1000", "/bin/chown 1000:1000 "
    mp = shell_string(mp)
    --if call_no_stdout("/bin/df | /bin/grep mp")==0 then return end
    call_no_stdout("/bin/mkdir -p " .. mp)
    call_no_stdout(own .. mp)
    local tmp = opt .. " " .. fs .. " " .. mp
    local ec
    if ft=="crypto_LUKS" then
        call_no_stdout("echo sidavid | cryptsetup luksOpen " .. fs .. " app")
        local capp = string.format("/bin/mount /dev/mapper/app %s", mp)
        ec = call_no_stdout(capp)
    elseif ft=="ntfs" then
        ec = call_no_stdout("/usr/bin/ntfs-3g -o nls=utf8," .. tmp)
    elseif ft=="vfat" then
        ec = call_no_stdout("/bin/mount -t vfat -o iocharset=utf8,rw,umask=0000,dmask=0000,fmask=0000," .. tmp)
    elseif ft:match("ext") then
        ec = call_no_stdout("/bin/mount " .. fs .. " " .. mp)
    else
        ec = call_no_stdout("/bin/mount -o " .. tmp)
    end
    call_no_stdout(own .. mp)
    if ec ~= 0 then
        call_no_stdout("/bin/rmdir " .. mp)
    end
    return ec==0
end


function system_name()
    local fs = require "nixio.fs"
    local name = fs.readfile("/tmp/sysinfo/board_name")
    name = name and name:match("[^\n]*")
    return name
end

function GetRouterVer()
    local fs = require "nixio.fs"
    local ver = fs.readfile( "/etc/openwrt_version" )
    ver = ver and ver:match( "[^\n]*" )
    return ver
end

function get_internaldev_devname()
    local usbpat = uci_cfg_get("idcard", "baseinfo", "internaldev") or "/----:"
    local fd = io.popen("/bin/ls /sys/block/sd* -l", "r")
    if fd then
        while true do
            local line = fd:read("*l")
            if not line then break end
            if line:find(usbpat, 1, true) then
                fd:close()
                local ud = line:match("sd[%a]+$")
                return ud
            end
        end
        fd:close()
    end
end


function mount_device(devpath, devname)
    local lmu = require "luci.model.uci"
    local uci = lmu.cursor()

    local k, v
    local blkid = sysblkid(true)
    local idx = 0

    local usbpat = uci_cfg_get("idcard", "baseinfo", "internaldev") or "/----:"
    local isinner = devpath:find(usbpat, 1, true)
    if isinner then
        local fname, section = "fstab", "automount"
        InitConfigNameSection( fname, section, "_automount", uci )
        uci:set(fname, section, "inner", devname)
        uci:commit(fname)
    end
    local mp
    local ret = {}
    for k, v in pairs(blkid) do
        if v.fs:match(devname .. "%w+") and v.fstype then
            idx = idx+1
            label = v.label or "attach"
            local nid = v.fs:match("sd([%w]+)") or v.fs:match("mmc([%w]+)")
            if isinner then
                if v.fstype == "swap" then
                    idx = idx-1
                    call_no_stdout("/usr/sbin/swapon " .. v.fs)
                elseif idx==1 then mp = MOUNTAPP
                elseif idx==2 then mp = MOUNTROOT
                else mp = string.format("%s/%s(P%s)", MOUNTROOT, label, nid)
                end
            else
                mp = string.format("%s/%s(P%s)", MOUNTROOT, label, nid)
            end
            if mount(v.fs, mp, v.fstype) then
                ret[#ret+1] = { mountpoint = mp, fs = v.fs }
            end
        end
    end
    return ret
end

function umount_device(devpath, devname)
    require "luci.sys"
    local lmu = require "luci.model.uci"
    local uci = lmu.cursor()

    local k, v

    local df = luci.sys.mounts()
    local pat = devname .. "[%d]*$"
    local ret = {}
    local _, v
    for _, v in pairs(df) do
        local mp = v.mountpoint
        if v.fs:match(pat) then
            local fs = shell_string(v.fs)
            mp = shell_string(mp)
            call_no_stdout("/bin/umount -f " .. mp)
            call_no_stdout("/bin/umount -f " .. fs)
            call_no_stdout("/bin/rmdir " .. mp)
            ret[#ret+1] = { mountpoint = v.mp, fs = v.fs }
        end
    end
    sysblkid(true)
    return ret
end

function get_network_interface(str)
    local ubus = require "ubus"
    local conn = ubus.connect()
    if not conn then return end
    local status = conn:call("network.interface." .. str, "status", {})
    return status
end

function get_network_jmac(str)
    local ubus = require "ubus"
    local conn = ubus.connect()
    if not conn then return end
    local device = conn:call("network.device", "status", {name="eth0.1"})
    return device.macaddr or "01:02:03:04:05:06"
end

function relay_realip(times)
    if not times or times<1 then times=1 end
    while times>0 do
        times = times - 1
        local net = get_network_interface("bridge")
        if net and net["l3_device"] and net.proto then
            local jmac =  get_network_jmac(net["l3_device"])
            local ip = net["ipv4-address"] and net["ipv4-address"][1]
            local ipv6 = net["ipv6-address"] and net["ipv6-address"][1]
            local ret = {
                ip     = ip and ip.address,
                mask   = ip and ip.mask,
                uptime = net.uptime,
                gw     = net.route and net.route[1] and net.route[1].target,
                dns    = net["dns-server"],
                proto  = net.proto,
                ifname = net["l3_device"],
                mac = jmac,
            }
            return ret
        end
        if times>0 then call_no_stdout("/bin/sleep 1") end
    end
end

function wan_realip(times)
    if not times or times<1 then times=1 end
    while times>0 do
        times = times - 1
        local net = get_network_interface("wan")
        if net and net["l3_device"] and net.proto then
            local jmac =  get_network_jmac(net["l3_device"])
            local ip = net["ipv4-address"] and net["ipv4-address"][1]
            local ipv6 = net["ipv6-address"] and net["ipv6-address"][1]
            local ret = {
                ip     = ip and ip.address,
                mask   = ip and ip.mask,
                uptime = net.uptime,
                gw     = net.route and net.route[1] and net.route[1].target,
                dns    = net["dns-server"],
                proto  = net.proto,
                ifname = net["l3_device"],
                mac = jmac,
            }
            return ret
        end
        if times>0 then call_no_stdout("/bin/sleep 1") end
    end
end

function deal_ping( host )
    if not host then return 0 end
    local pr = os.execute("/bin/ping -q -w 2 -c 2 " .. host .. ">/dev/null 2>/dev/null" )
    if pr==0 then return 1
    else return 0 end
end

function shell_string(str)
    if not str then return "''" end
    local sl = str:gsub("'", "'\\''")
    return "'" .. sl .. "'"
end

function connect_detect()
    local util = require "luci.util"
    local rip = wan_realip(1)
    local gw = rip and rip.gw
    local net = "www.baidu.com"
    local _SL = shell_string

    local lv
    if gw then
        local cmd = string.format("/usr/bin/pingdetect %s %s"
                , _SL(gw), _SL(net) )
        lv = tonumber(util.exec(cmd))
    else
        lv = 0
    end
    return lv
end

function md5sum(ss)
    local cmd = "/bin/echo \"" .. ss .. "\" | /usr/bin/md5sum"
    --local cmd = "/bin/echo " .. shell_string(ss) .. " | /usr/bin/md5sum"
    mdname = luci.util.exec(cmd)
    if mdname then mdname = mdname:sub(1, 32) end
    return mdname
end


function qualitylevel( percent)
    local scale = percent
    if not scale or scale == 0 then icon = 0
    elseif scale < 25 then icon = 1
    elseif scale < 50 then icon = 2
    elseif scale < 75 then icon = 3
    else icon = 4 end
    return icon
end


function html_decode(str)
    local s = str:gsub("&#?[%w]+;", function(e)
        if e:sub(2,2)=="#" then return string.char(e:sub(3, #e-1)) end
        local pre = e:sub(2, #e-1)
        if pre == "lt" then return "<"
        elseif pre == "gt" then return ">"
        elseif pre == "quot" then return '"'
        elseif pre == "amp" then return "&" end
    end)
    return s
end

function wait_second( lmt, fun, ... )
    local nio = require "nixio"
    for i=1,lmt do
        nio.nanosleep(1)
        local a = fun(...)
        if a then return true end
    end
end

function config_reset( uci, fname, section, items, retain )
    local stype = uci:get(fname, section)
    local k, v
    local store = {}
    for k, v in pairs(retain or {}) do
        local vv = uci:get(fname, section, v)
        store[v] = vv
    end
    uci:delete( fname, section )
    InitConfigNameSection( fname, section, stype, uci )
    for k, v in pairs(items or {}) do
        uci:set(fname, section, k, v)
    end
    for k, v in pairs(store) do
        uci:set(fname, section, k, v)
    end
end
