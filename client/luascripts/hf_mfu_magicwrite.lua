local cmds = require('commands')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils =  require('utils')
local ansicolors  = require('ansicolors')

-- global
local DEBUG = false -- the debug flag
local bxor = bit32.bxor
local _password = nil
local err_lock = 'use -k or change cfg0 block'

copyright = 'Copyright (c) 2017 IceSQL AB. All rights reserved.'
author = 'Christian Herrmann'
version = 'v1.1.4'
desc = 'This script enables easy programming of a MAGIC NTAG 21* card'
example = [[
    -- read magic tag configuration
    ]]..ansicolors.yellow..[[script run hf_mfu_magicwrite -c  ]]..ansicolors.reset..[[

    -- set uid
    ]]..ansicolors.yellow..[[script run hf_mfu_magicwrite -u 04112233445566 ]]..ansicolors.reset..[[

    -- set pwd / pack
    ]]..ansicolors.yellow..[[script run hf_mfu_magicwrite -p 11223344 -a 8080 ]]..ansicolors.reset..[[

    -- set version to NTAG213
    ]]..ansicolors.yellow..[[script run hf_mfu_magicwrite -v 0004040201000f03 ]]..ansicolors.reset..[[

    -- set signature
    ]]..ansicolors.yellow..[[script run hf_mfu_magicwrite -s 1122334455667788990011223344556677889900112233445566778899001122 ]]..ansicolors.reset..[[

    -- wipe tag
    ]]..ansicolors.yellow..[[script run hf_mfu_magicwrite -w ]]..ansicolors.reset..[[

    -- wipe a locked down tag by giving the password
    ]]..ansicolors.yellow..[[script run hf_mfu_magicwrite -k ffffffff -w ]]..ansicolors.reset..[[

]]
usage = [[
script run hf_mfu_easywrite -h -k <passwd> -c -w -u <uid> -t <type> -p <passwd> -a <pack> -s <signature> -o <otp> -v <version>
]]
arguments = [[
    -h      this help
    -c      read magic configuration
    -u      UID (14 hexsymbols), set UID on tag
    -t      tag type to impersonate
                 1 = UL EV1 48b
                 2 = UL EV1 128b
                 3 = NTAG 210
                 4 = NTAG 212
                 5 = NTAG 213 (true)
                 6 = NTAG 215 (true)
                 7 = NTAG 216 (true)
                 8 = NTAG I2C 1K
                 9 = NTAG I2C 2K
                10 = NTAG I2C 1K PLUS
                11 = NTAG I2C 2K PLUS
                12 = NTAG 213F (true)
                13 = NTAG 216F (true)
    -p      password (8 hexsymbols),  set password on tag.
    -a      pack ( 4 hexsymbols), set pack on tag.
    -s      signature data (64 hexsymbols), set signature data on tag.
    -o      OTP data (8 hexsymbols), set `One-Time Programmable` data on tag.
    -v      version data (16 hexsymbols), set version data on tag.
    -w      wipe tag. You can specify password if the tag has been locked down. Fills tag with zeros and put default values for NTAG213 (like -t 5)
    -k      pwd to use with the wipe option
]]
---
-- A debug printout-function
local function dbg(args)
    if not DEBUG then return end
    if type(args) == 'table' then
        local i = 1
        while result[i] do
            dbg(result[i])
            i = i+1
        end
    else
        print('###', args)
    end
end
-- This is only meant to be used when errors occur
local function oops(err)
    print("ERROR: ",err)
    core.clearCommandBuffer()
    return nil, err
end
---
-- Usage help
local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print(ansicolors.cyan..'Usage'..ansicolors.reset)
    print(usage)
    print(ansicolors.cyan..'Arguments'..ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan..'Example usage'..ansicolors.reset)
    print(example)
end
---
-- set the global password variable
local function set_password(pwd)
    if pwd == nil then _password = nil; return true, 'Ok' end
    if #pwd ~= 8 then return nil, 'password wrong length. Must be 4 hex bytes' end
    if #pwd == 0 then _password = nil end
    _password = pwd
    return true, 'Ok'
end
--- Picks out and displays the data read from a tag
-- Specifically, takes a usb packet, converts to a Command
-- (as in commands.lua), takes the data-array and
-- reads the number of bytes specified in arg1 (arg0 in c-struct)
-- @param usbpacket the data received from the device
local function getResponseData(usbpacket)
    local resp = Command.parse(usbpacket)
    local len = tonumber(resp.arg1) * 2
    return string.sub(tostring(resp.data), 0, len);
end
---
--
local function sendRaw(rawdata, options)

    local flags = lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT
                + lib14a.ISO14A_COMMAND.ISO14A_RAW
                + lib14a.ISO14A_COMMAND.ISO14A_APPEND_CRC

    local c = Command:newMIX{cmd = cmds.CMD_HF_ISO14443A_READER,
                arg1 = flags,
                -- arg2 contains the length, which is half the length of the ASCII-string rawdata
                arg2 = string.len(rawdata)/2,
                data = rawdata}

    return c:sendMIX(options.ignore_response)
end
---
--
local function send(payload)
    local usb, err = sendRaw(payload,{ignore_response = false})
    if err then return oops(err) end
    return getResponseData(usb)
end
---
-- select tag and if password is set, authenticate
local function connect()
    core.clearCommandBuffer()

    -- First of all, connect
    info, err = lib14a.read(true, true)
    if err then
        lib14a.disconnect()
        return oops(err)
    end
    core.clearCommandBuffer()

    --authenticate if needed using global variable
    if _password then
        send('1B'.._password)
    end
    return true
end
--
-- Read magic configuration
local function read_config()
    local info = connect()
    if not info then return false, "Can't select card" end

    -- read PWD
    local pwd = send("30F0"):sub(1,8)

    -- 04 response indicates that blocks has been locked down.
    if pwd == '04' then lib14a.disconnect(); return nil, "can't read configuration, "..err_lock end

    -- read PACK
    local pack = send("30F1"):sub(1,4)

    -- read SIGNATURE
    local signature1 = send('30F2'):sub(1,32)
    local signature2 = send('30F6'):sub(1,32)

    -- read VERSION
    local version = send('30FA'):sub(1,16)
    -- read config
    local cardtype = send('30FC'):sub(1,2)

    local typestr = ''
    if cardtype == '00' then typestr = 'NTAG 213'
    elseif cardtype == '01' then typestr = 'NTAG 215'
    elseif cardtype == '02' then typestr = 'NTAG 216'
    end

    local versionstr = 'unknown'
    if version == '0004030101000B03' then versionstr = 'UL EV1 48b'
    elseif version == '0004030101000E03' then versionstr = 'UL EV1 128b'
    elseif version == '0004040101000B03' then versionstr = 'NTAG 210'
    elseif version == '0004040101000E03' then versionstr = 'NTAG 212'
    elseif version == '0004040201000F03' then versionstr = 'NTAG 213'
    elseif version == '0004040201001103' then versionstr = 'NTAG 215'
    elseif version == '0004040201001303' then versionstr = 'NTAG 216'
    elseif version == '0004040502011303' then versionstr = 'NTAG I2C 1K'
    elseif version == '0004040502011503' then versionstr = 'NTAG I2C 2K'
    elseif version == '0004040502021303' then versionstr = 'NTAG I2C 1K PLUS'
    elseif version == '0004040502021503' then versionstr = 'NTAG I2C 2K PLUS'
    elseif version == '0004040401000F03' then versionstr = 'NTAG 213F'
    elseif version == '0004040401001303' then versionstr = 'NTAG 216F'
    end

    print('Magic NTAG 21* Configuration')
    print(' - Type    ', typestr, '(genuine cardtype)')
    print(' - Password', pwd)
    print(' - Pack    ', pack)
    print(' - Version ', version, '(' .. versionstr .. ')')
    print(' - Signature', signature1..signature2)

    lib14a.disconnect()
    return true, 'Ok'
end
---
-- Write SIGNATURE data
local function write_signature(data)

    -- uid string checks
    if data == nil then return nil, 'empty data string' end
    if #data == 0 then return nil, 'empty data string' end
    if #data ~= 64 then return nil, 'data wrong length. Should be 32 hex bytes' end

    local info = connect()
    if not info then return false, "Can't select card" end

    print('Writing new signature')

    local b,c
    local cmd = 'A2F%d%s'
    local j = 2
    for i = 1, #data, 8 do
        b = data:sub(i,i+7)
        c = cmd:format(j,b)
        local resp = send(c)
        if resp == '04' then lib14a.disconnect(); return nil, 'Failed to write signature' end
        j = j + 1
    end
    lib14a.disconnect()
    return true, 'Ok'
end
---
-- Write PWD
local function write_pwd(pwd)
    -- PWD string checks
    if pwd == nil then return nil, 'empty PWD string' end
    if #pwd == 0 then return nil, 'empty PWD string' end
    if #pwd ~= 8 then return nil, 'PWD wrong length. Should be 4 hex bytes' end

    local info = connect()
    if not info then return false, "Can't select card" end

    print('Writing new PWD ', pwd)

    local resp = send('A2F0'..pwd)
    lib14a.disconnect()
    if resp == '04' then
        return nil, 'Failed to write password'
    else
        return true, 'Ok'
    end
end
---
-- Write PACK
local function write_pack(pack)
    -- PACK string checks
    if pack == nil then return nil, 'empty PACK string' end
    if #pack == 0 then return nil, 'empty PACK string' end
    if #pack ~= 4 then return nil, 'PACK wrong length. Should be 4 hex bytes' end

    local info = connect()
    if not info then return false, "Can't select card" end

    print('Writing new PACK', pack)

    local resp = send('A2F1'..pack..'0000')
    lib14a.disconnect()
    if resp == '04' then
        return nil, 'Failed to write pack'
    else
        return true, 'Ok'
    end
end
--
-- Write OTP block
local function write_otp(block3)

    -- OTP string checks
    if block3 == nil then return nil, 'empty OTP string' end
    if #block3 == 0 then return nil, 'empty OTP string' end
    if #block3 ~= 8 then return nil, 'OTP wrong length. Should be 4 hex bytes' end

    local info = connect()
    if not info then return false, "Can't select card" end

    print('Writing new OTP ', block3)

    local resp = send('A203'..block3)
    lib14a.disconnect()
    if resp == '04' then
        return nil, 'Failed to write OTP'
    else
        return true, 'Ok'
    end
end
--
-- Writes a UID with bcc1, bcc2.  Needs a magic tag.
local function write_uid(uid)
    -- uid string checks
    if uid == nil then return nil, 'empty uid string' end
    if #uid == 0 then return nil, 'empty uid string' end
    if #uid ~= 14 then return nil, 'uid wrong length. Should be 7 hex bytes' end

    local info = connect()
    if not info then return false, "Can't select card" end

    print('Writing new UID ', uid)

    local uidbytes = utils.ConvertHexToBytes(uid)
    local bcc1 = bxor(bxor(bxor(uidbytes[1], uidbytes[2]), uidbytes[3]), 0x88)
    local bcc2 = bxor(bxor(bxor(uidbytes[4], uidbytes[5]), uidbytes[6]), uidbytes[7])
    local block0 = string.format('%02X%02X%02X%02X', uidbytes[1], uidbytes[2], uidbytes[3], bcc1)
    local block1 = string.format('%02X%02X%02X%02X', uidbytes[4], uidbytes[5], uidbytes[6], uidbytes[7])
    local block2 = string.format('%02X%02X%02X%02X', bcc2, 0x48, 0x00, 0x00)
    local resp

    resp = send('A200'..block0)
    resp = send('A201'..block1)
    resp = send('A202'..block2)
    lib14a.disconnect()

    if resp == '04' then
        return nil, 'Failed to write new uid'
    else
        return true, 'Ok'
    end
end
---
-- Write VERSION data,
-- make sure you have correct version data
local function write_version(data)
    -- version string checks
    if data == nil then return nil, 'empty version string' end
    if #data == 0 then return nil, 'empty version string' end
    if #data ~= 16 then return nil, 'version wrong length. Should be 8 hex bytes' end

    local info = connect()
    if not info then return false, "Can't select card" end

    print('Writing new version', data)

    local b1 = data:sub(1,8)
    local b2 = data:sub(9,16)
    local resp
    resp = send('A2FA'..b1)
    resp = send('A2FB'..b2)
    lib14a.disconnect()
    if resp == '04' then
        return nil, 'Failed to write version'
    else
        return true, 'Ok'
    end
end
---
-- write TYPE which card is based on.
-- 00 = 213,  01 = 215, 02 = 216
local function write_type(data)
    -- type string checks
    if data == nil then return nil, 'empty type string' end
    if #data == 0 then return nil, 'empty type string' end
    if #data ~= 2 then return nil, 'type wrong length. Should be 1 hex byte' end

    local info = connect()
    if not info then return false, "Can't select card" end
    print('Writing new type', data)

    local resp = send('A2FC'..data..'000000')
    lib14a.disconnect()
    if resp == '04' then
        return nil, 'Failed to write type'
    else
        return true, 'Ok'
    end
end
---
-- Set tag type.  Predefinde version data together with magic type set.
-- Since cmd always gives 10 bytes len (data+crc) we can impersonate the following types
-- we only truly be three types NTAG 213,215 and 216
local function set_type(tagtype)

    -- tagtype checks
    if type(tagtype) == 'string' then tagtype = tonumber(tagtype, 10) end
    if tagtype == nil then return nil, 'empty tagtype' end

    if tagtype == 1 then
        print('Setting: UL-EV1 48')
        write_otp('00000000')               -- Setting OTP to default 00 00 00 00
        write_version('0004030101000b03')   -- UL-EV1 (48) 00 04 03 01 01 00 0b 03
        write_type('00')                    -- based on NTAG213..

        -- Setting UL-Ev1 default config bl 16,17
        connect()
        send('a210000000FF')
        send('a21100050000')

    elseif tagtype == 2 then
        print('Setting: UL-EV1 128')
        write_otp('00000000')               -- Setting OTP to default 00 00 00 00
        write_version('0004030101000e03')   -- UL-EV1 (128) 00 04 03 01 01 00 0e 03
        write_type('01')

        -- Setting UL-Ev1 default config bl 37,38
        connect()
        send('a225000000FF')
        send('a22600050000')
    elseif tagtype == 3 then
        print('Setting: NTAG 210')
        write_version('0004040101000b03')   -- NTAG210 00 04 04 01 01 00 0b 03
        write_type('00')

        -- Setting NTAG210 default CC block456
        connect()
        send('a203e1100600')
        send('a2040300fe00')
        send('a20500000000')
        -- Setting  cfg1/cfg2
        send('a210000000FF')
        send('a21100050000')
    elseif tagtype == 4 then
        print('Setting: NTAG 212')
        write_version('0004040101000E03')   -- NTAG212 00 04 04 01 01 00 0E 03
        write_type('00')

        -- Setting NTAG212 default CC block456
        connect()
        send('a203e1101000')
        send('a2040103900a')
        send('a205340300fe')
        -- Setting  cfg1/cfg2
        send('a225000000FF')
        send('a22600050000')
    elseif tagtype == 5 then
        print('Setting: NTAG 213')
        write_version('0004040201000F03')       -- NTAG213 00 04 04 02 01 00 0f 03
        write_type('00')

        -- Setting NTAG213 default CC block456
        connect()
        send('a203e1101200')
        send('a2040103a00c')
        send('a205340300fe')
        -- setting cfg1/cfg2
        send('a229000000ff')
        send('a22a00050000')
    elseif tagtype == 6 then
        print('Setting: NTAG 215')
        write_version('0004040201001103')       -- NTAG215 00 04 04 02 01 00 11 03
        write_type('01')

        -- Setting NTAG215 default CC block456
        connect()
        send('a203e1103e00')
        send('a2040300fe00')
        send('a20500000000')
        -- setting cfg1/cfg2
        send('a283000000ff')
        send('a28400050000')
    elseif tagtype == 7 then
        print('Setting: NTAG 216')
        write_version('0004040201001303')       -- NTAG216 00 04 04 02 01 00 13 03
        write_type('02')

        -- Setting NTAG216 default CC block456
        connect()
        send('a203e1106d00')
        send('a2040300fe00')
        send('a20500000000')
        -- setting cfg1/cfg2
        send('a2e3000000ff')
        send('a2e400050000')
    elseif tagtype == 8 then
        print('Setting: NTAG I2C 1K')
        write_version('0004040502011303')       -- NTAG_I2C_1K 00 04 04 05 02 01 13 03
        write_type('02')

        -- Setting NTAG I2C 1K default CC block456
        connect()
        send('a203e1106D00')
        send('a2040300fe00')
        send('a20500000000')
    elseif tagtype == 9 then
        print('Setting: NTAG I2C 2K')
        write_version('0004040502011503')       -- NTAG_I2C_2K 00 04 04 05 02 01 15 03
        write_type('02')

        -- Setting NTAG I2C 2K default CC block456
        connect()
        send('a203e110EA00')
        send('a2040300fe00')
        send('a20500000000')
    elseif tagtype == 10 then
        print('Setting: NTAG I2C plus 1K')
        write_version('0004040502021303')       -- NTAG_I2C_1K 00 04 04 05 02 02 13 03
        write_type('02')

        -- Setting NTAG I2C 1K default CC block456
        connect()
        send('a203e1106D00')
        send('a2040300fe00')
        send('a20500000000')
    elseif tagtype == 11 then
        print('Setting: NTAG I2C plus 2K')
        write_version('0004040502021503')       -- NTAG_I2C_2K 00 04 04 05 02 02 15 03
        write_type('02')

        -- Setting NTAG I2C 2K default CC block456
        connect()
        send('a203e1106D00')
        send('a2040300fe00')
        send('a20500000000')
    elseif tagtype == 12 then
        print('Setting: NTAG 213F')
        write_version('0004040401000F03')       -- NTAG213F 00 04 04 04 01 00 0f 03
        write_type('00')

        -- Setting NTAG213 default CC block456
        connect()
        send('a203e1101200')
        send('a2040103a00c')
        send('a205340300fe')
        -- setting cfg1/cfg2
        send('a229000000ff')
        send('a22a00050000')
    elseif tagtype == 13 then
        print('Setting: NTAG 216F')
        write_version('0004040401001303')       -- NTAG216F 00 04 04 04 01 00 13 03
        write_type('02')

        -- Setting NTAG216 default CC block456
        connect()
        send('a203e1106d00')
        send('a2040300fe00')
        send('a20500000000')
        -- setting cfg1/cfg2
        send('a2e3000000ff')
        send('a2e400050000')
    end

    lib14a.disconnect()
    if resp == '04' then
        return nil, 'Failed to set type'
    else
        return true, 'Ok'
    end
end
---
-- wipe tag
local function wipe()

    local info = connect()
    if not info then return false, "Can't select card" end

    local err, msg, resp
    local cmd_empty = 'A2%02X00000000'
    local cmd_cfg1  = 'A2%02X000000FF'
    local cmd_cfg2  = 'A2%02X00050000'

    print('Wiping tag')

    for b = 3, 0xFB do
        --configuration block 0
        if b == 0x29 or b == 0x83 or b == 0xe3 then
            local cmd = (cmd_cfg1):format(b)
            resp = send(cmd)
        --configuration block 1
        elseif b == 0x2a or b == 0x84 or b == 0xe4 then
            local cmd = (cmd_cfg2):format(b)
            resp = send(cmd)
        else
            resp = send(cmd_empty:format(b))
        end
        if resp == '04' or #resp == 0 then
            io.write('\nwrote block '..b, ' failed\n')
            err = true
        else
            io.write('.')
        end
        io.flush()
    end
    io.write('\r\n')

    lib14a.disconnect()

    if err then return nil, "Tag locked down, "..err_lock end

    print('setting default values...')

    set_password(nil)

    -- set NTAG213 default values
    err, msg = set_type(5)
    if err == nil then return err, msg end

    --set UID
    err, msg = write_uid('04112233445566')
    if err == nil then return err, msg end

    --set pwd
    err, msg = write_pwd('FFFFFFFF')
    if err == nil then return err, msg end

    --set pack
    err, msg = write_pack('0000')
    if err == nil then return err, msg end

    return true, 'Ok'
end
---
-- The main entry point
function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    local err, msg

    if #args == 0 then return help() end

    -- Read the parameters
    for o, a in getopt.getopt(args, 'hck:u:t:p:a:s:o:v:w') do

        -- help
        if o == "h" then return help() end

        --key
        if o == 'k' then err, msg = set_password(a) end

        -- configuration
        if o == "c" then err, msg = read_config() end

        --wipe tag
        if o == "w" then err, msg = wipe() end

        -- write uid
        if o == "u" then err, msg = write_uid(a) end

        -- write type/version
        if o == "t" then err, msg = set_type(a) end

        -- write pwd
        if o == "p" then err, msg = write_pwd(a) end

        -- write pack
        if o == "a" then err, msg = write_pack(a) end

        -- write signature
        if o == "s" then err, msg = write_signature(a) end

        -- write otp
        if o == "o" then err, msg = write_otp(a) end

        -- write version
        if o == "v" then err, msg = write_version(a) end

        if err == nil then return oops(msg) end
    end

end

main(args)
