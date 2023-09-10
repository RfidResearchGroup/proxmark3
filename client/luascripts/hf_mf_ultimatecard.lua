local cmds = require('commands')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils =  require('utils')
local ansicolors  = require('ansicolors')

-- global
local DEBUG = false -- the debug flag
local bxor = bit32.bxor
local _ntagpassword = nil
local _key = '00000000' -- default UMC key
local err_lock = 'use -k or change cfg0 block'
local _print = 0
copyright = ''
author = 'Nathan Glaser'
version = 'v1.0.5'
date = 'Created - Jan 2022'
desc = 'This script enables easy programming of an Ultimate Mifare Magic card'
example = [[
    -- read magic tag configuration
    ]]..ansicolors.yellow..[[script run hf_mf_ultimatecard -c  ]]..ansicolors.reset..[[

    -- set uid
    ]]..ansicolors.yellow..[[script run hf_mf_ultimatecard -u 04112233445566 ]]..ansicolors.reset..[[

    -- set NTAG pwd / pack
    ]]..ansicolors.yellow..[[script run hf_mf_ultimatecard -p 11223344 -a 8080 ]]..ansicolors.reset..[[

    -- set version to NTAG213
    ]]..ansicolors.yellow..[[script run hf_mf_ultimatecard -v 0004040201000f03 ]]..ansicolors.reset..[[

    -- set ATQA/SAK to [00 44] [08]
    ]]..ansicolors.yellow..[[script run hf_mf_ultimatecard -q 004408 ]]..ansicolors.reset..[[

    -- wipe tag with a NTAG213 or Mifare 1k S50 4 byte
    ]]..ansicolors.yellow..[[script run hf_mf_ultimatecard -w 1]]..ansicolors.reset..[[

    -- use a non default UMC key. Only use this if the default key for the MAGIC CARD was changed.
    ]]..ansicolors.yellow..[[script run hf_mf_ultimatecard -k ffffffff -w 1]]..ansicolors.reset..[[

    -- Wipe tag, turn into NTAG215, set sig, version, NTAG pwd/pak, and OTP.
    ]]..ansicolors.yellow..[[script run hf_mf_ultimatecard -w 1 -t 18 -u 04112233445566 -s 112233445566778899001122334455667788990011223344556677 -p FFFFFFFF -a 8080 -o 11111111]]..ansicolors.reset..[[

]]
usage = [[
script run hf_mf_ultimatecard -h -k <passwd> -c -w <type> -u <uid> -t <type> -p <passwd> -a <pack> -s <signature> -o <otp> -v <version> -q <atqa/sak> -g <gtu> -z <ats> -m <ul-mode> -n <ul-protocol>
]]
arguments = [[
    -h      this help
    -c      read magic configuration
    -u      UID (8-20 hexsymbols), set UID on tag
    -t      tag type to impersonate
                 1 = Mifare Mini S20 4-byte
                 2 = Mifare Mini S20 7-byte 15 = NTAG 210
                 3 = Mifare Mini S20 10-byte 16 = NTAG 212
                 4 = Mifare 1k S50 4-byte   17 = NTAG 213
                 5 = Mifare 1k S50 7-byte   18 = NTAG 215
                 6 = Mifare 1k S50 10-byte  19 = NTAG 216
                 7 = Mifare 4k S70 4-byte   20 = NTAG I2C 1K
                 8 = Mifare 4k S70 7-byte   21 = NTAG I2C 2K
                 9 = Mifare 4k S70 10-byte  22 = NTAG I2C 1K PLUS
            ***  10 = UL -   NOT WORKING FULLY   23 = NTAG I2C 2K PLUS
            ***  11 = UL-C - NOT WORKING FULLY   24 = NTAG 213F
                 12 = UL EV1 48b                25 = NTAG 216F
                 13 = UL EV1 128b
            ***  14 = UL Plus - NOT WORKING YET

    -p      NTAG password (8 hexsymbols),  set NTAG password on tag.
    -a      NTAG pack ( 4 hexsymbols), set NTAG pack on tag.
    -s      Signature data (64 hexsymbols), set signature data on tag.
    -o      OTP data (8 hexsymbols), set `One-Time Programmable` data on tag.
    -v      Version data (16 hexsymbols), set version data on tag.
    -q      ATQA/SAK (<2b ATQA><1b SAK> hexsymbols), set ATQA/SAK on tag.
    -g      GTU Mode (1 hexsymbol), set GTU shadow mode.
    -z      ATS (<1b length><0-16 ATS> hexsymbols), Configure ATS. Length set to 00 will disable ATS.
    -w      Wipe tag. 0 for Mifare or 1 for UL. Fills tag with zeros and put default values for type selected.
    -m      Ultralight mode (00 UL EV1, 01 NTAG, 02 UL-C, 03 UL) Set type of UL.
    -n      Ultralight protocol (00 MFC, 01 UL), switches between UL and MFC mode
    -k      Ultimate Magic Card Key (IF DIFFERENT THAN DEFAULT 00000000)
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
    print(date)
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
local function set_ntagpassword(pwd)
    if pwd == nil then _ntagpassword = nil; return true, 'Ok' end
    if #pwd ~= 8 then return nil, 'password wrong length. Must be 4 hex bytes' end
    if #pwd == 0 then _ntagpassword = nil end
    _ntagpassword = pwd
    return true, 'Ok'
end
-- set the global UMC key variable
local function set_key(key)
    print('Key:'..key)
    if key == nil then _key = '00000000'; return true, 'Ok' end
    if #key ~= 8 then return nil, 'UMC key is wrong the length. Must be 4 hex bytes' end
    if #key == 0 then _key = nil end
    _key = key
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
local function sendRaw(rawdata, options)
    local flags = lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT
                + lib14a.ISO14A_COMMAND.ISO14A_RAW
                + lib14a.ISO14A_COMMAND.ISO14A_APPEND_CRC
    local c = Command:newMIX{cmd = cmds.CMD_HF_ISO14443A_READER,
                arg1 = flags,
                arg2 = string.len(rawdata)/2,
                data = rawdata}
    return c:sendMIX(options.ignore_response)
end
---
local function send(payload)
    local usb, err = sendRaw(payload,{ignore_response = false})
    if err then return oops(err) end
    return getResponseData(usb)
end
---
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
    if _ntagpassword then
        send('1B'.._ntagpassword)
    end
    return true
end
---
-- Read magic configuration
local function read_config()
    local info = connect()
    if not info then return false, "Can't select card" end
    -- read Ultimate Magic Card CONFIG
    if magicconfig == nil then
    magicconfig = send("CF".._key.."C6")
    else print('No Config')
    end
    -- extract data from CONFIG - based on CONFIG in https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/magic_cards_notes.md#gen-4-gtu
    ulprotocol, uidlength, readpass, gtumode, ats, atqa1, atqa2, sak, ulmode = magicconfig:sub(1,2), magicconfig:sub(3,4), magicconfig:sub(5,12), magicconfig:sub(13,14), magicconfig:sub(15,48), magicconfig:sub(51,52), magicconfig:sub(49,50), magicconfig:sub(53,54), magicconfig:sub(55,56)
    atqaf = atqa1..' '..atqa2
    cardtype, cardprotocol, gtustr, atsstr = 'unknown', 'unknown', 'unknown', 'unknown'
    if magicconfig == nil then lib14a.disconnect(); return nil, "can't read configuration, "..err_lock end
    if #magicconfig ~= 64 and #magicconfig ~= 68 then lib14a.disconnect(); return nil, "partial read of configuration, "..err_lock end
    if gtumode == '00' then gtustr = 'Pre-write/Shadow Mode'
    elseif gtumode == '01' then gtustr = 'Restore Mode'
    elseif gtumode == '02' then gtustr = 'Disabled'
    elseif gtumode == '03' then gtustr = 'Disabled, high speed R/W mode for Ultralight'
    end
    if ats:sub(1,2) == '00' then atsstr = 'Disabled'
    else atsstr = (string.sub(ats, 3))
    end
    if ulprotocol == '00' then
    cardprotocol = 'MIFARE Classic Protocol'
    ultype = 'Disabled'
    if uidlength == '00' then
        uid = send("CF".._key.."CE00"):sub(1,8)
        if atqaf == '00 04' and sak == '09' then cardtype = 'MIFARE Mini S20 4-byte UID'
        elseif atqaf == '00 04' and sak == '08' then cardtype = 'MIFARE 1k S50 4-byte UID'
        elseif atqaf == '00 02' and sak == '18' then cardtype = 'MIFARE 4k S70 4-byte UID'
        end
    elseif uidlength == '01' then
        uid = send("CF".._key.."CE00"):sub(1,14)
        if atqaf == '00 44' and sak == '09' then cardtype = 'MIFARE Mini S20 7-byte UID'
        elseif atqaf == '00 44' and sak == '08' then cardtype = 'MIFARE 1k S50 7-byte UID'
        elseif atqaf == '00 42' and sak == '18' then cardtype = 'MIFARE 4k S70 7-byte UID'
        end
    elseif uidlength == '02' then
        uid = send("CF".._key.."CE00"):sub(1,20)
        if atqaf == '00 84' and sak == '09' then cardtype = 'MIFARE Mini S20 10-byte UID'
        elseif atqaf == '00 84' and sak == '08' then cardtype = 'MIFARE 1k S50 10-byte UID'
        elseif atqaf == '00 82' and sak == '18' then cardtype = 'MIFARE 4k S70 10-byte UID'
        end
    end
    elseif ulprotocol == '01' then
    -- Read Ultralight config only if UL protocol is enabled
    cardprotocol = 'MIFARE Ultralight/NTAG'
    block0 = send("3000")
    uid0 = block0:sub(1,6)
    uid = uid0..block0:sub(9,16)
    if ulmode == '00' then ultype = 'Ultralight EV1'
    elseif ulmode == '01' then ultype = 'NTAG21x'
    elseif ulmode == '02' then ultype = 'Ultralight-C'
    elseif ulmode == '03' then ultype = 'Ultralight'
    end
    -- read VERSION
    cversion = send('30FA'):sub(1,16)
    -- pwdblock must be set since the 30F1 and 30F2 special commands don't work on the ntag21x part of the UMC
    if ulmode == '03' then versionstr = 'Ultralight'
    elseif ulmode == '02' then versionstr = 'Ultralight-C'
    elseif cversion == '0004030101000B03' then versionstr = 'UL EV1 48b'
    elseif cversion == '0004030101000E03' then versionstr = 'UL EV1 128b'
    elseif cversion == '0004040101000B03' then versionstr = 'NTAG 210'
    elseif cversion == '0004040101000E03' then versionstr = 'NTAG 212'
    elseif cversion == '0004040201000F03' then versionstr = 'NTAG 213'
    elseif cversion == '0004040201001103' then versionstr = 'NTAG 215'
    elseif cversion == '0004040201001303' then versionstr = 'NTAG 216'
    elseif cversion == '0004040502011303' then versionstr = 'NTAG I2C 1K'
    elseif cversion == '0004040502011503' then versionstr = 'NTAG I2C 2K'
    elseif cversion == '0004040502021303' then versionstr = 'NTAG I2C 1K PLUS'
    elseif cversion == '0004040502021503' then versionstr = 'NTAG I2C 2K PLUS'
    elseif cversion == '0004040401000F03' then versionstr = 'NTAG 213F'
    elseif cversion == '0004040401001303' then versionstr = 'NTAG 216F'
    end
    -- read PWD
    cpwd = send("30F0"):sub(1,8)
    pwd = send("30E5"):sub(1,8)
    -- 04 response indicates that blocks has been locked down.
    if pwd == '04' then lib14a.disconnect(); return nil, "can't read configuration, "..err_lock end
    -- read PACK
    cpack = send("30F1"):sub(1,4)
    pack = send("30E6"):sub(1,4)
    -- read SIGNATURE
    signature1 = send('30F2'):sub(1,32)
    signature2 = send('30F6'):sub(1,32)
    lib14a.disconnect()
    end
    if _print < 1 then
    print(string.rep('=', 88))
    print('\t\t\tUltimate Magic Card Configuration')
    print(string.rep('=', 88))
    print(' - Raw Config      ', string.sub(magicconfig, 1, -9))
    print(' - Card Protocol    ', cardprotocol)
    print(' - Ultralight Mode   ', ultype)
    print(' - ULM Backdoor Key ', readpass)
    print(' - GTU Mode     ', gtustr)
    if ulprotocol == '01' then
        print(' - Card Type     ', versionstr)
    else
        print(' - Card Type     ', cardtype)
    end
    print(' - UID           ', uid)
    print(' - ATQA          ', atqaf)
    print(' - SAK          ', sak)
    if ulprotocol == '01' then
        print('')
        print(string.rep('=', 88))
        print('\t\t\tMagic UL/NTAG 21* Configuration')
        print(string.rep('=', 88))
        print(' - ATS          ', atsstr)
        print(' - Password     ', '[0xE5] '..pwd, '[0xF0] '..cpwd)
        print(' - Pack         ', '[0xE6] '..pack, '[0xF1] '..cpack)
        print(' - Version      ', cversion)
        print(' - Signature    ', signature1..signature2)
    end
    end
lib14a.disconnect()
return true, 'Ok'
end
---
-- calculate block0
local function calculate_block0(useruid)
    local uidbytes = utils.ConvertHexToBytes(useruid)
    local i = 1
    local bcc = bxor(uidbytes[i], uidbytes[i+1]);
    local length = #useruid / 2;

    -- bcc
    for i = 3, length, 1 do bcc = bxor(bcc, uidbytes[i]) end

    -- block0
    local block0 = ""
    for i = 1, length, 1 do block0 = block0..string.format('%02X', uidbytes[i]) end

    return block0..string.format('%02X', bcc)
end
--
-- Writes a UID for MFC and MFUL/NTAG cards
local function write_uid(useruid)
    -- read CONFIG
    if not magicconfig then
    _print = 1
    read_config()
    end
    local info = connect()
    if not info then return false, "Can't select card" end
    -- Writes a MFC UID with GEN4 magic commands.
    if ulprotocol == '00' then
    -- uid string checks
    if useruid == nil then return nil, 'empty uid string' end
    if #useruid == 0 then return nil, 'empty uid string' end
    if (#useruid ~= 8) and (#useruid ~= 14) and (#useruid ~= 20) then return nil, 'UID wrong length. Should be 4, 7 or 10 hex bytes' end
    print('Writing new UID ', useruid)
    local block0 = calculate_block0(useruid)
    print('Calculated block0 ', block0)
    local resp = send('CF'.._key..'CD00'..block0)
    -- Writes a MFUL UID with bcc1, bcc2 using NTAG21xx commands.
    elseif ulprotocol == '01' then
    -- uid string checks
    if useruid == nil then return nil, 'empty uid string' end
    if #useruid == 0 then return nil, 'empty uid string' end
    if #useruid ~= 14 then return nil, 'uid wrong length. Should be 7 hex bytes' end
    print('Writing new UID ', useruid)
    local uidbytes = utils.ConvertHexToBytes(useruid)
    local bcc1 = bxor(bxor(bxor(uidbytes[1], uidbytes[2]), uidbytes[3]), 0x88)
    local bcc2 = bxor(bxor(bxor(uidbytes[4], uidbytes[5]), uidbytes[6]), uidbytes[7])
    local block0 = string.format('%02X%02X%02X%02X', uidbytes[1], uidbytes[2], uidbytes[3], bcc1)
    local block1 = string.format('%02X%02X%02X%02X', uidbytes[4], uidbytes[5], uidbytes[6], uidbytes[7])
    local block2 = string.format('%02X%02X%02X%02X', bcc2, 0x48, 0x00, 0x00)
    local resp
    resp = send('A200'..block0)
    resp = send('A201'..block1)
    resp = send('A202'..block2)
    else
    print('Incorrect ul')
    end
    lib14a.disconnect()
    if resp ~= nil then
        return nil, oops('Failed to write UID')
    else
        return true, 'Ok'
    end
end
---
-- Write ATQA/SAK
  local function write_atqasak(atqasak)
    -- read CONFIG
    if not magicconfig then
    _print = 1
    read_config()
    end
    if atqasak == nil then return nil, 'Empty ATQA/SAK string' end
    if #atqasak == 0 then return nil, 'Empty ATQA/SAK string' end
    if #atqasak ~= 6 then return nil, 'ATQA/SAK wrong length. Should be 6 hex bytes. I.E. 004408  ATQA(0044) SAK(08)' end
    local atqauser1 = atqasak:sub(1,2)
    local atqauser2 = atqasak:sub(3,4)
    local atqauserf = atqauser2..atqauser1
    local sakuser = atqasak:sub(5,6)
    if sakuser == '04' then
    print('Never set SAK bit 3 (e.g. SAK=04), it indicates an extra cascade level is required')
    return nil
    elseif (sakuser == '20' or sakuser == '28') and atslen == '00' then
    print('When SAK equals 20 or 28, ATS must be turned on')
    return nil
    elseif atqauser2 == '40' then
    print('ATQA of [00 40] will cause the card to not answer.')
    return nil
    else
    local info = connect()
    if not info then return false, "Can't select card" end
    print('New ATQA: '..atqauser1..' '..atqauser2..'  New SAK: '..sakuser)
    local resp = send("CF".._key.."35"..atqauserf..sakuser)
    lib14a.disconnect()
    if resp == nil then
        return nil, oops('Failed to write ATQA/SAK')
    else
        return true, 'Ok'
    end
    end
end
---
-- Write NTAG PWD
local function write_ntagpwd(ntagpwd)
    -- read CONFIG
    if not magicconfig then
    _print = 1
    read_config()
    end
    if ulprotocol == '00' then return nil, 'Magic Card is not using the Ultralight Protocol' end
    -- PWD string checks
    if ntagpwd == nil then return nil, 'empty NTAG PWD string' end
    if #ntagpwd == 0 then return nil, 'empty NTAG PWD string' end
    if #ntagpwd ~= 8 then return nil, 'NTAG PWD wrong length. Should be 4 hex bytes' end
    local info = connect()
    if not info then return false, "Can't select card" end
    print('Writing new NTAG PWD ', ntagpwd)
    local resp = send('A2E5'..ntagpwd) -- must add both for password to be read by the reader command B1
    local resp = send('A2F0'..ntagpwd)
    lib14a.disconnect()
    if resp == nil then
        return nil, 'Failed to write password'
    else
        return true, 'Ok'
    end
end
---
-- Write PACK
local function write_pack(userpack)
    -- read CONFIG
    if not magicconfig then
    _print = 1
    read_config()
    end
    if ulprotocol == 0 then return nil, 'Magic Card is not using the Ultralight Protocol' end
    -- PACK string checks
    if userpack == nil then return nil, 'empty PACK string' end
    if #userpack == 0 then return nil, 'empty PACK string' end
    if #userpack ~= 4 then return nil, 'PACK wrong length. Should be 4 hex bytes' end
    local info = connect()
    if not info then return false, "Can't select card" end
    print('Writing new PACK', userpack)
    send('A2E6'..userpack..'0000')
    send('A2F1'..userpack..'0000')
    lib14a.disconnect()
    return true, 'Ok'
end
---
-- Write OTP block
local function write_otp(block3)
    -- OTP string checks
    if block3 == nil then return nil, 'empty OTP string' end
    if #block3 == 0 then return nil, 'empty OTP string' end
    if #block3 ~= 8 then return nil, 'OTP wrong length. Should be 4 hex bytes' end
    -- read CONFIG
    if not magicconfig then
    _print = 1
    read_config()
    end
    if ulprotocol == '00' then return nil, 'Magic Card is not using the Ultralight Protocol' end
    local info = connect()
    if not info then return false, "Can't select card" end
    print('Writing new OTP ', block3)
    local resp = send('A203'..block3)
    lib14a.disconnect()
    if resp ~= '0A' then return false, oops('Failed to write OTP')
    else
        return true, 'Ok'
    end
end
---
-- Write VERSION data,
-- make sure you have correct version data
local function write_version(data)
    -- Version string checks
    if data == nil then return nil, 'empty version string' end
    if #data == 0 then return nil, 'empty version string' end
    if #data ~= 16 then return nil, 'version wrong length. Should be 8 hex bytes' end
    -- read CONFIG
    if not magicconfig then
    _print = 1
    read_config()
    end
    if ulprotocol == '00' then return nil, 'Magic Card is not using the Ultralight Protocol' end
    print('Writing new version', data)
    local b1 = data:sub(1,8)
    local b2 = data:sub(9,16)
    local info = connect()
    if not info then return false, "Can't select card" end
    local resp
    resp = send('A2FA'..b1)
    resp = send('A2FB'..b2)
    lib14a.disconnect()
    if resp ~= '0A' then return nil, oops('Failed to write version')
    else
        return true, 'Ok'
    end

end
---
-- Write SIGNATURE data
local function write_signature(data)
    -- Signature string checks
    if data == nil then return nil, 'empty data string' end
    if #data == 0 then return nil, 'empty data string' end
    if #data ~= 64 then return nil, 'data wrong length. Should be 32 hex bytes' end
    -- read CONFIG
    if not magicconfig then
    _print = 1
    read_config()
    end
    local info = connect()
    if not info then return false, "Can't select card" end
    if ulprotocol == '00' then
        print('Writing new MFC signature',data)
        send('CF'.._key..'6B48')
        lib14a.disconnect()
        connect() -- not 100% sure why it's needed, but without this blocks aren't actually written
        local sig1 = data:sub(1, 32)
        local sig2 = data:sub(33, 64)

        send('CF'.._key..'CD45'..sig1)
        send('CF'.._key..'CD46'..sig2)
        send('CF'.._key..'CD475C8FF9990DA270F0F8694B791BEA7BCC')
    else
        print('Writing new MFUL signature',data)
        local b,c
        local cmd = 'A2F%d%s'
        local j = 2
        for i = 1, #data, 8 do
            b = data:sub(i,i+7)
            c = cmd:format(j,b)
            local resp = send(c)
            if resp ~= '0A' then lib14a.disconnect(); return nil, oops('Failed to write signature') end
            j = j + 1
        end
    end
    lib14a.disconnect()
    return true, 'Ok'
end
---
-- Enable/Disable GTU Mode
-- 00: pre-write, 01: restore mode, 02: disabled, 03: disabled, high speed R/W mode for Ultralight
local function write_gtu(gtu)
    if gtu == nil then return nil, 'empty GTU string' end
    if #gtu == 0 then return nil, 'empty GTU string' end
    if #gtu ~= 2 then return nil, 'type wrong length. Should be 1 hex byte' end
    local info = connect()
    if not info then return false, "Can't select card" end
    if gtu == '00' then
    print('Enabling GTU Pre-Write')
    send('CF'.._key..'32'..gtu)
    elseif gtu == '01' then
    print('Enabling GTU Restore Mode')
    send('CF'.._key..'32'..gtu)
    elseif gtu == '02' then
    print('Disabled GTU')
    send('CF'.._key..'32'..gtu)
    elseif gtu == '03' then
    print('Disabled GTU, high speed R/W mode for Ultralight')
    send('CF'.._key..'32'..gtu)
    else
    print('Failed to set GTU mode')
    end
    lib14a.disconnect()
    return true, 'Ok'
end
---
-- Write ATS
-- First hexbyte is length. 00 to disable ATS. 16 hexbytes for ATS
local function write_ats(atsuser)
    if atsuser == nil then return nil, 'empty ATS string' end
    if #atsuser == 0 then return nil, 'empty ATS string' end
    if #atsuser > 34 then return nil, 'type wrong length. Should be <1b length><0-16b ATS> hex byte' end
    local atscardlen = atsuser:sub(1,2)
    local atscardlendecimal = tonumber(atscardlen, 16)
    local atsf = string.sub(atsuser, 3)
    if (#atsf / 2) ~= atscardlendecimal then
    oops('Given length of ATS ('..atscardlendecimal..') does not match the ATS_length ('..(#atsf / 2)..')')
    return true, 'Ok'
    else
    local info = connect()
    if not info then return false, "Can't select card" end
    print('Writing '..atscardlendecimal..' ATS bytes of '..atsf)
    send("CF".._key.."34"..atsuser)
    end
    lib14a.disconnect()
    return true, 'Ok'
end
---
-- Change UL/MFC protocol
local function write_ulp(ulp)
    if ulp == nil then return nil, 'empty ULP string' end
    if #ulp == 0 then return nil, 'empty ULP string' end
    if #ulp > 2 then return nil, 'type wrong length. Should be 1 hex byte' end
    local info = connect()
    if not info then return false, "Can't select card" end
    if ulp == '00' then
    print('Changing card to Mifare Classic Protocol')
    send("CF".._key.."69"..ulp)
    elseif ulp == '01' then
    print('Changing card to Ultralight Protocol')
    send("CF".._key.."69"..ulp)
    else
        oops('Protocol needs to be either 00 or 01')
    end
    lib14a.disconnect()
    return true, 'Ok'
end
---
-- Change UL Mode Type
local function write_ulm(ulm)
    if ulm == nil then return nil, 'empty ULM string' end
    if #ulm == 0 then return nil, 'empty ULM string' end
    if #ulm > 2 then return nil, 'type wrong length. Should be 1  hex byte' end
    local info = connect()
    if not info then return false, "Can't select card" end
    if ulm == '00' then
    print('Changing card UL mode to Ultralight EV1')
    send("CF".._key.."6A"..ulm)
    elseif ulm == '01' then
    print('Changing card UL mode to NTAG')
    send("CF".._key.."6A"..ulm)
    elseif ulm == '02' then
    print('Changing card UL mode to Ultralight-C')
    send("CF".._key.."6A"..ulm)
    elseif ulm == '03' then
    print('Changing card UL mode to Ultralight')
    send("CF".._key.."6A"..ulm)
    else
        oops('UL mode needs to be either 00, 01, 02, 03')
    end
    lib14a.disconnect()
    return true, 'Ok'
end
---
--  Set type for magic card presets.
local function set_type(tagtype)
    -- tagtype checks
    if type(tagtype) == 'string' then tagtype = tonumber(tagtype, 10) end
    if tagtype == nil then return nil, oops('empty tagtype') end
    -- Setting Mifare mini S20 4-byte
    if tagtype == 1 then
        print('Setting: Ultimate Magic card to Mifare mini S20 4-byte')
        connect()
    send("CF".._key.."F000000000000002000978009102DABC19101011121314151604000900")
    lib14a.disconnect()
        write_uid('04112233')
    -- Setting Mifare mini S20 7-byte
    elseif tagtype == 2 then
        print('Setting: Ultimate Magic card to Mifare mini S20 7-byte')
        connect()
    send("CF".._key.."F000010000000002000978009102DABC19101011121314151644000900")
    lib14a.disconnect()
        write_uid('04112233445566')
    -- Setting Mifare mini S20 10-byte
    elseif tagtype == 3 then
        print('Setting: Ultimate Magic card to Mifare mini S20 10-byte')
        connect()
    send("CF".._key.."F000020000000002000978009102DABC19101011121314151684000900")
    lib14a.disconnect()
        write_uid('04112233445566778899')
    -- Setting Mifare 1k S50 4--byte
    elseif tagtype == 4 then
        print('Setting: Ultimate Magic card to Mifare 1k S50 4-byte')
        connect()
    send("CF".._key.."F000000000000002000978009102DABC19101011121314151604000800")
    lib14a.disconnect()
        write_uid('04112233')
    -- Setting Mifare 1k S50 7-byte
    elseif tagtype == 5 then
        print('Setting: Ultimate Magic card to Mifare 1k S50 7-byte')
        connect()
    send("CF".._key.."F000010000000002000978009102DABC19101011121314151644000800")
    lib14a.disconnect()
        write_uid('04112233445566')
    -- Setting Mifare 1k S50 10-byte
    elseif tagtype == 6 then
        print('Setting: Ultimate Magic card to Mifare 1k S50 10-byte')
        connect()
    send("CF".._key.."F000020000000002000978009102DABC19101011121314151684000800")
    lib14a.disconnect()
        write_uid('04112233445566778899')
    -- Setting Mifare 4k S70 4-byte
    elseif tagtype == 7 then
        print('Setting: Ultimate Magic card to Mifare 4k S70 4-byte')
        connect()
    send("CF".._key.."F000000000000002000978009102DABC19101011121314151602001800")
    lib14a.disconnect()
        write_uid('04112233')
    -- Setting Mifare 4k S70 7-byte
    elseif tagtype == 8 then
        print('Setting: Ultimate Magic card to Mifare 4k S70 7-byte')
        connect()
    send("CF".._key.."F000010000000002000978009102DABC19101011121314151642001800")
    lib14a.disconnect()
        write_uid('04112233445566')
    -- Setting Mifare 4k S70 10-byte
    elseif tagtype == 9 then
        print('Setting: Ultimate Magic card to Mifare 4k S70 10-byte')
        connect()
    send("CF".._key.."F000020000000002000978009102DABC19101011121314151682001800")
    lib14a.disconnect()
        write_uid('04112233445566778899')
    -- Setting UL
    elseif tagtype == 10 then
        print('Setting: Ultimate Magic card to UL')
        connect()
    send("CF".._key.."F0010100000000030A0A78008102DBA0C119402AB5BA4D321A44000003")
    lib14a.disconnect()
        write_uid('04112233445566')
        write_otp('00000000')               -- Setting OTP to default 00 00 00 00
        write_version('0000000000000000')   -- UL-C does not have a version
    -- Setting UL-C
    elseif tagtype == 11 then
        print('Setting: Ultimate Magic card to UL-C')
        connect()
    send("CF".._key.."F0010100000000030A0A78008102DBA0C119402AB5BA4D321A44000002")
    print('Setting default permissions and 3des key')
        send('A22A30000000')            -- Auth0 page 48/0x30 and above need authentication
        send('A22B80000000')            -- Auth1 read and write access restricted
        send('A22C42524541')            -- Default 3des key
    send('A22D4B4D4549')
    send('A22E46594F55')
    send('A22F43414E21')
    lib14a.disconnect()
        write_uid('04112233445566')
        write_otp('00000000')               -- Setting OTP to default 00 00 00 00
        write_version('0000000000000000')   -- UL-C does not have a version
    elseif tagtype == 12 then
        print('Setting: Ultimate Magic card to UL-EV1 48')
    connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000000")
        -- Setting UL-Ev1 default config bl 16,17
    send('a2E5FFFFFFFF') -- A2F0 block does not align correctly to actual pwd block
    send('a2E6FFFFFFFF') -- A2F1 block does not align correctly to actual pack block
        send('a210000000FF')
        send('a21100050000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_otp('00000000')               -- Setting OTP to default 00 00 00 00
        write_version('0004030101000b03')   -- UL-EV1 (48) 00 04 03 01 01 00 0b 03
    elseif tagtype == 12 then
        print('Setting: Ultimate Magic card to UL-EV1 128')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000000")
        -- Setting UL-Ev1 default config bl 37,38
    send('a2E5FFFFFFFF') -- A2F0 block does not align correctly to actual pwd block
    send('a2E6FFFFFFFF') -- A2F1 block does not align correctly to actual pack block
        send('a225000000FF')
        send('a22600050000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_otp('00000000')               -- Setting OTP to default 00 00 00 00
        write_version('0004030101000e03')   -- UL-EV1 (128) 00 04 03 01 01 00 0e 03
    elseif tagtype == 15 then
        print('Setting: Ultimate Magic card to NTAG 210')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
        -- Setting NTAG210 default CC block456
        send('a203e1100600')
        send('a2040300fe00')
        send('a20500000000')
        -- Setting  cfg1/cfg2
        send('a210000000FF')
        send('a21100050000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_version('0004040101000b03')   -- NTAG210 00 04 04 01 01 00 0b 03
    elseif tagtype == 16 then
        print('Setting: Ultimate Magic card to NTAG 212')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
        -- Setting NTAG212 default CC block456
        send('a203e1101000')
        send('a2040103900a')
        send('a205340300fe')
        -- Setting  cfg1/cfg2
        send('a225000000FF')
        send('a22600050000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_version('0004040101000E03')   -- NTAG212 00 04 04 01 01 00 0E 03
    elseif tagtype == 17 then
        print('Setting: Ultimate Magic card to NTAG 213')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
        -- Setting NTAG213 default CC block456
        send('a203e1101200')
        send('a2040103a00c')
        send('a205340300fe')
        -- setting cfg1/cfg2
        send('a229000000ff')
        send('a22a00050000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_version('0004040201000F03')       -- NTAG213 00 04 04 02 01 00 0f 03
    elseif tagtype == 18 then
        print('Setting: Ultimate Magic card to NTAG 215')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
        -- Setting NTAG215 default CC block456
        send('a203e1103e00')
        send('a2040300fe00')
        send('a20500000000')
        -- setting cfg1/cfg2
        send('a283000000ff')
        send('a28400050000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_version('0004040201001103')       -- NTAG215 00 04 04 02 01 00 11 03
    elseif tagtype == 19 then
        print('Setting: Ultimate Magic card to NTAG 216')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
        -- Setting NTAG216 default CC block456
        send('a203e1106d00')
        send('a2040300fe00')
        send('a20500000000')
        -- setting cfg1/cfg2
        send('a2e3000000ff')
        send('a2e400050000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_version('0004040201001303')       -- NTAG216 00 04 04 02 01 00 13 03
    elseif tagtype == 20 then
        print('Setting: Ultimate Magic card to NTAG I2C 1K')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
        -- Setting NTAG I2C 1K default CC block456
        send('a203e1106D00')
        send('a2040300fe00')
        send('a20500000000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_version('0004040502011303')       -- NTAG_I2C_1K 00 04 04 05 02 01 13 03
    elseif tagtype == 21 then
        print('Setting: Ultimate Magic card to NTAG I2C 2K')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
        -- Setting NTAG I2C 2K default CC block456
        send('a203e110EA00')
        send('a2040300fe00')
        send('a20500000000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_version('0004040502011503')       -- NTAG_I2C_2K 00 04 04 05 02 01 15 03
    elseif tagtype == 22 then
        print('Setting: Ultimate Magic card to NTAG I2C plus 1K')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
        -- Setting NTAG I2C 1K default CC block456
        send('a203e1106D00')
        send('a2040300fe00')
        send('a20500000000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_version('0004040502021303')       -- NTAG_I2C_1K 00 04 04 05 02 02 13 03
    elseif tagtype == 23 then
        print('Setting: Ultimate Magic card to NTAG I2C plus 2K')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
        -- Setting NTAG I2C 2K default CC block456
        send('a203e1106D00')
        send('a2040300fe00')
        send('a20500000000')
    write_uid('04112233445566')
        write_version('0004040502021503')       -- NTAG_I2C_2K 00 04 04 05 02 02 15 03
    elseif tagtype == 24 then
        print('Setting: Ultimate Magic card to  NTAG 213F')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
        -- Setting NTAG213 default CC block456
        send('a203e1101200')
        send('a2040103a00c')
        send('a205340300fe')
        -- setting cfg1/cfg2
        send('a229000000ff')
        send('a22a00050000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_version('0004040401000F03')       -- NTAG213F 00 04 04 04 01 00 0f 03
    elseif tagtype == 25 then
        print('Setting: Ultimate Magic card to  NTAG 216F')
        connect()
    send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
        -- Setting NTAG216 default CC block456
        send('a203e1106d00')
        send('a2040300fe00')
        send('a20500000000')
        -- setting cfg1/cfg2
        send('a2e3000000ff')
        send('a2e400050000')
    lib14a.disconnect()
    write_uid('04112233445566')
        write_version('0004040401001303')       -- NTAG216F 00 04 04 04 01 00 13 03
    else
    oops('No matching tag types')
    end
    lib14a.disconnect()
    if resp == '04' then
        return nil, 'Failed to set type'
    else
        return true, 'Ok'
    end
end
---
-- returns true if b is the index of a sector trailer
local function mfIsSectorTrailer(b)
    n=b+1
    if (n < 32*4 ) then
        if  (n % 4 ==  0) then return true
        else return false
        end
    end

    if (n % 16 == 0) then return true
    end

    return false
end
---
-- wipe tag
local function wipe(wtype)
    local info = connect()
    if not info then return false, "Can't select card" end
    if wtype == '0' then
        print('Starting Mifare Wipe')
        send("CF".._key.."F000000000000002000978009102DABC19101011121314151604000800")
        send("CF".._key.."CD000102030404080400000000000000BEAF")
        local err, msg, resp
        local cmd_empty = 'CF'.._key..'CD%02X00000000000000000000000000000000'
        local cmd_trail = 'CF'.._key..'CD%02XFFFFFFFFFFFFFF078069FFFFFFFFFFFF'
        for b = 1, 0xFF do
            if mfIsSectorTrailer(b) then
                local cmd = (cmd_trail):format(b)
                resp = send(cmd)
            else
                local cmd = (cmd_empty):format(b)
                resp = send(cmd)
            end
            if resp == nil then
                io.write('\nwrote block '..b, ' failed\n')
                err = true
            else
                io.write('.')
            end
            io.flush()
        end
        print('\n')
        err, msg = set_type(4)
        if err == nil then return err, msg end
        lib14a.disconnect()
        return true, 'Ok'
    elseif wtype == '1' then
        print('Starting Ultralight Wipe')
        local err, msg, resp
        local cmd_empty = 'A2%02X00000000'
        local cmd_cfg1  = 'A2%02X000000FF'
        local cmd_cfg2  = 'A2%02X00050000'
        print('Wiping tag')
        local info = connect()
        if not info then return false, "Can't select card" end
        send("CF".._key.."F001010000000003000978009102DABC19101011121314151644000001")
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
        print('\n')
        if err then return nil, "Tag locked down, "..err_lock end
        -- set NTAG213 default values
        err, msg = set_type(17)
        if err == nil then return err, msg end
        --set UID
        err, msg = write_uid('04112233445566')
        if err == nil then return err, msg end
        --set NTAG pwd
        err, msg = write_ntagpwd('FFFFFFFF')
        if err == nil then return err, msg end
        --set pack
        err, msg = write_pack('0000')
        if err == nil then return err, msg end
        lib14a.disconnect()
        return true, 'Ok'
    else oops('Use 0 for Mifare wipe or 1 for Ultralight wipe')
    end
end
---
-- The main entry point
function main(args)
    print()
    local err, msg
    if #args == 0 then return help() end
    -- Read the parameters
    for o, a in getopt.getopt(args, 'hck:u:t:p:a:s:o:v:q:g:z:n:m:w:') do
        -- help
        if o == "h" then return help() end
        -- set Ultimate Magic Card Key for read write
        if o == "k" then err, msg = set_key(a) end
        -- configuration
        if o == "c" then err, msg = read_config() end
        -- wipe tag
        if o == "w" then err, msg = wipe(a) end
        -- write uid
        if o == "u" then err, msg = write_uid(a) end
        -- write type/version
        if o == "t" then err, msg = set_type(a) end
        -- write NTAG pwd
        if o == "p" then err, msg = write_ntagpwd(a) end
        -- write pack
        if o == "a" then err, msg = write_pack(a) end
        -- write signature
        if o == "s" then err, msg = write_signature(a) end
        -- write otp
        if o == "o" then err, msg = write_otp(a) end
        -- write version
        if o == "v" then err, msg = write_version(a) end
        -- write atqa/sak
        if o == "q" then err, msg = write_atqasak(a) end
        -- write gtu mode
        if o == "g" then err, msg = write_gtu(a) end
        -- write ats
        if o == "z" then err, msg = write_ats(a) end
        -- write UL mode
        if o == "m" then err, msg = write_ulm(a) end
        -- write UL protocol
        if o == "n" then err, msg = write_ulp(a) end
        if err == nil then return oops(msg) end
    end
end
main(args)
