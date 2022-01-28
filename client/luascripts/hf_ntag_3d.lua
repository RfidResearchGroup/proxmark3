local getopt = require('getopt')
local lib14a = require('read14a')
local utils = require('utils')
local ansicolors = require('ansicolors')

copyright = 'Copyright (c) 2017 IceSQL AB. All rights reserved.'
author = "Christian Herrmann"
version = 'v1.0.6'
desc = [[
This script writes a empty template for 3D printing system onto a empty NTAG213 or MAGIC NTAG21*

Thanks to @jack for his invaluable input on some of the configuration.
]]
example =[[
     -- This will generate GOLD, PLA, TH, EU, 200m,  tagbased uid.
     script run hf_ntag-3d -c 46 -m 50 -p 5448 -s 4555  -l 200

     -- This will generate GOLD, PLA, TH, EU, 200m,  userbased uid.
     script run hf_ntag-3d -u 11223344556677 -c 46 -m 50 -p 5448 -s 4555  -l 200

     -- This will generate GOLD, PLA, TH, EU, 200m,  userbased uid. and configure a MAGIC NTAG.
     script run hf_ntag-3d -u 11223344556677 -c 46 -m 50 -p 5448 -s 4555  -l 200 -1
]]
usage = [[
script run hf_ntag-3d [-h] [-t] [-u <uid>] [-c <color>] [-m <material>] [-p <region>] [-s <region>] [-l <length>]
]]
arguments = [[
    -h             : this help
    -t             : selftest
    -u <UID>       : UID
    -c <COLOR>     : color of filament
    -m <MATERIAL>  : material of filament
    -p <REGION>    : Manufacturer region
    -s <REGION>    : Sales region
    -l <LENGTH>    : Spool length.  Use only 100,200,300.   300 has problems on OSX
]]

local DEBUG = true
local TIMEOUT = 10000 -- 10 seconds
local bxor = bit32.bxor
local band = bit32.band
local rshift = bit32.rshift

local _regions = {
    {'4742', 'GB'},
    {'5457', 'TW'},
    {'4555', 'EU'},
    {'5553', 'US'},
    {'454E', 'EN'},
    {'4A50', 'JP'},
    {'434E', 'CN'},
    {'5448', 'TH'},
    {'4153', 'AS'},
    {'5246', 'RF'},
    {'4746', 'GF'},
    {'4341', 'CA'},
    {'504D', 'PM'},
    {'5044', 'PD'},
}
local _manufacturers = {
    {'5457', 'TW'},
    {'434E', 'CN'},
    {'5448', 'TH'},
}
local _sales = {
    {'4742', 'GB'},
    {'4555', 'EU'},
    {'5553', 'US'},
    {'454E', 'EN'},
    {'504D', 'PM'},
}
local _materials = {
    {'20', 'Other material'},
    {'41', 'ABS'},
    {'46', 'Flexible TPE Tree'},
    {'46', 'TPE'},
    {'46', 'PVA'},
    {'47', 'PETG'},
    {'50', 'PLA'},
    {'51', 'PLA'},
    {'54', 'Tough PLA'},
    {'55', 'UVCR'},
    {'56', 'Water Soluble PVA'},
}
local _colors = {
    {'30', 'Bronze'},
    {'31', 'Silver'},
    {'32', 'Clear Red'},
    {'33', 'Clear'},
    {'34', 'Bottle Green'},
    {'35', 'Neon Magenta'},
    {'36', 'SteelBlue'},
    {'37', 'Sun Orange'},
    {'38', 'Pearl White'},
    {'39', 'Copper'},
    {'41', 'Purple'},
    {'42', 'Blue'},
    {'43', 'Neon Tangerine'},
    {'44', 'Viridity'},
    {'45', 'Olivine'},
    {'46', 'Gold'},
    {'47', 'Green'},
    {'48', 'Neon Green'},
    {'49', 'Snow White'},
    {'4A', 'Neon Yellow'},
    {'4B', 'Black'},
    {'4C', 'Violet'},
    {'4D', 'Grape Purple'},
    {'4E', 'Purpurine'},
    {'4F', 'Clear Yellow'},
    {'50', 'Clear Green'},
    {'51', 'Clear Tangerine'},
    {'52', 'Red'},
    {'53', 'Cyber Yellow'},
    {'54', 'Tangerine'},
    {'55', 'Clear Blue'},
    {'56', 'Clear Purple'},
    {'57', 'White'},
    {'58', 'Clear Magenta'},
    {'59', 'Yellow'},
    {'5A', 'Nature'},
}
---
--
local function find( arr, name )
    if not name then return nil end
    name = name:lower()
    for k, v in pairs(arr) do
        if ( v[2]:lower() == name or v[1]:lower() == name ) then
            return v
        end
    end
    return nil
end
---
--
local function list( arr, desc )
    print ('Value\t'..desc)
    print (string.rep('=', 20))
    for k, v in pairs(arr) do
        print(("%s\t%s"):format(v[1],v[2]))
    end
end
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
---
-- This is only meant to be used when errors occur
local function oops(err)
    print('ERROR:', err)
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
--
-- Exit message
local function ExitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end
---
--
local function write_tag(uid, t)

    print('Writing to tag')
    core.console('hw dbg -0')
    utils.Sleep(0.5)

    local cmd = ''
    local pwd, pack = core.keygen_algo_d(uid)

    for i= 8, 23 do
        cmd = ('hf mfu wrbl --blk %02d -d %s -k %08X'):format(i, t[i], pwd)
        core.console(cmd)
    end

    --cfg1
    core.console(('hf mfu wrbl --blk 42 -d %s -k %08X'):format(t[42], pwd))
    --cfg0
    core.console(('hf mfu wrbl --blk 41 -d %s -k %08X'):format(t[41], pwd))
    --dynamic
    core.console(('hf mfu wrbl --blk 40 -d %s -k %08X'):format(t[40], pwd))

    core.console('hw dbg -1')
    utils.Sleep(0.5)
    print('Done')
end
---
-- configures a magic NTAG for NTAG213, with UID and PWD,PACK.
local function configure_magic_ntag(uid)

    print('Configuring MAGIC NTAG')
    -- Save the global args, those are *our* arguments
    local myargs = args

    local pwd, pack = core.keygen_algo_d(uid)

    -- Set the arguments for hf_mfu_magicwrite script v1.0.8
    -- -t 12   == configure NTAG213F
    -- -u    == set UID
    -- -p    == set pwd
    -- -a    == set pack
    args =('-t 12 -u %s -p %08X -a %04X'):format(uid, pwd, pack)
    require('hf_mfu_magicwrite')

    -- Set back args. Not that it's used, just for the karma...
    args = myargs

    print('Done')
end
---
-- generates random hex numbers between 31-39
local function random_num_hex(length)
    local str = ''
    local i
    for i = 1, length, 1 do
        str = str..math.random(31, 39)
    end
    return str
end
---
--
local function nwo( val )
    local b1 = band(val, 0xFF)
    local b2 = band( rshift(val,  8), 0xFF)
    local b3 = band( rshift(val, 16), 0xFF)
    local b4 = band( rshift(val, 24), 0xFF)
    return ('%02X%02X%02X%02X'):format(b1, b2, b3, b4)
end
---
-- NTAG213 template
local function template_NTAG213(uid, material, color, length, manufacture, sales)
    local pwd, pack = core.keygen_algo_d(uid)

    local m = tonumber(length, 10) * 1000
    local m_str = nwo(m)

    local t = {}
    -- default empty file
    for i = 0,42 do
        t[i] = '00000000'
    end
--  t[4]  = '0103A00C' --
--  t[5]  = '340300FE' --
-- 6,7
    t[8]  = '5A'..material..color..'00'  -- 5A, material, color, 00
    t[9]  = '00'..random_num_hex(3)  -- 00, three bytes serial number
    t[10] = m_str  -- total capacity
    t[11] = m_str  -- total capacity
    t[12] = 'D2002D00'  -- fixed
    t[13] = manufacture..sales  -- regioner,
    t[14] = random_num_hex(4)  -- serial number
-- 15,16
    t[17] = '34000000' -- fixed
-- 18,19
    -- remaining capacity of spool
    t[20] = m_str
    t[21] = nwo( bxor(  m, 0x54321248))
    t[22] = nwo( bxor( (m - 3876923 ), 0x31275455))
    t[23] = nwo( bxor( (m + 6923923 ), 0x76235481))
-- 24-39
    t[40] = '000000BD' --dynamic
    t[41] = '07000008' --cfg0
    t[42] = '80050000' --cfg1
    t[43] = ('%08X'):format(pwd)
    t[44] = ('%04X0000'):format(pack)
    return t
end
---
-- outputs the called arguments
local function print_conf(uid, material, color, length, producer, sales )
    print('Create tag as following')
    print( string.rep('--',16) )
    print('UID           ', uid)
    print('Material      ', material[2])
    print('Color         ', color[2])
    print('Spool length  ', length)
    print('Region')
    print('  manufacturer', producer[2])
    print('  sales       ', sales[2])
    print( string.rep('--',16) )
end
---
-- self test
local function selftest()
    list(_regions, 'Regions')
    list(_materials, 'Materials')
    list(_colors, 'Colors')
    return nil
end
---
-- The main entry point
local function main(args)

    math.randomseed(os.time());
    math.random();

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    local uid = '04C5DF4A6D5180'
    local useUID = false
    local useMAGIC = false
    local material, color, length, producer, sales

    if #args == 0 then return help() end

    -- Read the parameters
    for o, a in getopt.getopt(args, 'ht1u:l:m:c:p:s:') do
        if o == 'h' then return help() end
        if o == 't' then return selftest() end
        if o == 'u' then uid = a; useUID = true end
        if o == 'm' then material = a end
        if o == 'c' then color = a end
        if o == 'l' then length = tonumber(a) end
        if o == 'p' then producer = a end
        if o == 's' then sales = a end
        if o == '1' then useMAGIC = true end
    end

    color = find(_colors, color)
    if not color then list(_colors, 'Colors'); return oops('\n\nNot valid color') end

    material = find(_materials, material)
    if not material then list(_materials, 'Materials'); return oops('\n\nNot valid material') end

    producer = find(_manufacturers, producer)
    if not producer then list(_manufacturers, 'Regions Manufacturers'); return oops('\n\nNo valid manufacturer region') end

    sales = find(_sales, sales)
    if not sales then list(_sales, 'Regions Sales'); return oops('\n\nNo valid sales region') end

    if length > 300 then
        return oops('\n\nNot valid spool length. Must be lesser than 300')
    end

    if useUID then
        -- uid string checks
        if uid == nil then return oops('empty uid string') end
        if #uid == 0 then return oops('empty uid string') end
        if #uid ~= 14 then return oops('uid wrong length. Should be 7 hex bytes') end
    else
        -- GET TAG UID
        local tag, err = lib14a.read(false, true)
        if not tag then return oops(err) end
        core.clearCommandBuffer()
        uid = tag.uid
    end

    --print
    print_conf(uid, material, color, length, producer, sales )

    -- create template
    local t = template_NTAG213(uid, material[1], color[1], length, producer[1], sales[1])

    -- using MAGIC NTAG
    if useMAGIC then
        configure_magic_ntag(uid)
    end

    -- write template data to tag
    write_tag(uid, t)
end

main(args)
