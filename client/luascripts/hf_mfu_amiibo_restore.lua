local cmds = require('commands')
local getopt = require('getopt')
local os = require('os')
local io = require('io')
local bin = require('bin')
local utils = require('utils')
local ansicolors = require('ansicolors')
local amiibo_tools = require('amiibo_tools')

copyright = ''
author = 'George Talusan'
version = 'v0.0.1'
desc = [[
This script will try to restore a binary datadump of an Amiibo to a blank NTAG215.
It will recalculate PWD and PACK if necessary, set the appropriate password and sector lock bytes.

NOTE: PyAmiibo must be installed.  The helper script pyscripts/amiibo_change_uid.py depends on PyAmiibo.

YMMV if a non-blank NTAG215 is provided!
]]
example = [[
    1. script run hf_mfu_amiibo_restore
    2. script run hf_mfu_amiibo_restore -f myfile -k password
]]
usage = [[
script run hf_mfu_amiibo_restore [-h] [-f <filename> -k <password>]
]]
arguments = [[
    -h             : this help
    -f             : filename for the datadump to read (bin)
    -k             : password of blank NTAG 215 (use `hf mfu info` to find it)
]]

local DEBUG = false -- the debug flag

local bxor = bit32.bxor
local sub = string.sub
local format = string.format

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

local function main(args)
    print( string.rep('--',20) )
    print( string.rep('--',20) )

    local result, err, hex
    local inputTemplate = 'dumpdata.bin'
    local password

    for o, a in getopt.getopt(args, 'hf:k:') do
        if o == 'h' then return help() end
        if o == 'f' then inputTemplate = a end
        if o == 'k' then password = a end
    end

    print(('Loading data from %s'):format(inputTemplate))
    hex, err = utils.ReadDumpFile(inputTemplate)
    if not hex then return oops(err) end

    if not password or #password ~= 8 then
        return oops('Expecting 4 byte password (hint: use `hf mfu info` to get it)')
    end

    -- chomp emu header
    if #hex == 1192 then
        hex = hex:sub(113)
    end

    local amiibo_offset = 0
    local amiibo_info = hex:sub(amiibo_offset + 169, amiibo_offset + 169 + 15):lower()
    local amiibo_game = amiibo_info:sub(1, 3)
    local amiibo_type = amiibo_info:sub(7, 8)
    local amiibo_series = amiibo_info:sub(13, 14)

    dbg('raw: '..ansicolors.green..amiibo_info..ansicolors.reset)
    print('game: '..ansicolors.green..amiibo_tools.db.game_series[("0x%s"):format(amiibo_game)]..ansicolors.reset)
    print('character: '..ansicolors.green..amiibo_tools.db.amiibos[("0x%s"):format(amiibo_info)].name..ansicolors.reset)
    print('type: '..ansicolors.green..amiibo_tools.db.types[("0x%s"):format(amiibo_type)]..ansicolors.reset)
    print('series: '..ansicolors.green..amiibo_tools.db.amiibo_series[("0x%s"):format(amiibo_series)]..ansicolors.reset)

    local uid = core.ul_read_uid();
    if uid == nil then
        return oops("Can't read UID of NTAG215 card.  Reposition card and try again.")
    end

    local tmp = ('%s.bin'):format(os.tmpname())
    local amiibo_file = io.open(tmp, 'w+b')
    amiibo_file:write(bin.pack('H', hex))
    amiibo_file:close()
    local tmp2 = ('%s.bin'):format(os.tmpname())

    print('generating new Amiibo binary for NTAG215 '..ansicolors.green..uid)
    core.clearCommandBuffer()
    core.console(('script run amiibo_change_uid %s %s %s %s'):format(uid, tmp, tmp2, core.search_file('resources/key_retail', '.bin')))

    -- let's sanity check the output
    hex, err = utils.ReadDumpFile(tmp2)
    if not hex or #hex ~= 1080 then
        os.remove(tmp)
        os.remove(tmp2)
        return oops('There was a problem generating the output Amiibo')
    end

    core.console(('hf mfu restore -f %s -k %s'):format(tmp2, password))

    -- re-write some blocks because `hf mfu restore` won't write out blocks 0-3, and PyAmiibo won't give a PACK/PWD
    local pwd, pack = core.keygen_algo_b(uid)
    core.console(('hf mfu wrbl -b 3 -d F110FFEE -k %s'):format(password)) -- CC?
    core.console(('hf mfu wrbl -b 134 -d %04X0000 -k %s'):format(pack, password)) -- PACK/RFUI
    core.console(('hf mfu wrbl -b 133 -d %08X -k %s'):format(pwd, password)) -- PWD
    core.console(('hf mfu wrbl -b 131 -d 00000004 -k %08X'):format(pwd)) -- CFG0
    core.console(('hf mfu wrbl -b 132 -d 5F000000 -k %08X'):format(pwd)) -- CFG1

    local lock_bytes = hex:sub(17, 24)
    dbg('lock_bytes: '..lock_bytes)
    core.console(('hf mfu wrbl -b 2 -d %s -k %08X'):format(lock_bytes, pwd)) -- BCC1/static lock
    core.console(('hf mfu wrbl -b 130 -d 01000FBD -k %08X'):format(pwd)) -- dynamic lock/RFUI

    os.remove(tmp)
    os.remove(tmp2)
end
main(args)
