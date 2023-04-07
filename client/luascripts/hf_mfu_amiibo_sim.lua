local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local utils = require('utils')
local ansicolors = require('ansicolors')
local amiibo_tools = require('amiibo_tools')

copyright = ''
author = 'George Talusan'
version = 'v0.0.2'
desc = [[
This script will try to load a binary datadump of an Amiibo.
It will recalculate PWD and PACK if necessary.
]]
example = [[
    1. script run hf_mfu_amiibo_sim
    2. script run hf_mfu_amiibo_sim -f myfile
]]
usage = [[
script run hf_mfu_amiibo_sim [-h] [-f <filename>]
]]
arguments = [[
    -h             : this help
    -f             : filename for the datadump to read (bin)
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

local function LoadEmulator(uid, blocks)
    io.write('Sending Amiibo to emulator memory')
    local cmd, blockdata
    for i=0,148,1 do
        blockdata = blocks[i]
        io.write('.')
        io.flush()
        core.clearCommandBuffer()
        cmd = Command:newNG{cmd = cmds.CMD_HF_MIFARE_EML_MEMSET, data = ('%02x%02x%02x%s'):format(i, 1, 4, blockdata)}
        local err, msg = cmd:sendNG(true)
        if err == nil then return err, msg end
    end
    io.write('\n')
end

local function main(args)
    print( string.rep('--',20) )
    print( string.rep('--',20) )

    local result, err, hex
    local inputTemplate = 'dumpdata.bin'

    for o, a in getopt.getopt(args, 'hf:u:') do
        if o == 'h' then return help() end
        if o == 'f' then inputTemplate = a end
    end

    print(('Loading data from %s'):format(inputTemplate))
    hex, err = utils.ReadDumpFile(inputTemplate)
    if not hex then return oops(err) end

    -- only deal with missing PWD and PACK, or with 56 emu hdr
    if #hex ~= 1064 and #hex ~= 1080 and #hex ~= 1192 then return oops('Expecting either a plain binary or emulator dump') end

    local amiibo_offset = (#hex == 1064 or #hex == 1080) and 0 or 112
    local amiibo_info = hex:sub(amiibo_offset + 169, amiibo_offset + 169 + 15):lower()
    local amiibo_game = amiibo_info:sub(1, 3)
    local amiibo_type = amiibo_info:sub(7, 8)
    local amiibo_series = amiibo_info:sub(13, 14)

    dbg('raw: '..ansicolors.green..amiibo_info..ansicolors.reset)
    print('game: '..ansicolors.green..amiibo_tools.db.game_series[("0x%s"):format(amiibo_game)]..ansicolors.reset)
    print('character: '..ansicolors.green..amiibo_tools.db.amiibos[("0x%s"):format(amiibo_info)].name..ansicolors.reset)
    print('type: '..ansicolors.green..amiibo_tools.db.types[("0x%s"):format(amiibo_type)]..ansicolors.reset)
    print('series: '..ansicolors.green..amiibo_tools.db.amiibo_series[("0x%s"):format(amiibo_series)]..ansicolors.reset)

    local blocks = {}
    local blockindex = 0

    -- add empty header if necessary
    if (#hex == 1064 or #hex == 1080) then
        for i = 0, 13, 1 do
            blocks[i] = '00000000'
        end
        blocks[2] = '00000086'
        blockindex = 14
    end
    for i = 1, #hex, 8 do
        blocks[blockindex] = hex:sub(i, i+7)
        blockindex = blockindex + 1
    end

    -- force lock bytes, otherwise the Amiibo won't be recognized
    blocks[16] = blocks[16]:sub(1, 4)..'0FE0'

    -- add PWD and PACK
    local uid = blocks[14]:sub(1, 6)..blocks[15]:sub(1, 8)
    blocks[147] = ("%08x"):format(bxor(bxor(tonumber(sub(uid, 2, 10), 16), tonumber(sub(uid, 6, 14), 16)), 0xaa55aa55))
    blocks[148] = "80800000"

    err = LoadEmulator(uid, blocks)
    if err then return oops(err) end
    core.clearCommandBuffer()
    core.console(("hf mfu sim -t 7 -u %s"):format(uid))
end
main(args)
