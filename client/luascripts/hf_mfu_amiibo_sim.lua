local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local utils = require('utils')
local ansicolors = require('ansicolors')
local amiibo_tools = require('amiibo_tools')

copyright = ''
author = 'George Talusan, modified by Lee Hambley'
version = 'v0.0.3'
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

local bxor = bit32.bxor
local sub = string.sub

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

local function BlocksToBinary(blocks, last)
    local out = {}
    for i = 0, last, 1 do
        local blk = blocks[i]
        if not blk or #blk ~= 8 then
            return nil, ('Invalid block %d (%s)'):format(i, tostring(blk))
        end
        for j = 1, 8, 2 do
            out[#out+1] = string.char(tonumber(blk:sub(j, j + 1), 16))
        end
    end
    return table.concat(out)
end

local function LoadViaEload(blocks)
    io.write('Sending Amiibo to emulator memory')
    local blob, err = BlocksToBinary(blocks, 148)
    if not blob then return false, err end

    -- Create temp file for eload command
    -- Note: No direct MFU memory set command available (CMD_HF_MIFARE_EML_MEMSET only for MIFARE)
    local tmp = '/tmp/amiibo_emul.bin'
    local fh, ferr = io.open(tmp, 'wb')
    if not fh then return false, ferr end
    fh:write(blob)
    fh:close()

    core.clearCommandBuffer()
    local ok, msg = core.console(('hf mfu eload -f %s'):format(tmp))
    
    -- Clean up temp file
    os.remove(tmp)
    
    if ok == false then
        return false, msg or 'eload command failed'
    end
    io.write('\n')
    return true
end

local function main(args)
    print( string.rep('--',20) )
    print( string.rep('--',20) )

    local err, hex
    local inputTemplate = 'dumpdata.bin'

    for o, a in getopt.getopt(args, 'hf:') do
        if o == 'h' then return help() end
        if o == 'f' then inputTemplate = a end
    end

    print(('Loading data from %s'):format(inputTemplate))
    hex, err = utils.ReadDumpFile(inputTemplate)
    if not hex then return oops(err) end

    if #hex ~= 1064 and #hex ~= 1080 and #hex ~= 1192 then return oops('Expecting either a plain binary or emulator dump') end

    local amiibo_offset = (#hex == 1064 or #hex == 1080) and 0 or 112
    local amiibo_info = hex:sub(amiibo_offset + 169, amiibo_offset + 169 + 15):lower()
    local amiibo_game = amiibo_info:sub(1, 3)
    local amiibo_type = amiibo_info:sub(7, 8)
    local amiibo_series = amiibo_info:sub(13, 14)

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
    local pwd = ("%08x"):format(bxor(bxor(tonumber(sub(uid, 2, 10), 16), tonumber(sub(uid, 6, 14), 16)), 0xaa55aa55))
    blocks[147] = pwd
    blocks[148] = "80800000"

    local ok, loadErr = LoadViaEload(blocks)
    if not ok then return oops(loadErr) end
    core.clearCommandBuffer()
    core.console(("hf mfu sim -t 7 -u %s"):format(uid))
end
main(args)
