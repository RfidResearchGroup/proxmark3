local getopt = require('getopt')
local cmds = require('commands')
local lib14a = require('read14a')
local utils = require('utils')
local ansicolors = require('ansicolors')
--
-- Refactored iceman, 2019
copyright = ''
author = 'Martin Holst Swende & Asper'
version = 'v1.0.2'
desc = [[
This script will automatically recognize and dump full content of a NFC NDEF Initialized tag; non-initialized tags will be ignored.

It also write the dump to an eml-file <uid>.eml.

(The difference between an .eml-file and a .bin-file is that the eml file contains
ASCII representation of the hex-data, with linebreaks between 'rows'. A .bin-file contains the
raw data, but when saving into that for, we lose the information about how the memory is structured.
For example: 24 bytes could be 6 blocks of 4 bytes, or vice versa.
Therefore, the .eml is better to use file when saving dumps.)

]]
example = [[
    1. script run hf_ndef_dump
]]
usage = [[
script run hf_ndef_dump [-h] [-d] [-v]
]]
arguments = [[
    -h              this help
    -d              debug logging on
    -v              verbose output (from ndef parsing)

]]

local DEBUG = true -- the debug flag
local band = bit32.band
local rshift = bit32.rshift
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
-- Sends an instruction to do nothing, only disconnect
function disconnect()
    local command = Command:newMIX{cmd = cmds.CMD_HF_ISO14443A_READER, arg1 = 0,}
    -- We can ignore the response here, no ACK is returned for this command
    -- Check /armsrc/iso14443a.c, ReaderIso14443a() for details
    return command:sendMIX(true)
end
---
--
local function getblockdata(response)
    if not response then
        return nil, 'No response from device'
    end

    local count, cmd, arg0, arg1, arg2, data = bin.unpack('LLLLH40', response)
    if arg0 == 1 then
        return data:sub(1, 32)
    end

    return nil, "Couldn't read block"
end
---_ Gets data from a block
-- @return {block, block+1, block+2, block+3} if successful
-- @return nil, errormessage if unsuccessful
local function getBlock(blockno)
    local block, err
    local c = Command:newMIX{cmd = cmds.CMD_HF_MIFAREU_READBL, arg1 = blockno, data = 0}
    block, err = getblockdata(c:sendMIX(false))
    if not block then return oops(err) end

    if #block < 32 then
        return nil, ('Expected at least 16 bytes, got %d - this tag is not NDEF-compliant'):format(string.len(data))
    end
    -- Now, parse out the block data
    -- 0534 00B9 049C AD7F 4A00 0000 E110 1000 2155
    -- b0b0 b0b0 b1b1 b1b1 b2b2 b2b2 b3b3 b3b3 CRCC
    b0 = string.sub(block, 1, 8)
    b1 = string.sub(block, 9, 16)
    b2 = string.sub(block, 17, 24)
    b3 = string.sub(block, 25, 32)
    return {b0, b1, b2, b3}
end
---
--
local function main( args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )

    local err, data, data2, k, v, i
    local verbose = 0
    -- Read the parameters
    for o, a in getopt.getopt(args, 'hdv') do
        if o == 'h' then return help() end
        if o == 'd' then DEBUG = true end
        if o == 'v' then verbose = 1 end
    end

    -- First of all, connect
    info, err = lib14a.read(true, true)
    if err then
        disconnect();
        return oops(err)
    end
    core.clearCommandBuffer()

    if info.name:match("Ultralight") then
        print('[=] Found a tag')
    else
        disconnect()
        return oops('[!] Not a Ultralightbased card. This script reads NDEF formatted UL/NTAGS')
    end

    -- Info contained within the tag (block 0 example)
    -- 0534 00B9 049C AD7F 4A00 0000 E110 1000 2155
    -- b0b0 b0b0 b1b1 b1b1 b2b2 b2b2 b3b3 b3b3 CRCC
    -- MM?? ???? ???? ???? ???? ???? NNVV SS?? ----
    -- M = Manufacturer info
    -- N = NDEF-Structure-Compliant (if value is E1)
    -- V = NFC Forum Specification version (if 10 = v1.0)

    -- First, get blockt 3 byte 2
    local blocks, err = getBlock(0)
    if err then
        disconnect()
        return oops(err)
    end
    -- Block 3 contains number of blocks
    local b3 = utils.ConvertHexToBytes(blocks[4]);
    local t5tarea = b3[3] * 8
    local t5tarea_blocks = t5tarea / 4;

    -- NDEF compliant?
    if b3[1] ~= 0xE1 then
        disconnect()
        return oops('[!] This tag is not NDEF-Compliant')
    end

    -- Reuse existing info
    local blockData = {blocks[1], blocks[2], blocks[3], blocks[4]}

    --[[ Due to the infineon my-d move bug
    (if I send 30 0F i receive block0f+block00+block01+block02 insted of block0f+block10+block11+block12)
    the only way to avoid this is to send the read command as many times as block numbers
    removing bytes from 5 to 18 from each answer.
    --]]
    print('[=] Dumping data...')
    for i = 4, t5tarea_blocks - 1, 1 do
        blocks, err = getBlock(i)
        if err then
            disconnect();
            return oops(err)
        end
        table.insert(blockData, blocks[1])
    end
    -- Deactivate field
    disconnect()
    -- Print results
    print('[=] --- Tag NDEF Message info')
    print('[=] '.. string.rep('--', 50) )
    print('[=]          Type : ', info.name)
    print('[=]           UID : ', info.uid)
    print('[=]  Manufacturer : ', info.manufacturer)
    print('[=]  Capacity Container : '.. blockData[4])
    print(('[=]     %02X : NDEF Magic Number'):format(b3[1]) )

    local vLow = band(b3[2], 0xF)
    local vHi = band(rshift(b3[2], 4), 0xF)
    print(('[=]     %02X : version %d.%d supported by tag'):format(b3[2], vHi, vLow) )

    print(('[=]     %02X : Physical Memory Size: %d bytes'):format(b3[3], t5tarea) )
    if b3[3] == 0x96 then
       print(('  %02X : NDEF Memory Size: %d bytes'):format(b3[3], 48))
    elseif b3[3] == 0x12 then
       print(('  %02X : NDEF Memory Size: %d bytes'):format(b3[3], 144))
    elseif b3[3] == 0x3E then
       print(('  %02X : NDEF Memory Size: %d bytes'):format(b3[3], 496))
    elseif b3[3] == 0x6D then
       print(('  %02X : NDEF Memory Size: %d bytes'):format(b3[3], 872))
    end

    local rLow = band(b3[4], 0xF)
    local rHi = band(rshift(b3[4], 4), 0xF)
    local wstr, rstr

    if rLow == 0 then
       wstr = 'Write access granted without any security'
    elseif rLow == 0x0F then
       wstr = 'No write access granted at all'
    else
       wstr = '(RFU)'
    end

    if rHi ~= 0x00 then
       rstr = '(RFU)'
    else
       rstr = 'Read access granted without any security'
    end

    print( ('[=]     %02X : %s / %s'):format(b3[4], rstr, wstr))

    print('[=] '.. string.rep('--', 50) )
    local ndefdata = table.concat(blockData, '', 5)
    core.ndefparse(t5tarea, verbose, ndefdata)
    print('[=] '.. string.rep('--', 50) )

    print('')
    print('[=] Tag dump')
    print('|---|-------------------|')
    for k,v in ipairs(blockData) do

--        print(string.format('Block %02x: %02x %02x %02x %02x', k-1, string.byte(v, 1,4)))
        print(string.format(' %02x | %s', k-1, v) )
    end
    print('|---|-------------------|')

    local filename, err = utils.WriteDumpFile(info.uid, blockData)
    if err then return oops(err) end

    print(string.format('[+] Dumped data into %s', filename))

end
main(args)
