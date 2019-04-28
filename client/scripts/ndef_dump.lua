local getopt = require('getopt')
local cmds = require('commands')
local lib14a = require('read14a')
local utils = require('utils')

copyright = ''
author = 'Martin Holst Swende & Asper'
version = 'v1.0.1'
desc = [[
This script will automatically recognize and dump full content of a NFC NDEF Initialized tag; non-initialized tags will be ignored.

It also write the dump to an eml-file <uid>.eml.

(The difference between an .eml-file and a .bin-file is that the eml file contains
ASCII representation of the hex-data, with linebreaks between 'rows'. A .bin-file contains the
raw data, but when saving into that for, we lose the infromation about how the memory is structured.
For example: 24 bytes could be 6 blocks of 4 bytes, or vice versa.
Therefore, the .eml is better to use file when saving dumps.)

]]
example = [[
    1. script run ndef_dump
]]
usage = [[
script run ndef_dump

Arguments:
    -h              this help
    -d              debug logging on

]]

local DEBUG = true -- the debug flag

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
    print('Example usage')
    print(example)
    print(usage)
end
--
-- Sends an instruction to do nothing, only disconnect
function disconnect()
    local command = Command:newMIX{cmd = cmds.CMD_READER_ISO_14443a, arg1 = 0,}
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
    
    local count, cmd, arg0 = bin.unpack('LL', response)
    if arg0 == 1 then
        local count, arg1, arg2, data = bin.unpack('LLH511', response, count)
        return data:sub(1, 32)
    else
        return nil, "Couldn't read block"
    end
end
---_ Gets data from a block
-- @return {block, block+1, block+2, block+3} if successfull
-- @return nil, errormessage if unsuccessfull
local function getBlock(blockno)
    local block, err
    local cmd = Command:newMIX{cmd = cmds.CMD_MIFAREU_READBL, arg1 = blockno, data = 0}
    block, err = getblockdata(cmd:sendMIX(false))
    if not block then return oops(err) end
    
    if #block < 32 then
        return nil, ('Expected at least 16 bytes, got %d - this tag is not NDEF-compliant'):format(string.len(data))
    end
    print('block', block)
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
    
    dbg('script started')
    local err, data, data2, k, v, i
    -- Read the parameters
    for o, a in getopt.getopt(args, 'hd') do
        if o == 'h' then return help() end
        if o == 'd' then DEBUG = true end
    end

    -- First of all, connect
    info, err = lib14a.read(true, true)
    if err then 
        disconnect();
        return oops(err)
    end
    core.clearCommandBuffer()

    if info.name:match("Ultralight") then
        dbg('Found a tag')
    else
        disconnect()
        return oops('Not a Ultralightbased card. This script reads NDEF formatted UL/NTAGS')
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
    local b3chars = utils.ConvertHexToBytes(blocks[4]);
    local numBlocks = b3chars[3] * 2 + 6
    print("Number of blocks:", numBlocks)

    -- NDEF compliant?
    if b3chars[1] ~= 0xE1 then
        disconnect()
        return oops('This tag is not NDEF-Compliant')
    end

    local ndefversion = b3chars[2]

    -- Reuse existing info
    local blockData = {blocks[1], blocks[2], blocks[3], blocks[4]}

    --[[ Due to the infineon my-d move bug
    (if I send 30 0F i receive block0f+block00+block01+block02 insted of block0f+block10+block11+block12)
    the only way to avoid this is to send the read command as many times as block numbers
    removing bytes from 5 to 18 from each answer.
    --]]
    print('Dumping data...please wait')
    for i = 4, numBlocks - 1, 1 do
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
    print('Tag info')    
    print('UID         ', info.uid)
    print('NDEF version', ('%02x'):format(ndefversion))
    print('Manufacturer', info.manufacturer)
    print('Type        ', info.name)

    for k,v in ipairs(blockData) do
        print(string.format('Block %02x: %02x %02x %02x %02x', k-1, string.byte(v, 1,4)))
    end
    
    local filename, err = utils.WriteDumpFile(info.uid, blockData)
    if err then return oops(err) end

    print(string.format('Dumped data into %s', filename))

end
main(args)
