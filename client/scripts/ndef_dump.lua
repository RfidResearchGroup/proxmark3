local getopt = require('getopt')
local cmds = require('commands')
local taglib = require('taglib')
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

--- This function is a lua-implementation of
-- cmdhf14a.c:waitCmd(uint8_t iSelect)
local function waitCmd(iSelect)
    local response = core.WaitForResponseTimeout(cmds.CMD_ACK, 1000)
    if response then
        local count,cmd,arg0,arg1,arg2 = bin.unpack('LLLL',response)

        local iLen = arg0
        if iSelect then iLen = arg1 end
        dbg(("Received %i octets (arg0:%d, arg1:%d)"):format(iLen, arg0, arg1))
        if iLen == 0 then return nil, "No response from tag" end
        local recv = string.sub(response,count, iLen+count-1)
        return recv
    end
    return nil, "No response from device"
end
---
--
local function show(data)
    local formatString = ('H%d'):format(string.len(data))
    local _,hexdata = bin.unpack(formatString, data)
    dbg('Hexdata', hexdata)
end
--- Fire up a connection with a tag, return uid
-- @return UID if successfull
-- @return nil, errormessage if unsuccessfull
local function open()
    dbg('Opening connection')
    core.clearCommandBuffer()
    local x = string.format('hf 14a raw -r -p -s')
    dbg(x)
    core.console(x)
    dbg('done')
    data, err = waitCmd(true)
    if err then return oops(err) end
    show(data)
    local formatString = ('H%d'):format(string.len(data))
    local _,uid = bin.unpack(formatString, data)
    return uid
end
--- Shut down tag communication
-- return no return values
local function close()
    dbg('Closing connection')
    core.clearCommandBuffer()
    local x = string.format('hf 14a raw -r')
    dbg(x)
    core.console(x)
    dbg('done')
end
---_ Gets data from a block
-- @return {block, block+1, block+2, block+3} if successfull
-- @return nil, errormessage if unsuccessfull
local function getBlock(block)
    local data, err

    core.clearCommandBuffer()

    local x = string.format('hf 14a raw -r -c -p 30 %02x', block)
    dbg(x)
    core.console(x)
    dbg('done')
    -- By now, there should be an ACK waiting from the device, since
    -- we used the -r flag (don't read response).

    data, err = waitCmd(false)
    if err then return oops(err) end
    show(data)

    if string.len(data) < 18 then
        return nil, ('Expected at least 18 bytes, got %d - this tag is not NDEF-compliant'):format(string.len(data))
    end
    -- Now, parse out the block data
    -- 0534 00B9 049C AD7F 4A00 0000 E110 1000 2155
    -- b0b0 b0b0 b1b1 b1b1 b2b2 b2b2 b3b3 b3b3 CRCC
    b0 = string.sub(data, 1, 4)
    b1 = string.sub(data, 5, 8)
    b2 = string.sub(data, 9, 12)
    b3 = string.sub(data, 13, 16)
    return {b0, b1, b2, b3}
end

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

    -- Info contained within the tag (block 0 example)
    -- 0534 00B9 049C AD7F 4A00 0000 E110 1000 2155
    -- b0b0 b0b0 b1b1 b1b1 b2b2 b2b2 b3b3 b3b3 CRCC
    -- MM?? ???? ???? ???? ???? ???? NNVV SS?? ----
    -- M = Manufacturer info
    -- N = NDEF-Structure-Compliant (if value is E1)
    -- V = NFC Forum Specification version (if 10 = v1.0)

    -- First, 'connect' (fire up the field) and get the uid
    local uidHexstr = open()

    -- First, get blockt 3 byte 2
    local blocks, err = getBlock(0)
    if err then
        close()
        return oops(err)
    end
    -- Block 3 contains number of blocks
    local b3chars = {string.byte(blocks[4], 1,4)}
    local numBlocks = b3chars[3] * 2 + 6
    print("Number of blocks:", numBlocks)

    -- NDEF compliant?
    if b3chars[1] ~= 0xE1 then
        close()
        return oops('This tag is not NDEF-Compliant')
    end

    local ndefVersion = b3chars[2]

    -- Block 1, byte 1 contains manufacturer info
    local bl1_b1 = string.byte(blocks[1], 1)
    local manufacturer = taglib.lookupManufacturer(bl1_b1)

    -- Reuse existing info
    local blockData = {blocks[1], blocks[2], blocks[3], blocks[4]}

    --[[ Due to the infineon my-d move bug
    (if I send 30 0F i receive block0f+block00+block01+block02 insted of block0f+block10+block11+block12)
    the only way to avoid this is to send the read command as many times as block numbers
    removing bytes from 5 to 18 from each answer.
    --]]
    print('Dumping data...please wait')
    for i=4,numBlocks-1,1 do
        blocks, err = getBlock(i)
        if err then close(); return oops(err) end
        table.insert(blockData, blocks[1])
    end
    -- Deactivate field
    close()
    -- Print results
    print(string.format('Tag manufacturer: %s', manufacturer))
    print(string.format('Tag UID: %s', uidHexstr))
    print(string.format('Tag NDEF version: 0x%02x', ndefVersion))

    for k,v in ipairs(blockData) do
        print(string.format('Block %02x: %02x %02x %02x %02x', k-1, string.byte(v, 1,4)))
    end
    local filename, err = utils.writeDumpFile(uidHexstr, blockData)
    if err then return oops(err) end

    print(string.format('Dumped data into %s', filename))

end
main(args)
