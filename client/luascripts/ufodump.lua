local cmds = require('commands')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils = require('utils')

copyright = ''
author = 'Iceman'
version = 'v1.0.1'
desc = [[
This is a script that reads AZTEK ISO14443a tags.
It starts from block 0 and ends at default block 20.  Use 'b' to say different endblock.
xor:  the first three block (0,1,2) is not XORED.  The rest seems to be xored.
]]
example = [[
    -- default
    script run ufodump

    -- stop at block 10
    script run ufodump -b 10
]]
usage = [[
script run ufudump -h -b

Arguments:
      h   this helptext
      b   endblock in decimal (1-255,  default 20)
]]

-- Some globals
local DEBUG = false -- the debug flag
---
-- A debug printout-function
local function dbg(args)
    if not DEBUG then return end
    if type(args) == 'table' then
        local i = 1
        while args[i] do
            dbg(args[i])
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
--- Picks out and displays the data read from a tag
-- Specifically, takes a usb packet, converts to a Command
-- (as in commands.lua), takes the data-array and
-- reads the number of bytes specified in arg1 (arg0 in c-struct)
-- and displays the data
-- @blockno just to print which block the data belong to
-- @param usbpacket the data received from the device
function showdata(blockno, data)
    local xorkey = '55AA55AA55AA55AA6262'
    local s = data.." | "
    local dex = ''
    local rs
    for i = 1, 20-4, 4 do
        local item = string.sub(data, i, i+3)
        local xor = string.sub(xorkey, i, i+3)

        if blockno > 2 then
            rs = bit32.bxor(tonumber(item,16) , tonumber(xor,16))
        else
            rs = tonumber(item, 16)
        end
        dex = (dex..'%04X'):format(rs)
    end
    s = s..dex.." | "
    print( (" %02d | %s"):format(blockno,s))
end
--
-- Send a "raw" iso14443a package, ie "hf 14a raw" command
function sendRaw(rawdata, options)

    local flags = lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT
                + lib14a.ISO14A_COMMAND.ISO14A_RAW
                + lib14a.ISO14A_COMMAND.ISO14A_APPEND_CRC
                + lib14a.ISO14A_COMMAND.ISO14A_NO_RATS

    local command = Command:newMIX{cmd = cmds.CMD_HF_ISO14443A_READER,
                                arg1 = flags, -- Send raw
                                -- arg2 contains the length, which is half the length
                                -- of the ASCII-string rawdata
                                arg2 = string.len(rawdata)/2,
                                data = rawdata}

    return command:sendMIX(options.ignore_response)
end
---
-- The main entry point
function main(args)

    local ignore_response = false
    local endblock = 20

    -- Read the parameters
    for o, a in getopt.getopt(args, 'hb:') do
        if o == 'h' then return help() end
        if o == 'b' then endblock = a end
    end
    endblock = endblock or 20

    -- First of all, connect
    info, err = lib14a.read(true, true)
    if err then
        lib14a.disconnect()
        return oops(err)
    end
    core.clearCommandBuffer()

    local blockData = {}

    -- Show tag info
    print(('\nFound Card UID [%s]\n'):format(info.uid))

    print('blk | data             | xored')
    print('----+------------------+-------------------')
    for block = 00, endblock do
        local cmd = string.format('10%02x00', block)
        res, err = sendRaw(cmd , {ignore_response = ignore_response})
        if err then
            lib14a.disconnect()
            return oops(err)
        end

        local cmd_response = Command.parse(res)
        local len = tonumber(cmd_response.arg1) * 2
        local data = string.sub(tostring(cmd_response.data), 0, len-4)

        showdata(block, data)
        table.insert(blockData, data)
    end
    print("----+------------------+-------------------")
    lib14a.disconnect()

    local filename, err = utils.WriteDumpFile(info.uid, blockData)
    if err then return oops(err) end

    print(string.format('\nDumped data into %s', filename))
end

-------------------------
-- Testing
-------------------------
function selftest()
    DEBUG = true
    dbg('Performing test')
    main()
    dbg('Tests done')
end
-- Flip the switch here to perform a sanity check.
-- It read a nonce in two different ways, as specified in the usage-section
if '--test' == args then
    selftest()
else
    -- Call the main
    main(args)
end
