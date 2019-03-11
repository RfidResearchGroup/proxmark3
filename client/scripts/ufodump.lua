local cmds = require('commands')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils = require('utils')
example = [[
    script run ufodump
    script run ufodump -b 10
]]
author = "Iceman"
desc =
[[
This is a script that reads AZTEK iso14443a tags.
It starts from block 0,  and ends at default block 20.  Use 'b' to say different endblock.

xor:  the first three block (0,1,2) is not XORED.  The rest seems to be xored.

Arguments:
      h   this helptext
      b   endblock in decimal (1-255,  default 20)
]]

-- Some globals
local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local DEBUG = false -- the debug flag
---
-- A debug printout-function
local function dbg(args)
    if DEBUG then
        print("###", args)
    end
end
---
-- This is only meant to be used when errors occur
local function oops(err)
    print("ERROR: ",err)
    core.clearCommandBuffer()
end
---
-- Usage help
local function help()
    print(desc)
    print("Example usage")
    print(example)
end
--
-- writes data to ascii textfile.
function writeDumpFile(uid, blockData)
        local destination = string.format("%s.eml", uid)
        local file = io.open(destination, "w")
        if file == nil then
            return nil, string.format("Could not write to file %s", destination)
        end
        local rowlen = string.len(blockData[1])

        for i,block in ipairs(blockData) do
            if rowlen ~= string.len(block) then
                print(string.format("WARNING: Dumpdata seems corrupted, line %d was not the same length as line 1",i))
            end
            file:write(block.."\n")
        end
        file:close()
        return destination
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
    --print(">> ", rawdata)
    local flags = lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT + lib14a.ISO14A_COMMAND.ISO14A_RAW + lib14a.ISO14A_COMMAND.ISO14A_APPEND_CRC + lib14a.ISO14A_COMMAND.ISO14A_NO_RATS
    local command = Command:new{cmd = cmds.CMD_READER_ISO_14443a,
                                arg1 = flags, -- Send raw
                                -- arg2 contains the length, which is half the length
                                -- of the ASCII-string rawdata
                                arg2 = string.len(rawdata)/2,
                                data = rawdata}
    return lib14a.sendToDevice(command, options.ignore_response)
end
--
-- Sends an instruction to do nothing, only disconnect
function disconnect()
    local command = Command:new{cmd = cmds.CMD_READER_ISO_14443a, arg1 = 0,}
    -- We can ignore the response here, no ACK is returned for this command
    -- Check /armsrc/iso14443a.c, ReaderIso14443a() for details
    return lib14a.sendToDevice(command, true)
    --core.console("hf 14a raw -r")
end
---
-- The main entry point
function main(args)

    local ignore_response = false
    local endblock = 20

    -- Read the parameters
    for o, a in getopt.getopt(args, 'hb:') do
        if o == "h" then return help() end
        if o == "b" then endblock = a end
    end
    endblock = endblock or 20

    -- First of all, connect
    info, err = lib14a.read(true, true)
    if err then disconnect() return oops(err) end
    core.clearCommandBuffer()

    local blockData = {}

    -- Show tag info
    print(("\nFound Card UID [%s]\n"):format(info.uid))

    print("blk | data             | xored")
    print("----+------------------+-------------------")
    for block = 00, endblock do
        local cmd = string.format("10%02x00", block)
        res, err = sendRaw(cmd , {ignore_response = ignore_response})
        if err then disconnect() return oops(err) end

        local cmd_response = Command.parse(res)
        local len = tonumber(cmd_response.arg1) * 2
        local data = string.sub(tostring(cmd_response.data), 0, len-4)

        showdata(block, data)
        table.insert(blockData, data)
    end
    print("----+------------------+-------------------")
    disconnect()

    local filename, err = writeDumpFile(info.uid, blockData)
    if err then return oops(err) end

    print(string.format("\nDumped data into %s", filename))
end

-------------------------
-- Testing
-------------------------
function selftest()
    DEBUG = true
    dbg("Performing test")
    main()
    dbg("Tests done")
end
-- Flip the switch here to perform a sanity check.
-- It read a nonce in two different ways, as specified in the usage-section
if "--test"==args then
    selftest()
else
    -- Call the main
    main(args)
end
