local cmds = require('commands')
local getopt = require('getopt')
local lib14a = require('read14a')

copyright = ''
author = "Martin Holst Swende"
version = 'v1.0.1'
desc = [[
This is a script to allow raw 1444a commands to be sent and received.
]]
example = [[
    # 1. Connect and don't disconnect
    script run 14araw -p

    # 2. Send mf auth, read response (nonce)
    script run 14araw -o -x 6000F57b -p

    # 3. disconnect
    script run 14araw -o

    # All three steps in one go:
    script run 14araw -x 6000F57b
]]
usage = [[
script run 14araw -x 6000F57b

Arguments:
    -o              do not connect - use this only if you previously used -p to stay connected
    -r              do not read response
    -c              calculate and append CRC
    -p              stay connected - dont inactivate the field
    -x <payload>    Data to send (NO SPACES!)
    -d              Debug flag
    -t              Topaz mode
    -3              ISO14443-4 (use RATS)
]]

--[[

This script communicates with
/armsrc/iso14443a.c, specifically ReaderIso14443a() at around line 1779 and onwards.

Check there for details about data format and how commands are interpreted on the
device-side.
]]

-- Some globals
local DEBUG = false -- the debug flag

-------------------------------
-- Some utilities
-------------------------------

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
---
-- The main entry point
function main(args)

    if args == nil or #args == 0 then return help() end

    local ignore_response = false
    local append_crc = false
    local stayconnected = false
    local payload = nil
    local doconnect = true
    local topaz_mode = false
    local no_rats = false

    -- Read the parameters
    for o, a in getopt.getopt(args, 'orcpx:dt3') do
        if o == 'o' then doconnect = false end
        if o == 'r' then ignore_response = true end
        if o == 'c' then append_crc = true end
        if o == 'p' then stayconnected = true end
        if o == 'x' then payload = a end
        if o == 'd' then DEBUG = true end
        if o == 't' then topaz_mode = true end
        if o == '3' then no_rats = true end
    end

    -- First of all, connect
    if doconnect then
        dbg("doconnect")

        info, err = lib14a.read(true, no_rats)
        if err then
            lib14a.disconnect()
            return oops(err)
        end
        print(('Connected to card, uid = %s'):format(info.uid))
    end

    -- The actual raw payload, if any
    if payload then
        res, err = sendRaw(payload,{ignore_response = ignore_response, topaz_mode = topaz_mode, append_crc = append_crc})
        if err then
            lib14a.disconnect()
            return oops(err)
        end

        if not ignoreresponse then
            -- Display the returned data
            showdata(res)
        end
    end
    -- And, perhaps disconnect?
    if not stayconnected then
        lib14a.disconnect()
    end
end

--- Picks out and displays the data read from a tag
-- Specifically, takes a usb packet, converts to a Command
-- (as in commands.lua), takes the data-array and
-- reads the number of bytes specified in arg1 (arg0 in c-struct)
-- and displays the data
-- @param usbpacket the data received from the device
function showdata(usbpacket)
    local cmd_response = Command.parse(usbpacket)
    local len = tonumber(cmd_response.arg1) *2
    --print("data length:",len)
    local data = string.sub(tostring(cmd_response.data), 0, len);
    print("<< ",data)
end

function sendRaw(rawdata, options)
    print('>> ', rawdata)

    local flags = lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT + lib14a.ISO14A_COMMAND.ISO14A_RAW

    if options.topaz_mode then
        flags = flags + lib14a.ISO14A_COMMAND.ISO14A_TOPAZMODE
    end
    if options.append_crc then
        flags = flags + lib14a.ISO14A_COMMAND.ISO14A_APPEND_CRC
    end

    local command = Command:newMIX{cmd = cmds.CMD_READER_ISO_14443a,
                                arg1 = flags, -- Send raw
                                -- arg2 contains the length, which is half the length
                                -- of the ASCII-string rawdata
                                arg2 = string.len(rawdata)/2,
                                data = rawdata}
    return  command:sendMIX(options.ignore_response)
end


-------------------------
-- Testing
-------------------------
function selftest()
    DEBUG = true
    dbg('Performing test')
    main()
    main('-p')
    main(' -o -x 6000F57b -p')
    main('-o')
    main('-x 6000F57b')
    dbg('Tests done')
end
-- Flip the switch here to perform a sanity check.
-- It read a nonce in two different ways, as specified in the usage-section
if '--test'==args then
    selftest()
else
    -- Call the main
    main(args)
end
