local getopt = require('getopt')
local lib14a = require('read14a')
local cmds = require('commands')
local ansicolors = require('ansicolors')

copyright = 'Copyright 2021 A. Ozkal, released under GPLv2+.'
author = 'Ave'
version = 'v1.0.0'
desc = [[
This script attempts to grab signatures from an NTAG or MFULEV1 card and print it in a machine parsable way
 ]]
example = [[
    script run ntag_getsig
]]
usage = [[
    script run ntag_getsig [-h]
]]
arguments = [[
    -h                   : This help
]]

local function help()
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

-- Used to send raw data to the firmware to subsequently forward the data to the card.
-- from mifareplus.lua
local function sendRaw(rawdata, crc, power)
    -- print(("<sent>:       %s"):format(rawdata))

    local flags = lib14a.ISO14A_COMMAND.ISO14A_RAW
    if crc then
        flags = flags + lib14a.ISO14A_COMMAND.ISO14A_APPEND_CRC
    end
    if power then
        flags = flags + lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT
    end

    local command = Command:newMIX{cmd = cmds.CMD_HF_ISO14443A_READER,
                                arg1 = flags, -- Send raw
                                arg2 = string.len(rawdata) / 2, -- arg2 contains the length, which is half the length of the ASCII-string rawdata
                                data = rawdata
                                }
    local ignore_response = false
    local result, err = command:sendMIX(ignore_response)
    if result then
        --unpack the first 4 parts of the result as longs, and the last as an extremely long string to later be cut down based on arg1, the number of bytes returned
        local count,cmd,arg1,arg2,arg3,data = bin.unpack('LLLLH512',result)

        returned_bytes = string.sub(data, 1, arg1 * 2)
        if #returned_bytes > 0 then
            -- print(("<recvd>: %s"):format(returned_bytes)) -- need to multiply by 2 because the hex digits are actually two bytes when they are strings
            return returned_bytes
        else
            return nil
        end
    else
        print("Error sending the card raw data.")
        return nil
    end
end

---
-- The main entry point
function main(args)
    -- Read the parameters
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end

    local tag, err = lib14a.read(true, false)

    if not err then
        local sig = sendRaw("3C00", true, true)
        local ver = sendRaw("60", true, false)
        if sig and ver then  -- if false, that's a fail right there
            sig = string.sub(sig, 0, -5)
            ver = string.sub(ver, 0, -5)
            local text = tag.name..","..ver..","..tag.uid..","..sig
            print(text)

            local filename = "originalitysig.csv"
            local outfile = io.open(filename, "a")
            if outfile ~= nil then
                outfile:write(text.."\n")
                io.close(outfile)
            else
                print(ansicolors.red.."Couldn't open file originalitysig.csv."..ansicolors.reset)
            end
        else
            print(ansicolors.red.."Read FAILED."..ansicolors.reset)
        end
    end
end

main(args)
