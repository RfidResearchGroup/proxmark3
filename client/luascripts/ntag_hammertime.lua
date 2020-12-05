local getopt = require('getopt')
local lib14a = require('read14a')
local cmds = require('commands')
local ansicolors = require('ansicolors')

copyright = 'Copyright 2020 A. Ozkal, released under GPLv2+.'
author = 'Ave'
version = 'v2.1.3'
desc = [[
This script writes a bunch of random blocks to a NTAG or MFUL card to test its actual write limits
 ]]
example = [[
    script run ntag_hammertime -w 1000 -r 50 -z 50 -f 5 -s 4 -e 129
]]
usage = [[
    script run ntag_hammertime [-h] [-w <writecount>] [-r <readevery>] [-z <reselectevery>] [-f <maximumfails>] [-s <writestartblock>] [-e <writeendblock>]
]]
arguments = [[
    -h                   : This help
    -w <writeroundcount> : Amount of write rounds to be done to each block (optional, default: 100)
    -r <readevery>       : Verify frequency (reads and checks written values every x rounds, optional, default: 10)
    -z <reselectevery>   : Reselect frequency (reselects card once every x rounds, optional, default: 10)
    -f <maximumfails>    : Maximum consequent fails (read/write) that will trigger a fail state (optional, default: 3)
    -s <writestartblock> : Block number for writes to be started to (optional, inclusive, decimal, default: 4)
    -e <writeendblock>   : Block number for writes to be ended on (optional, inclusive, decimal, default: 129)
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

function randhex(len)
    result = ""
    for i = 1,len,1
    do
        -- 48-57 numbers, 65-70 a-f
        hex = math.random(0, 15)
        if hex >= 10 then
            hex = hex + 7
        end
        result = result..string.char(48 + hex)
    end
    return result
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

local function selectCard(keepField, arg2, attemptCount)
    for i = 1,attemptCount,1
    do
        if lib14a.read(keepField, arg2) then
            return true
        end
    end
    return false
end

---
-- The main entry point
function main(args)
    failcounter = 0

    -- param defaults
    loopcount = 100
    verifyevery = 10
    reselectevery = 10
    failmax = 3
    blockstart = 4
    blockend = 129

    -- Read the parameters
    for o, a in getopt.getopt(args, 'hw:r:z:f:s:e:') do
        if o == 'h' then return help() end
        if o == 'w' then loopcount = tonumber(a) end
        if o == 'r' then verifyevery = tonumber(a) end
        if o == 'z' then reselectevery = tonumber(a) end
        if o == 'f' then failmax = tonumber(a) end
        if o == 's' then blockstart = tonumber(a) end
        if o == 'e' then blockend = tonumber(a) end
    end

    starttime = os.time()

    if selectCard(true, false, 3) ~= true then
        return print("Select failed.")
    end
    for i = 1,loopcount,1
    do
        for block = blockstart,blockend,1
        do
            data = randhex(8)
            print(i..": Writing "..data.." to block "..block..".")
            blockhex = string.format("%02x", block)
            result = sendRaw("A2"..blockhex..data, true, true)
            if result then  -- if false/nil, that's a fail right there
                print(ansicolors.green.."Got "..result.."."..ansicolors.reset) -- We want this to be 0A
                failcounter = 0
            else
                print(ansicolors.red.."Write FAILED."..ansicolors.reset)
                failcounter = failcounter + 1
                goto continue
            end

            if i % verifyevery == 0 then
                result = sendRaw("30"..blockhex, true, true)
                if result then  -- if false, that's a fail right there
                    result = string.sub(result, 0, 8)
                    if result ~= data then
                        print(ansicolors.red.."Read IMPROPER, supposed to be "..data..", got "..result.."."..ansicolors.reset)
                        failcounter = failcounter + 1
                        goto continue
                    else
                        print(ansicolors.green.."Read matches the write."..ansicolors.reset)
                        failcounter = 0
                    end
                else
                    print(ansicolors.red.."Read FAILED."..ansicolors.reset)
                    failcounter = failcounter + 1
                    goto continue
                end
            end
            ::continue::

            if failcounter >= failmax then
                -- close field
                lib14a.read(false, false)
                return print(ansicolors.red.."Test failed after "..(os.time() - starttime).." seconds, "..(i*(blockend-blockstart)).." writes and "..math.floor((i*(blockend-blockstart))/verifyevery).." reads."..ansicolors.reset)
            end
        end

        if i % reselectevery == 0 then
            -- reselect
            sendRaw("", false, false)
            if selectCard(true, false, 3) ~= true then
                return print("Reselect failed.")
            end
            print("Reselected card, current rate: "..(i*(blockend-blockstart))/(os.time() - starttime).." writes/s.")
        end
    end

    -- close field
    lib14a.read(false, false)
    print("Successfully completed test in "..(os.time() - starttime).." seconds, did "..(loopcount*(blockend-blockstart)).." writes and "..math.floor((loopcount*(blockend-blockstart))/verifyevery).." reads.")
end

main(args)
