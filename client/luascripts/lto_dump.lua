local cmds = require('commands')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils = require('utils')

copyright = ''
author = 'Kevin'
version = 'v1.0.1'
desc = [[
This is a script that reads LTO-CM  ISO14443a tags.
It starts from block 0 and ends at default block 254.
]]
example = [[
    -- default
    script run lto_dump

    -- stop at block 10
    script run lto_dump -e 10
]]
usage = [[
script run lto_dump -h -s -e

Arguments:
      h   this helptext
      s   start block in decimal
      e   end block in decimal
]]

-- Some globals
local DEBUG = false -- the debug flag
local lshift = bit32.lshift
local band = bit32.band
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

local function sendRaw(rawdata, options)

    local flags = lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT + lib14a.ISO14A_COMMAND.ISO14A_RAW

    if options.connect then
        flags = flags + lib14a.ISO14A_COMMAND.ISO14A_CONNECT
    end

    if options.no_select then
        flags = flags + lib14a.ISO14A_COMMAND.ISO14A_NO_SELECT
    end

    if options.append_crc then
        flags = flags + lib14a.ISO14A_COMMAND.ISO14A_APPEND_CRC
    end

    local arg2 = #rawdata / 2
    if options.bits7 then
       arg2 = arg2 + tonumber(lshift(7, 16))
    end

    local command = Command:newMIX{cmd = cmds.CMD_HF_ISO14443A_READER,
                                arg1 = flags, -- Send raw
                                -- arg2 contains the length, which is half the length
                                -- of the ASCII-string rawdata
                                arg2 = arg2,
                                data = rawdata}
    return command:sendMIX(options.ignore_response)
end

---
-- get hex data from response
local function getdata(usbpacket)
    local cmd_response = Command.parse(usbpacket)
    local len = tonumber(cmd_response.arg1) * 2
    return string.sub(tostring(cmd_response.data), 0, len)
end

---
-- helper function to send payloads easier
local function send(payload, options)
    local res, err = sendRaw(payload, options)
    if err then
        lib14a.disconnect()
        return oops(err)
    end
    core.clearCommandBuffer()
    if options.ignore_response then
        return "ok", nil
    else
        return res, err
    end
end

---
-- The main entry point
function main(args)

    local startblock = 0
    local endblock = 254
    -- Read the parameters
    for o, a in getopt.getopt(args, 'hs:e:') do
        if o == 'h' then return help() end
        if o == 's' then startblock = a end
        if o == 'e' then endblock = a end
    end

-- Original loop
--    core.console("hf 14a raw -a -p -b 7 45")
--    local cmd_select = string.format("hf 14a raw -c -p 9370%s", serial_number)
--    core.console(cmd_select)
--    for i = 0, 254 do
--      local cmd_rd_blk = string.format("hf 14a raw -c -p 30 %02x", i)
--      core.console(cmd_rd_blk)
--      core.console("hf 14a raw -p 80")
--    end
--   core.console("hf 14a raw -r")

    -- Wakeup
    local payload = "45"
    local res, err = send(payload,{connect = true, no_select = true, ignore_response = false, append_crc = false, bits7 = true})
    if err then return end

    -- start selecting
    payload = "9320"
    res, err = send(payload,{ignore_response = false, append_crc = false})
    if err then return end

    local serial_number = getdata(res)
    payload = "9370"..serial_number
    res, err = send(payload,{ignore_response = false, append_crc = true})
    if err then return end

    -- Show tag info
    print(('\nFound LTO-CM serial number: [%s]\n'):format(serial_number))

    -- Dumping data
    print('blk | data             ')
    print('----+------------------')
    local block_data = {}
    for block = startblock, endblock do

        payload = string.format('30%02x', block)
        res, err = send(payload , {ignore_response = false, append_crc = true})
        if err then return end

        local d0_d15 = getdata(res)

        payload = "80"
        res, err = send(payload, {ignore_response = false, append_crc = false})
        if err then return end

        local d16_d31 = getdata(res)

        -- remove crc bytes
        d0_d15 = string.sub(d0_d15, 0, #d0_d15 - 4)
        d16_d31 = string.sub(d16_d31, 0, #d16_d31 - 4)

        print(block, d0_d15..d16_d31)
        table.insert(block_data, d0_d15..d16_d31)
    end
    print("----+------------------")
    lib14a.disconnect()

    local filename, err = utils.WriteDumpFile(serial_number, block_data)
    if err then return oops(err) end

    print(string.format('\nDumped data into %s', filename))
end

main(args)
