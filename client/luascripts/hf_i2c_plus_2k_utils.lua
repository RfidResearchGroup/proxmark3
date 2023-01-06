local getopt = require('getopt')
local lib14a = require('read14a')
local cmds = require('commands')
local utils = require('utils')
local ansicolors  = require('ansicolors')

--- Commands
NTAG_I2C_PLUS_2K = '0004040502021503C859'
GET_VERSION = '60'
SELECT_SECTOR_PKT1 = 'C2FF'
SELECT_SECTOR0_PKT2 = '00000000'
SELECT_SECTOR1_PKT2 = '01000000'
READ_BLOCK = '30'
WRITE_BLOCK = 'A2'
ACK = '0A'
NAK = '00'
---


--- Arguments
copyright = ''
author = 'Shain Lakin'
version = 'v1.0.0'
desc =[[

This script can be used to read blocks, write blocks, dump sectors,
or write a files hex bytes to sector 0 or 1 on the NTAG I2C PLUS 2K tag.

]]

example =[[

    Read block 04 from sector 1:
    script run hf_i2c_plus_2k_utils -m r -s 1 -b 04

    Write FFFFFFFF to block A0 sector 1:
    script run hf_i2c_plus_2k_utils -m w -s 1 -b A0 -d FFFFFFFF

    Dump sector 1 user memory to console and file:
    script run hf_i2c_plus_2k_utils -m d -s 1

    Write a files hex bytes to sector 1 starting at block 04:
    script run hf_i2c_plus_2k_utils -m f -s 1 -f data.txt

]]
usage = [[

    Read mode:
    script run hf_i2c_plus_2k_utils -m r -s <sector> -b <block (hex)>

    Write mode:
    script run hf_i2c_plus_2k_utils -m w -s <sector> -b <block (hex)> -d <data (hex)>

    Dump mode:
    script run hf_i2c_plus_2k_utils -m d -s <sector>

    File mode:
    script run hf_i2c_plus_2k_utils -m f -s <sector> -f <file>

]]
arguments = [[
    -h      this help
    -m      mode (r/w/f)
    -b      block (hex)
    -f      file
    -s      sector (0/1)
    -d      data (hex)
]]
---


--- Help function
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
---


--- Message function
local function msg(string)
    print(ansicolors.magenta..string.rep('-',29)..ansicolors.reset)
    print(ansicolors.cyan..string..ansicolors.reset)
    print(ansicolors.magenta..string.rep('-',29)..ansicolors.reset)
end
---


--- Error handling
local function warn(err)

    print(ansicolors.magenta.."ERROR:"..ansicolors.reset,err)
    core.clearCommandBuffer()
    return nil, err

end
---


--- Setup tx/rx
local function sendRaw(rawdata, options)

    local flags = lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT
                + lib14a.ISO14A_COMMAND.ISO14A_RAW
                + lib14a.ISO14A_COMMAND.ISO14A_APPEND_CRC

    local c = Command:newMIX{cmd = cmds.CMD_HF_ISO14443A_READER,
                arg1 = flags,
                arg2 = string.len(rawdata)/2,
                data = rawdata}

    return c:sendMIX(options.ignore_response)
end
---


--- Function to connect
local function connect()
    core.clearCommandBuffer()

    info, err = lib14a.read(true, true)
    if err then
        lib14a.disconnect()
        return error(err)
    else
        return info.uid
    end
    core.clearCommandBuffer()

end
---


--- Function to disconnect
local function disconnect()
    core.clearCommandBuffer()
    lib14a.disconnect()
end
---


--- Function to get response data
local function getResponseData(usbpacket)

    local resp = Command.parse(usbpacket)
    local len = tonumber(resp.arg1) * 2
    return string.sub(tostring(resp.data), 0, len);

end
---


--- Function to send raw bytes
local function send(payload)

    local usb, err = sendRaw(payload,{ignore_response = false})
    if err then return warn(err) end
    return getResponseData(usb)

end
---

--- Function to select sector
local function select_sector(sector)
    send(SELECT_SECTOR_PKT1)
    if sector == '0' then
        send(SELECT_SECTOR0_PKT2)
    elseif sector == '1' then
        send(SELECT_SECTOR1_PKT2)
    end
end
---

--- Function to write file to sector
local function filewriter(file,sector)
    file_bytes = utils.ReadDumpFile(file)
    len = string.len(file_bytes) / 8
    start_char = 1
    end_char = 8
    block_counter = 4
    -- NTAG_I2C_PLUS_2K:SECTOR_0:225,SECTOR_1:255
    end_block = 225
    connect()
    select_sector(sector)
    for count = 1, len do
        block = file_bytes:sub(start_char, end_char)
        data = send(WRITE_BLOCK..string.format("%02x",block_counter)..block)
        print('[*] Writing bytes '..block..' to page '..string.format("%02x", block_counter))
        if data == ACK then
            print(ansicolors.cyan..'[*] Received ACK, write successful'..ansicolors.reset)
        else
            print(ansicolors.magenta..'[!] Write failed'..ansicolors.reset)
        end
        start_char = start_char + 8
        end_char = end_char + 8
        block_counter = block_counter + 1
        if block_counter == end_block then
            print(ansicolors.magenta..'[!] Not enough memory space!'..ansicolors.reset)
            break
        end
    end
    disconnect()
end
---

--- Function to dump user memory to console and disk
local function dump(sector,uid)
    connect()
    select_sector(sector)
    counter = 0
    dest = uid..'.hex'
    file = io.open(dest, 'a')
    io.output(file)
    print("\n[+] Dumping sector "..sector.."\n")
    print(ansicolors.magenta..string.rep('--',16)..ansicolors.reset)
    for count = 1, 64 do
        result = send(READ_BLOCK..string.format("%02x", counter))
        print(ansicolors.cyan..result:sub(1,32)..ansicolors.reset)
        io.write(result:sub(1,32))
        counter = counter + 4
    end
    io.close(file)
    print(ansicolors.magenta..string.rep('--',16)..ansicolors.reset)
    print("\n[+] Memory dump saved to "..uid..".hex")
    disconnect()
end
---


--- Function to read and write blocks
local function exec(cmd, sector, block, bytes)
    connect()
    select_sector(sector)
    if cmd == READ_BLOCK then
        data = send(cmd..block)
        msg(data:sub(1,8))
    elseif cmd == WRITE_BLOCK then
        if bytes == 'NOP' then
            err = '[!] You need to pass some data'
            warn(err)
            print(usage)
            do return end
        else
            data = send(cmd..block..bytes)
            if data == ACK then
                print(ansicolors.cyan..'[+] Received ACK, write succesful'..ansicolors.reset)
            elseif data ~= ACK then
                print(ansicolors.magenta..'[!] Write failed'..ansicolors.reset)
            end
        end
    end
    disconnect()
    return(data)
end
---


--- Main
local function main(args)

    for o, a in getopt.getopt(args, 'm:b:s:d:f:h') do
        if o == 'm' then mode = a end
        if o == 'b' then block = a end
        if o == 's' then sector = a end
        if o == 'd' then bytes = a end
        if o == 'f' then file = a end
        if o == 'h' then return help() end
    end

    uid = connect()

    connect()
    version = send(GET_VERSION)
    disconnect()

    if version == NTAG_I2C_PLUS_2K then

        if mode == 'r' then
            print('\n[+] Reading sector '..sector..' block '..block)
            exec(READ_BLOCK,sector,block,bytes)
        elseif mode == 'w' then
            print('\n[+] Writing '..bytes..' to sector '..sector..' block '..block)
            exec(WRITE_BLOCK,sector,block,bytes)
        elseif mode == 'f' then
            filewriter(file,sector)
        elseif mode == 'd' then
            dump(sector,uid)
        end

    else
        return print(usage)
    end

    if command == '' then return print(usage) end

end
---


main(args)
