local ansicolors  = require('ansicolors')
local cmds = require('commands')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils = require('utils')

-- globals
copyright = ''
author = 'Dmitry Malenok'
version = 'v1.0.0'
desc =  [[
The script provides functionality for writing Mifare Ultralight Ultra/UL-5 tags.
]]
example = [[
    -- restpre (write) dump to tag
    ]]..ansicolors.yellow..[[script run hf_mfu_ultra -k ffffffff -r hf-mfu-3476FF1514D866-dump.bin]]..ansicolors.reset..[[

    -- wipe tag (]]..ansicolors.red..[[Do not use it with UL-5!]]..ansicolors.reset..[[)
    ]]..ansicolors.yellow..[[script run hf_mfu_ultra -k 1d237f76 -w ]]..ansicolors.reset..[[
]]
usage = [[
script run hf_mfu_ultra -h -k <passwd> -w -r <dump filename>
]]
arguments = [[
    -h      this help
    -k      pwd to use with the restore and wipe operations
    -r      restore a binary dump to tag
    -w      wipe tag (]]..ansicolors.red..[[Do not use it with UL-5!]]..ansicolors.reset..[[)

]]


local _password = nil
local _defaultPassword = 'FFFFFFFF'
local _dumpstart = 0x38*2 + 1
---

--- Handles errors
local function error(err)
    print(ansicolors.red.."ERROR:"..ansicolors.reset, err)
    core.clearCommandBuffer()
    return nil, err
end
---

-- sets the global password variable
local function setPassword(password)
    if password == nil or #password == 0 then
        _password = nil;
    elseif #password ~= 8 then
        return false, 'Password must be 4 hex bytes'
    else 
        _password = password
    end
    return true, 'Sets'
end


--- Parses response data
local function parseResponse(rawResponse)
    local resp = Command.parse(rawResponse)
    local len = tonumber(resp.arg1) * 2
    return string.sub(tostring(resp.data), 0, len);
end
---

--- Sends raw data to PM3 and returns raw response if any
local function sendRaw(rawdata, options)

    local flags = lib14a.ISO14A_COMMAND.ISO14A_RAW

    if options.keep_signal then
        flags = flags + lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT
    end

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
       arg2 = arg2 | tonumber(bit32.lshift(7, 16))
    end

    local command = Command:newMIX{cmd = cmds.CMD_HF_ISO14443A_READER,
                    arg1 = flags,
                    arg2 = arg2,
                    data = rawdata}
    return command:sendMIX(options.ignore_response)
end
---

--- Sends raw data to PM3 and returns parsed response
local function sendWithResponse(payload, options)
    local opts;
    if options then 
        opts = options
    else
        opts = {ignore_response = false, keep_signal = true, append_crc = true}
    end
    local rawResp, err = sendRaw(payload, opts)
    if err then return err end
    return parseResponse(rawResp)
end
---

-- Authenticates if password is provided
local function authenticate(password)
    if password then
        local resp, err = sendWithResponse('1B'..password)
        if err then return err end
        -- looking for 2 bytes (4 symbols) of PACK and 2 bytes (4 symbols) of CRC
        if not resp or #resp ~=8 then return false, 'It seems that password is wrong' end
        return true
    end
    return true
end
--

-- selects tag and authenticates if password is provided
local function connect()
    core.clearCommandBuffer()
    local info, err = lib14a.read(true, true)
    if err then
        lib14a.disconnect()
        return false, err
    end
    core.clearCommandBuffer()

    return authenticate(_password)
end
--

-- reconnects and selects tag again
local function reconnect()
    lib14a.disconnect()
    utils.Sleep(1)
    local info, err = connect()
    if not info then return false, "Unable to select tag: "..err end
    return true
end
--

-- checks tag version
local function checkTagVersion()
    local resp, err = sendWithResponse('60');
    if err or resp == nil then return false, err end
    if string.find(resp, '0034210101000E03') ~= 1 then return false, 'Wrong tag version: '..string.sub(resp,1,-5) end
    return true
end
--

-- sends magic wakeup command
local function magicWakeup()
    io.write('Sending magic wakeup command...')
    local resp, err = sendRaw('5000', {ignore_response = false, append_crc = true})
    if err or resp == nil then return false, "Unable to send first magic wakeup command: "..err end
    resp, err = sendRaw('40', {connect = true, no_select = true, ignore_response = false, keep_signal = true, append_crc = false, bits7 = true})
    if err or resp == nil then return false, "Unable to send first magic wakeup command: "..err end
    resp, err = sendRaw('43', {ignore_response = false, keep_signal = true, append_crc = false})
    if err or resp == nil then return false, "Unable to send second magic wakeup command: "..err end
    print(ansicolors.green..'done'..ansicolors.reset..'.')
    return true
end
--

-- Writes dump to tag
local function writeDump(filename)
    print(string.rep('--',20))
    local info, err = connect()
    if not info then return false, "Unable to select tag: "..err end
    info, err = checkTagVersion()
    if not info then return info, err end

    -- load dump from file
    io.write('Loading dump from file '..filename..'...')
    local dump
    dump, err = utils.ReadDumpFile(filename)
    if not dump then return false, err end
    if #dump ~= _dumpstart - 1 + 0xa4*2 then return false, 'Invalid dump file' end
    print(ansicolors.green..'done'..ansicolors.reset..'.')

    local resp
    for i = 3, 0x23 do
        local blockStart = i * 8 + _dumpstart
        local block = string.sub(dump, blockStart, blockStart + 7)
        local cblock = string.format('%02x',i)
        io.write('Writing block 0x'..cblock..'...')
        resp, err = sendWithResponse('A2'..cblock..block)
        if err ~= nil then return false, err end
        print(ansicolors.green..'done'..ansicolors.reset..'.')
    end

    -- set password
    io.write('Setting password and pack ')
    info, err = reconnect()
    if not info then return false, err end
    local passwordStart = 0x27*8 + _dumpstart
    local password = string.sub(dump, passwordStart, passwordStart + 7)
    local packBlock = string.sub(dump, passwordStart+8, passwordStart + 15)
    io.write('(password: '..password..') (pack block: '..packBlock..')...')
    resp, err = sendWithResponse('A227'..password)
    if err ~= nil then return false, err end
    resp, err = sendWithResponse('A228'..packBlock)
    if err ~= nil then return false, err end
    if not setPassword(password) then return false, 'Unable to set password' end
    info, err = reconnect()
    if not info then return false, err end
    print(ansicolors.green..'done'..ansicolors.reset..'.')

    -- set configs and locks
    for i = 0x24, 0x26 do
        local blockStart = i * 8 + _dumpstart
        local block = string.sub(dump, blockStart, blockStart + 7)
        local cblock = string.format('%02x',i)
        io.write('Writing block 0x'..cblock..'...')
        resp, err = sendWithResponse('A2'..cblock..block)
        if err ~= nil then return false, err end
        info, err = reconnect()
        if not info then return false, err end
            print(ansicolors.green..'done'..ansicolors.reset..'.')
    end

    info, err = magicWakeup()
    if not info then return false, err end
    -- set uid and locks
    for i = 0x2, 0x0, -1 do
        local blockStart = i * 8 + _dumpstart
        local block = string.sub(dump, blockStart, blockStart + 7)
        local cblock = string.format('%02x',i)
        io.write('Writing block 0x'..cblock..'...')
        resp, err = sendWithResponse('A2'..cblock..block, {connect = i == 0x2, ignore_response = false, keep_signal = i ~= 0, append_crc = true})
        if err ~= nil then return false, err end
        print(ansicolors.green..'done'..ansicolors.reset..'.')
    end

    print(ansicolors.green..'The dump has been written to the tag.'..ansicolors.reset)
    return true
end
--

-- Wipes tag
local function wipe()
    print(string.rep('--',20))
    print('Wiping tag')

    local info, err = connect()
    if not info then return false, "Unable to select tag: "..err end
    info, err = checkTagVersion()
    if not info then return info, err end


    local resp
    -- clear lock bytes on page 0x02
    resp, err = sendWithResponse('3000')
    if err or resp == nil then return false, err end
    local currentLowLockPage = string.sub(resp,17,24)
    if(string.sub(currentLowLockPage,5,8) ~= '0000') then
        info, err = magicWakeup()
        if not info then return false, err end
        local newLowLockPage = string.sub(currentLowLockPage,1,4)..'0000'
        io.write('Clearing lock bytes on page 0x02...')
        resp, err = sendWithResponse('A202'..newLowLockPage, {connect = true, ignore_response = false, keep_signal = true, append_crc = true})
        if err ~= nil then return false, err end
        print(ansicolors.green..'done'..ansicolors.reset..'.')
    end

    -- clear lock bytes on page 0x24
    io.write('Clearing lock bytes on page 0x24...')
    info, err = reconnect()
    if not info then return false, err end
    resp, err = sendWithResponse('A224000000BD')
    if err ~= nil then return false, err end
    print(ansicolors.green..'done'..ansicolors.reset..'.')

    -- clear configs
    io.write('Clearing cfg0 and cfg1...')
    resp, err = sendWithResponse('A225000000FF')
    if err ~= nil then return false, err end
    resp, err = sendWithResponse('A22600050000')
    if err ~= nil then return false, err end
    print(ansicolors.green..'done'..ansicolors.reset..'.')

    -- clear password
    io.write('Reseting password (and pack) to default ('.._defaultPassword..') and 0000...')
    info, err = reconnect()
    if not info then return false, err end
    resp, err = sendWithResponse('A227'.._defaultPassword)
    if err ~= nil then return false, err end
    resp, err = sendWithResponse('A22800000000')
    if err ~= nil then return false, err end
    if not setPassword(_defaultPassword) then return false, 'Unable to set password' end
    info, err = reconnect()
    if not info then return false, err end
    print(ansicolors.green..'done'..ansicolors.reset..'.')

    -- clear other blocks
    for i = 3, 0x23 do
        local cblock = string.format('%02x',i)
        io.write('Clearing block 0x'..cblock..'...')
        resp, err = sendWithResponse('A2'..cblock..'00000000')
        if err ~= nil then return false, err end
        print(ansicolors.green..'done'..ansicolors.reset..'.')
    end

    print(ansicolors.green..'The tag has been wiped.'..ansicolors.reset)

    lib14a.disconnect()
    return true
end
--

-- Prints help
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

-- The main entry point
local function main(args)
    if #args == 0 then return help() end

    for opt, value in getopt.getopt(args, 'hk:r:w') do
        local res, err
        res = true
        if opt == "h" then return help() end
        if opt == 'k' then res, err = setPassword(value) end
        if opt == 'r' then res, err = writeDump(value) end
        if opt == 'w' then res, err = wipe() end
        if not res then return error(err) end
    end
    
end

main(args)
