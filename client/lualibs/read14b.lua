--[[
    This is a library to read 14443b tags. It can be used something like this

    local reader = require('read14b')
    result, err = reader.read14443b()
    if not result then
        print(err)
        return
    end
    print(result.name)

--]]
-- Loads the commands-library
local cmds = require('commands')
local utils = require('utils')

-- Shouldn't take longer than 2.5 seconds
local TIMEOUT = 2000

local ISO14B_COMMAND = {
    ISO14B_CONNECT = 0x1,
    ISO14B_DISCONNECT = 0x2,
    ISO14B_APDU = 0x4,
    ISO14B_RAW = 0x8,
    ISO14B_REQUEST_TRIGGER = 0x10,
    ISO14B_APPEND_CRC = 0x20,
    ISO14B_SELECT_STD = 0x40,
    ISO14B_SELECT_SR = 0x80,
    ISO14B_SET_TIMEOUT = 0x100,
}

local function parse14443b(data)
    --[[

    Based on this struct :

    typedef struct {
        uint8_t uid[10];
        uint8_t uidlen;
        uint8_t atqb[7];
        uint8_t chipid;
        uint8_t cid;
    } PACKED iso14b_card_select_t;

    --]]

    local count, uid, uidlen, atqb, chipid, cid = bin.unpack('H10CH7CC',data)
    uid = uid:sub(1, 2 * uidlen)
    return {
        uid = uid,
        uidlen = uidlen,
        atqb = atqb,
        chipid = chipid,
        cid = cid
    }
end

-- This function does a connect and retrieves some info
-- @return if successful: an table containing card info
-- @return if unsuccessful : nil, error
local function read14443b(disconnect)

    local command, result, info, err, data

    local flags = ISO14B_COMMAND.ISO14B_CONNECT +
                  ISO14B_COMMAND.ISO14B_SELECT_STD

    if disconnect then
        print('DISCONNECT')
        flags = flags + ISO14B_COMMAND.ISO14B_DISCONNECT
    end

    command = Command:newMIX{
            cmd = cmds.CMD_HF_ISO14443B_COMMAND,
            arg1 = flags
            }

    info = nil

    local result, err = command:sendMIX(false, TIMEOUT, true)
    if result then
        local count,cmd,arg0,arg1,arg2 = bin.unpack('LLLL', result)
        if arg0 == 0 then
            data = string.sub(result, count)
            info, err = parse14443b(data)
        else
            err = 'iso14443b card select failed'
        end
    else
        err = 'No response from card'
    end

    if err then
        return nil, err
    end
    return info, nil
end
---
-- Waits for a mifare card to be placed within the vicinity of the reader.
-- @return if successful: an table containing card info
-- @return if unsuccessful : nil, error
local function waitFor14443b()
    print('Waiting for card... press Enter to quit')
    while not core.kbd_enter_pressed() do
        res, err = read14443b(false)
        if res then return res, err end
        -- err means that there was no response from card
    end
    return nil, 'Aborted by user'
end
---
-- turns on the HF field.
local function connect14443b()
    local c = Command:newMIX{cmd = cmds.CMD_HF_ISO14443B_COMMAND, arg1 = ISO14B_COMMAND.ISO14B_CONNECT}
    return c:sendMIX(true)
end
---
-- Sends an instruction to do nothing, only disconnect
local function disconnect14443b()
    local c = Command:newMIX{cmd = cmds.CMD_HF_ISO14443B_COMMAND, arg1 = ISO14B_COMMAND.ISO14B_DISCONNECT}
    -- We can ignore the response here, no ACK is returned for this command
    -- Check /armsrc/iso14443b.c, ReaderIso14443b() for details
    return c:sendMIX(true)
end

local library = {
    read = read14443b,
    waitFor14443b = waitFor14443b,
    parse14443b  = parse14443b,
    connect = connect14443b,
    disconnect = disconnect14443b,
    ISO14B_COMMAND = ISO14B_COMMAND,
}

return library
