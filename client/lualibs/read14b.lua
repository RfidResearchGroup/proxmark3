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
local TIMEOUT = 2500

local ISO14B_COMMAND = {
    ISO14B_CONNECT = 1,
    ISO14B_DISCONNECT = 2,
    ISO14B_APDU = 4,
    ISO14B_RAW = 8,
    ISO14B_REQUEST_TRIGGER = 0x10,
    ISO14B_APPEND_CRC = 0x20,
    ISO14B_SELECT_STD = 0x40,
    ISO14B_SELECT_SR = 0x80,
}

local function parse1443b(data)
    --[[

    Based on this struct :

    typedef struct {
        uint8_t uid[10];
        uint8_t uidlen;
        uint8_t atqb[7];
        uint8_t chipid;
        uint8_t cid;
    } __attribute__((__packed__)) iso14b_card_select_t;

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
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
local function read14443b(disconnect)

    local command, result, info, err, data

    local flags = ISO14B_COMMAND.ISO14B_CONNECT +
                  ISO14B_COMMAND.ISO14B_SELECT_STD

    if disconnect then
        print('DISCONNECT')
        flags = flags + ISO14B_COMMAND.ISO14B_DISCONNECT
    end

    command = Command:newMIX{
            cmd = cmds.CMD_ISO_14443B_COMMAND,
            arg1 = flags
            }

    local result, err = command:sendMIX()
    if result then
        local count,cmd,arg0,arg1,arg2 = bin.unpack('LLLL',result)
        if arg0 == 0 then
            data = string.sub(result, count)
            info, err = parse1443b(data)
        else
            err = 'iso14443b card select failed'
        end
    else
        err = 'No response from card'
    end

    if err then
        print(err)
        return nil, err
    end
    return info
end

---
-- Waits for a mifare card to be placed within the vicinity of the reader.
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
local function waitFor14443b()
    print('Waiting for card... press any key to quit')
    while not core.ukbhit() do
        res, err = read14443b(false)
        if res then return res end
        -- err means that there was no response from card
    end
    return nil, 'Aborted by user'
end

---
-- turns on the HF field.
local function connect14443b()
    local c = Command:newMIX{cmd = cmds.CMD_ISO_14443B_COMMAND, arg1 = ISO14B_COMMAND.ISO14B_CONNECT}
    return c:sendMIX(true)
end
---
-- Sends an instruction to do nothing, only disconnect
local function disconnect14443b()
    local c = Command:newMIX{cmd = cmds.CMD_ISO_14443B_COMMAND, arg1 = ISO14B_COMMAND.ISO14B_DISCONNECT}
    -- We can ignore the response here, no ACK is returned for this command
    -- Check /armsrc/iso14443b.c, ReaderIso14443b() for details
    return c:sendMIX(true)
end

local library = {
    read = read14443b,
    waitFor14443b = waitFor14443b,
    parse1443b  = parse1443b,
    connect = connect14443b,
    disconnect = disconnect14443b,
    ISO14B_COMMAND = ISO14B_COMMAND,
}

return library
