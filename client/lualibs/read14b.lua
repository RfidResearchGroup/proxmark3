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
local TIMEOUT = 1000

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
    ISO14B_SEND_CHAINING = 0x200,
    ISO14B_SELECT_CTS = 0x400,
    ISO14B_CLEARTRACE = 0x800,
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
---    local count, uid, uidlen, atqb, chipid, cid = bin.unpack('H10CH7CC',data)
    --]]

    local uid = data:sub(1, 20)
    local uidlen = data:sub(21, 22)
    local atqb = data:sub(23, 36)
    local chipid = data:sub(37, 38)
    local cid = data:sub(39, 40)

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
    local flags = ISO14B_COMMAND.ISO14B_CONNECT +
                  ISO14B_COMMAND.ISO14B_SELECT_STD

    if disconnect then
        print('DISCONNECT')
        flags = flags + ISO14B_COMMAND.ISO14B_DISCONNECT
    end

    local flags_str  = ('%04x'):format(utils.SwapEndianness(('%04x'):format(flags), 16))
    local time_str  =  ('%08x'):format(0)
    local rawlen_str = ('%04x'):format(0)
    local senddata = ('%s%s%s'):format(flags_str, time_str, rawlen_str)
    local c = Command:newNG{cmd = cmds.CMD_HF_ISO14443B_COMMAND, data = senddata}

    local info = nil
    local result, err = c:sendNG(false, TIMEOUT)
    if result and result.Status == 0 then
        if result.Oldarg0 == 0 then
            info, err = parse14443b(result.Data)
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
-- turns on the HF field.
local function connect14443b()
    local data  = ('%04x%08x%04x'):format(utils.SwapEndianness(('%04x'):format(ISO14B_COMMAND.ISO14B_CONNECT), 16), 0,0)
    local c = Command:newNG{cmd = cmds.CMD_HF_ISO14443B_COMMAND, data = data}
    return c:sendNG(true)
end
---
-- Sends an instruction to do nothing, only disconnect
local function disconnect14443b()
    local data  = ('%04x%08x%04x'):format(utils.SwapEndianness(('%04x'):format(ISO14B_COMMAND.ISO14B_DISCONNECT), 16), 0,0)
    local c = Command:newNG{cmd = cmds.CMD_HF_ISO14443B_COMMAND, data = data}
    -- We can ignore the response here, no ACK is returned for this command
    -- Check /armsrc/iso14443b.c, ReaderIso14443b() for details
    return c:sendNG(true)
end
---
-- Waits for a mifare card to be placed within the vicinity of the reader.
-- @return if successful: an table containing card info
-- @return if unsuccessful : nil, error
local function waitFor14443b()
    print('Waiting for card... press <Enter> to quit')
    while not core.kbd_enter_pressed() do
        res, err = read14443b(false)
        if res then return res, err end
        -- err means that there was no response from card
    end
    disconnect14443b()
    return nil, 'Aborted by user'
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
