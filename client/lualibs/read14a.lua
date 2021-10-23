--[[
    This is a library to read 14443a tags. It can be used something like this

    local reader = require('read14a')
    result, err = reader.read14443a()
    if not result then
        print(err)
        return
    end
    print(result.name)

--]]
-- Loads the commands-library
local taglib = require('taglib')
local cmds = require('commands')

-- Shouldn't take longer than 2 seconds
local TIMEOUT = 2000

local ISO14A_COMMAND = {
    ISO14A_CONNECT = 1,
    ISO14A_NO_DISCONNECT = 2,
    ISO14A_APDU = 4,
    ISO14A_RAW = 8,
    ISO14A_REQUEST_TRIGGER = 0x10,
    ISO14A_APPEND_CRC = 0x20,
    ISO14A_SET_TIMEOUT = 0x40,
    ISO14A_NO_SELECT = 0x80,
    ISO14A_TOPAZMODE = 0x100,
    ISO14A_NO_RATS = 0x200,
    ISO14A_SEND_CHAINING = 0x400,
    ISO14A_USE_ECP = 0x800,
    ISO14A_USE_MAGSAFE = 0x1000,
}

local ISO14443a_TYPES = {}
ISO14443a_TYPES[0x00] = "NXP MIFARE Ultralight | Ultralight C | NTAG"
ISO14443a_TYPES[0x01] = "NXP MIFARE TNP3xxx Activision Game Appliance"
ISO14443a_TYPES[0x04] = "NXP MIFARE (various !DESFire !DESFire EV1)"
ISO14443a_TYPES[0x08] = "NXP MIFARE CLASSIC 1k | Plus 2k"
ISO14443a_TYPES[0x09] = "NXP MIFARE Mini 0.3k"
ISO14443a_TYPES[0x0A] = "FM11RF005SH (Shanghai Metro)"
ISO14443a_TYPES[0x10] = "NXP MIFARE Plus 2k"
ISO14443a_TYPES[0x11] = "NXP MIFARE Plus 4k"
ISO14443a_TYPES[0x18] = "NXP MIFARE Classic 4k | Plus 4k"
ISO14443a_TYPES[0x20] = "NXP MIFARE DESFire 4k | DESFire EV1 2k/4k/8k | Plus 2k/4k | JCOP 31/41"
ISO14443a_TYPES[0x24] = "NXP MIFARE DESFire | DESFire EV1"
ISO14443a_TYPES[0x28] = "JCOP31 or JCOP41 v2.3.1"
ISO14443a_TYPES[0x38] = "Nokia 6212 or 6131 MIFARE CLASSIC 4K"
ISO14443a_TYPES[0x88] = "Infineon MIFARE CLASSIC 1K"
ISO14443a_TYPES[0x98] = "Gemplus MPCOS"

local function tostring_14443a(sak)
    return ISO14443a_TYPES[sak] or ("Unknown (SAK=%x)"):format(sak)
end

local function parse14443a(data)
    --[[
    typedef struct {
        uint8_t uid[10];
        uint8_t uidlen;
        uint8_t atqa[2];
        uint8_t sak;
        uint8_t ats_len;
        uint8_t ats[256];
    } PACKED iso14a_card_select_t;
    --]]

    local count, uid, uidlen, atqa, sak, ats_len, ats = bin.unpack('H10CH2CCH', data)
    uid = uid:sub(1, 2 * uidlen)
    local man_byte = tonumber(uid:sub(1,2), 16)

    return {
        uid = uid,
        atqa  = atqa,
        sak = sak,
        name = tostring_14443a(sak),
        data = data,
        manufacturer = taglib.lookupManufacturer(man_byte),
        ats = ats
    }
end

-- This function does a connect and retrieves som einfo
-- @param dont_disconnect - if true, does not disable the field
-- @return if successful: an table containing card info
-- @return if unsuccessful : nil, error
local function read14443a(dont_disconnect, no_rats)
    local command, result, info, err, data

    command = Command:newMIX{
            cmd = cmds.CMD_HF_ISO14443A_READER,
            arg1 = ISO14A_COMMAND.ISO14A_CONNECT
            }

    if dont_disconnect then
        command.arg1 = command.arg1 + ISO14A_COMMAND.ISO14A_NO_DISCONNECT
    end
    if no_rats then
        command.arg1 = command.arg1 + ISO14A_COMMAND.ISO14A_NO_RATS
    end

    local result, err = command:sendMIX()
    if result then
        local count, cmd, arg1, arg2, arg3 = bin.unpack('LLLL',result)
        if arg1 == 0 then
            return nil, 'iso14443a card select failed'
        end
        data = string.sub(result, count)
        info = parse14443a(data)
    else
        err = 'No response from card'
    end

    if err then
        print(err)
        return nil, err
    end
    return info, nil
end

---
-- Waits for a mifare card to be placed within the vicinity of the reader.
-- @return if successful: an table containing card info
-- @return if unsuccessful : nil, error
local function waitFor14443a()
    print('Waiting for card... press Enter to quit')
    while not core.kbd_enter_pressed() do
        res, err = read14443a()
        if res then return res end
        -- err means that there was no response from card
    end
    return nil, 'Aborted by user'
end

-- Sends an instruction to do nothing, only disconnect
local function disconnect14443a()
    local c = Command:newMIX{cmd = cmds.CMD_HF_ISO14443A_READER}
    -- We can ignore the response here, no ACK is returned for this command
    -- Check /armsrc/iso14443a.c, ReaderIso14443a() for details
    return c:sendMIX(true)
end

local library = {
    read = read14443a,
    waitFor14443a = waitFor14443a,
    parse14443a = parse14443a,
    disconnect = disconnect14443a,
    ISO14A_COMMAND = ISO14A_COMMAND,
}

return library
