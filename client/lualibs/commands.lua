--[[
Handle Proxmark Communication Commands
--]]

local _commands = require('pm3_cmd')
local util = require('utils')
local TIMEOUT = 2000

local _reverse_lookup,k,v = {}
    for k, v in pairs(_commands) do
        _reverse_lookup[v] =  k
    end
    _commands.tostring = function(command)
    if(type(command) == 'number') then
        return ("%s (%d)"):format(_reverse_lookup[command]or "ERROR UNDEFINED!", command)
    end
    return ("Error, numeric argument expected, got : %s"):format(tostring(command))
end

Command = {

    new = function(self, o)

        local o = o or {}   -- create object if user does not provide one
        setmetatable(o, self) -- DIY inheritance a'la javascript
        self.__index = self

        o.cmd = o.cmd or _commands.CMD_UNKNOWN
        o.arg1 = o.arg1 or 0
        o.arg2 = o.arg2 or 0
        o.arg3 = o.arg3 or 0
        local data = o.data or "0"

        if (type(data) == 'string') then
            -- We need to check if it is correct length, otherwise pad it
            local len = #data
            if (len < 1024) then
                --Should be 1024 hex characters to represent 512 bytes of data
                data = data .. string.rep("0",1024 - len )
            end
            if (len > 1024) then
                -- OOps, a bit too much data here
                print( ( "WARNING: data size too large, was %s chars, will be truncated "):format(len) )
                --
                data = data:sub(1, 1024)
            end
        else
            print(("WARNING; data was NOT a (hex-) string, but was %s"):format(type(data)))
        end
        o.data = data
        return o
    end,
    newNG = function(self, o)

        local o = o or {}   -- create object if user does not provide one
        setmetatable(o, self) -- DIY inheritance a'la javascript
        self.__index = self

        o.cmd = o.cmd or _commands.CMD_UNKNOWN
        local data = o.data or ''

        if (type(data) == 'string') then
            if (#data > 1024) then
                -- OOps, a bit too much data here
                print( ( "WARNING: data size too large, was %s chars, will be truncated "):format( #data) )
                --
                data = data:sub(1, 1024)
            end
        end
        o.data = data
        return o
    end,
}
-- commented out,  not used.
function Command:__tostring()
    local output = ("%s\r\nargs : (%s, %s, %s)\r\ndata:\r\n%s\r\n"):format(
        _commands.tostring(self.cmd),
        tostring(self.arg1),
        tostring(self.arg2),
        tostring(self.arg3),
        tostring(self.data))
    return output
end








--- Raw command support, uniform across card technologies.
--
-- The device takes a different struct per technology, but the Lua side is the
-- same for all of them. Build with Command:newRaw{} using these named fields:
--
--   tech     '14a' | '14b' | '15'      which technology
--   flags    transport flag bitmask    (ISO14A_* / ISO14B_* / ISO15_*)
--   data     payload as a hex string   optional, defaults to empty
--   timeout  device-side timeout       14a and 14b only, ignored for 15
--   wait_us  pre-transmit delay        14a only, ignored elsewhere
--   lenbits  send this many bits       14a only, ignored elsewhere
--
-- The payload length is always derived from `data`, never passed separately.
--
-- On the wire these become, little endian:
--   14a  iso14a_raw_cmd_t  u32 flags, u32 timeout, u32 wait_us, u16 len, u16 lenbits, u8 data[]
--   14b  iso14b_raw_cmd_t  u16 flags, u32 timeout, u16 rawlen, u8 raw[]
--   15   iso15_raw_cmd_t   u8  flags, u16 rawlen, u8 raw[]

--- hex string -> raw byte string
function fromhex(hexstr)
    return (hexstr:gsub('%x%x', function(cc) return string.char(tonumber(cc, 16)) end))
end

--- raw byte string -> uppercase hex string
function tohex(raw)
    return (raw:gsub('.', function(c) return string.format('%02X', string.byte(c)) end))
end

-- little endian hex for a value of n bytes
local function le(value, nbytes)
    local out = ''
    local v = value or 0
    for _ = 1, nbytes do
        out = out .. string.format('%02X', v % 256)
        v = math.floor(v / 256)
    end
    return out
end

local RAW_CMD = {
    ['14a'] = _commands.CMD_HF_ISO14443A_READER,
    ['14b'] = _commands.CMD_HF_ISO14443B_COMMAND,
    ['15']  = _commands.CMD_HF_ISO15693_COMMAND,
}

--- Build a raw command for any of 14a / 14b / 15.
-- @return a Command ready for :sendNG()
function Command:newRaw(o)
    o = o or {}
    local tech = o.tech or '14a'
    local cmd = RAW_CMD[tech]
    if cmd == nil then
        error('Command:newRaw - unknown tech "'..tostring(tech)..'", expected 14a, 14b or 15')
    end

    local data = o.data or ''
    local len = #data / 2

    local hdr
    if tech == '14a' then
        hdr = le(o.flags, 4) .. le(o.timeout, 4) .. le(o.wait_us, 4) .. le(len, 2) .. le(o.lenbits, 2)
    elseif tech == '14b' then
        hdr = le(o.flags, 2) .. le(o.timeout, 4) .. le(len, 2)
    else
        hdr = le(o.flags, 1) .. le(len, 2)
    end

    local c = Command:newNG{ cmd = cmd, data = hdr .. data }
    c.tech = tech
    return c
end

--- Unpack the reply to a raw command, uniform across technologies.
-- @param tech  '14a' | '14b' | '15'
-- @param resp  the table returned by :sendNG()
-- @return len, extra, data
--         len   number of payload bytes
--         extra 14a: the select status on a CONNECT, otherwise nil
--         data  payload as a raw byte string (use tohex() to print it)
function parseRaw(tech, resp)
    if resp == nil or type(resp) ~= 'table' or resp.Data == nil then
        return nil, nil, nil
    end
    if tech == '14a' then
        -- iso14a_raw_resp_t: u16 len, u8 sel, u8 rfu, u8 data[]
        if #resp.Data < 8 then return nil, nil, nil end
        local len = tonumber(resp.Data:sub(1, 2), 16) + (tonumber(resp.Data:sub(3, 4), 16) * 256)
        local sel = tonumber(resp.Data:sub(5, 6), 16)
        return len, sel, fromhex(resp.Data:sub(9, 8 + (len * 2)))
    end
    -- 14b and 15 answer with the payload only
    return resp.Length, nil, fromhex(resp.Data:sub(1, resp.Length * 2))
end

function Command:sendNG( ignore_response, timeout )
    if timeout == nil then timeout = TIMEOUT end
    local data = self.data
    local cmd = self.cmd
    local err, msg = core.SendCommandNG(cmd, data)
    if err == nil then return nil, msg end

    if ignore_response then return true, nil end
    local response, msg = core.WaitForResponseTimeout(cmd, timeout)
    if response == nil then
        return nil, 'Error, waiting for response timed out :: '..msg
    end

    data = nil
    cmd = nil
    local count, length, magic, status, reason, crc

    count, cmd, length, magic, status, reason, crc = bin.unpack('SSIccS', response)
    count, data, ng = bin.unpack('H'..length..'C', response, count)

--[[  uncomment if you want to debug
    print('NG package received')
    print('CMD    ::', tostring(cmd))
    print('Length ::', tostring(length))
    print('Magic  ::', string.format("0x%08X", magic), util.ConvertHexToAscii(string.format("0x%08X", magic)))
    print('Status ::', tostring(status))
    print('crc    ::', string.format("0x%02X", crc))
    print('NG     ::', ng)
    print('Data   ::', data)
--]]
    return { Cmd = cmd,
            Length = length,
            Magic = magic,
            Status = status,
            Reason = reason,
            Crc = crc,
            Data = data,
            Ng = ng
    }
end

return _commands
