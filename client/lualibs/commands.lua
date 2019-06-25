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
    newMIX = function(self, o)

        local o = o or {}   -- create object if user does not provide one
        setmetatable(o, self) -- DIY inheritance a'la javascript
        self.__index = self

        o.cmd = o.cmd or _commands.CMD_UNKNOWN
        o.arg1 = o.arg1 or 0
        o.arg2 = o.arg2 or 0
        o.arg3 = o.arg3 or 0
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
    parse = function (packet)
            local count, cmd, arg1, arg2, arg3, data = bin.unpack('LLLLH511', packet)
            return Command:new{cmd = cmd, arg1 = arg1, arg2 = arg2, arg3 = arg3, data = data}
    end
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

function Command:getBytes()
    --If a hex-string has been used
    local data  = self.data
    local cmd = self.cmd
    local arg1, arg2, arg3 = self.arg1, self.arg2, self.arg3
    return bin.pack("LLLLH",cmd, arg1, arg2, arg3, data);
end

--- Sends a packet to the device
-- @param command - the usb packet to send
-- @param ignoreresponse - if set to true, we don't read the device answer packet
--     which is usually recipe for fail. If not sent, the host will wait 2s for a
--     response of type CMD_ACK
-- @return packet,nil if successfull
--         nil, errormessage if unsuccessfull
function Command:sendMIX( ignore_response, timeout )
    local data = self.data
    local cmd = self.cmd
    local arg1, arg2, arg3 = self.arg1, self.arg2, self.arg3

    local err, msg = core.SendCommandMIX(cmd, arg1, arg2, arg3, data)
    if err == nil then return err, msg end

    if ignore_response then return true, nil end

    if timeout == nil then timeout = TIMEOUT end

    local response, msg = core.WaitForResponseTimeout(_commands.CMD_ACK, timeout)
    if response == nil then
        return nil, 'Error, waiting for response timed out :: '..msg
    end

    -- lets digest
    data = nil
    cmd = nil
    arg1 = nil
    arg2 = nil
    arg3 = nil
    local count, length, magic, status, crc, ng

--         S    S       I      s       S    L     L     L
    count, cmd, length, magic, status, crc, arg1, arg2, arg3 = bin.unpack('SSIsSLLL', response)
    count, data, ng = bin.unpack('H'..length..'C', response, count)

    local packed = bin.pack("LLLLH", cmd, arg1, arg2, arg3, data)
    return packed, nil;
end
function Command:sendNG( ignore_response, timeout )
    local data = self.data
    local cmd = self.cmd
    local err, msg = core.SendCommandNG(cmd, data)
    if err == nil then return nil, msg end

    if ignore_response then return true, nil end

    if timeout == nil then timeout = TIMEOUT end

    local response, msg = core.WaitForResponseTimeout(cmd, timeout)
    if response == nil then
        return nil, 'Error, waiting for response timed out :: '..msg
    end

    data = nil
    cmd = nil
    local count, length, magic, status, crc, arg0, arg1, arg2

    count, cmd, length, magic, status, crc, arg0, arg1, arg2 = bin.unpack('SSIsSLLL', response)
    count, data, ng = bin.unpack('H'..length..'C', response, count)

--[[  uncomment if you want to debug

    print('NG package received')
    print('CMD    ::', tostring(cmd))
    print('Length ::', tostring(length))
    print('Magic  ::', string.format("0x%08X", magic), util.ConvertHexToAscii(string.format("0x%08X", magic)))
    print('Status ::', tostring(status))
    print('crc    ::', string.format("0x%02X", crc))
    print('Args   ::', ("(%s, %s, %s)\r\n"):format(
                    tostring(arg0),
                    tostring(arg1),
                    tostring(arg2)))
    print('NG     ::', ng)
    print('Data   ::', data)
--]]
    return { Cmd = cmd,
            Length = length,
            Magic = magic,
            Status = status,
            Crc = crc,
            Oldarg0 = arg0,
            Oldarg1 = arg1,
            Oldarg2 = arg2,
            Data = data,
            Ng = ng
    }
end

return _commands
