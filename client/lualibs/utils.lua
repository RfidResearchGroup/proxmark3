--[[
    This may be moved to a separate library at some point (Holiman)
--]]
local Utils =
{
    -- Asks the user for Yes or No
    confirm = function(message, ...)
        local answer
        message = message .. " [y/n] ?"
        repeat
            io.write(message)
            io.flush()
            answer = io.read()
            if answer == 'Y' or answer == "y" then
                return true
            elseif answer == 'N' or answer == 'n' then
                return false
            end
        until false
    end,
    ---
    -- Asks the user for input
    input = function (message, default)
        local answer = ''
        if default ~= nil then
            message = message .. " (default: ".. default.. " )"
        end
        io.write(message, "\n > ")
        io.flush()
        answer = io.read("*L")
        answer = string.gsub(answer, "\r\n", "")
        answer = string.gsub(answer, "\n", "")
        if answer == '' or answer == nil then answer = default end
        return answer
    end,

    ------------ FILE READING
    ReadDumpFile = function (filename)

        filename = filename or 'dumpdata.bin'
        if #filename == 0 then
            return nil, 'Filename length is zero'
        end

        infile = io.open(filename, "rb")
        if infile == nil then
            return nil, string.format("Could not read file %s",filename)
        end
        local t = infile:read("*all")
        io.close(infile)
        len = string.len(t)
        local  _,hex = bin.unpack(("H%d"):format(len),t)
        return hex
    end,

    ------------ FILE WRITING (EML)
    --- Writes an eml-file.
    -- @param uid - the uid of the tag. Used in filename
    -- @param blockData. Assumed to be on the format {'\0\1\2\3,'\b\e\e\f' ...,
    -- that is, blockData[row] contains a string with the actual data, not ascii hex representation
    -- return filename if all went well,
    -- @reurn nil, error message if unsuccessful
    WriteDumpFile = function(uid, blockData)
        local destination = string.format("%s.eml", uid)
        local file = io.open(destination, "w")
        if file == nil then
            return nil, string.format("Could not write to file %s", destination)
        end
        local rowlen = string.len(blockData[1])

        for i,block in ipairs(blockData) do
            if rowlen ~= string.len(block) then
                prlog(string.format("WARNING: Dumpdata seems corrupted, line %d was not the same length as line 1",i))
            end

            local formatString = string.format("H%d", string.len(block))
            local _,hex = bin.unpack(formatString,block)
            file:write(hex.."\n")
        end
        file:close()
        return destination
    end,

    ------------ string split function
    Split = function( inSplitPattern, outResults )
        if not outResults then
            outResults = {}
        end
        local start = 1
        local splitStart, splitEnd = string.find( self, inSplitPattern, start )
        while splitStart do
            table.insert( outResults, string.sub( self, start, splitStart-1 ) )
            start = splitEnd + 1
            splitStart, splitEnd = string.find( self, inSplitPattern, start )
        end
        table.insert( outResults, string.sub( self, start ) )
        return outResults
    end,

    ----ISO14443-B CRC
    Crc14b = function(s)
        if s == nil then return nil end
        if #s == 0 then return nil end
        if  type(s) == 'string' then
            local utils = require('utils')
            return utils.ConvertAsciiToHex(
                            core.iso14443b_crc(s)
                            )
        end
        return nil
    end,
    ----ISO15693 CRC
    Crc15 = function(s)
        if s == nil then return nil end
        if #s == 0 then return nil end
        if  type(s) == 'string' then
            local utils = require('utils')
            return utils.ConvertAsciiToHex(
                            core.iso15693_crc(s)
                            )
        end
        return nil
    end,

    ------------ CRC-8 Legic checksum
    -- Takes a hex string and calculates a crc8
    Crc8Legic = function(s)
        if s == nil then return nil end
        if #s == 0 then return nil end
        if  type(s) == 'string' then
            local utils = require('utils')
            local asc = utils.ConvertHexToAscii(s)
            return core.crc8legic(asc)
        end
        return nil
    end,
    ------------ CRC-16 Legic checksum
    -- Takes data as hex string, uid hex and calculates a crc16 legic
    Crc16Legic = function(s, uid)
        if s == nil then return nil end
        if #s == 0 then return nil end
        if uid == nil then return nil end
        if #uid == 0 then return nil end

        if  type(s) == 'string' then
            local utils = require('utils')
            local asc = utils.ConvertHexToAscii(s)
            local uidstr = utils.ConvertHexToAscii(uid)
            return core.crc16legic(asc, uidstr)
        end
        return nil
    end,


    ------------ CRC-16 ccitt checksum
    -- Takes a hex string and calculates a crc16
    Crc16 = function(s)
        if s == nil then return nil end
        if #s == 0 then return nil end
        if  type(s) == 'string' then
            local utils = require('utils')
            local asc = utils.ConvertHexToAscii(s)
            local hash = core.crc16(asc)
            return hash
        end
        return nil
    end,


    ------------ CRC-64 ecma checksum
    -- Takes a hex string and calculates a crc64 ecma hash
    Crc64 = function(s)
        if s == nil then return nil end
        if #s == 0 then return nil end
        if  type(s) == 'string' then
            local utils = require('utils')
            local asc = utils.ConvertHexToAscii(s)
            local hash = core.crc64(asc)
            return hash
        end
        return nil
    end,
    ------------ CRC-64 ecma 182 checksum
    -- Takes a hex string and calculates a crc64 ecma182 hash
    Crc64_ecma182 = function(s)
        if s == nil then return nil end
        if #s == 0 then return nil end
        if  type(s) == 'string' then
            local utils = require('utils')
            local asc = utils.ConvertHexToAscii(s)
            local hash = core.crc64_ecma182(asc)
            return hash
        end
        return nil
    end,

    ------------ SHA1 hash
    -- Takes a string and calculates a SHA1 hash
    Sha1 = function(s)
        if s == nil then return nil end
        if #s == 0 then return nil end
        if  type(s) == 'string' then
            return core.sha1(s)
        end
        return nil
    end,
    -- Takes a hex string and calculates a SHA1 hash
    Sha1Hex = function(s)
        if s == nil then return nil end
        if #s == 0 then return nil end
        if  type(s) == 'string' then
            local utils = require('utils')
            local asc = utils.ConvertHexToAscii(s)
            local hash = core.sha1(asc)
            return hash
        end
        return nil
    end,


    -- input parameter is a string
    -- Swaps the endianness and returns a number,
    -- IE:  'cd7a' -> '7acd'  -> 0x7acd
    SwapEndianness = function(s, len)
        if s == nil then return nil end
        if #s == 0 then return '' end
        if  type(s) ~= 'string' then return nil end

        local retval = 0
        if len == 16 then
            local t = s:sub(3,4)..s:sub(1,2)
            retval = tonumber(t,16)
        elseif len == 24 then
            local t = s:sub(5,6)..s:sub(3,4)..s:sub(1,2)
            retval = tonumber(t,16)
        elseif len == 32 then
            local t = s:sub(7,8)..s:sub(5,6)..s:sub(3,4)..s:sub(1,2)
            retval = tonumber(t,16)
        end
        return retval
    end,

    -- input parameter is a string
    -- Swaps the endianness and returns a string,
    -- IE:  'cd7a' -> '7acd'  -> 0x7acd
    SwapEndiannessStr = function(s, len)
        if s == nil then return nil end
        if #s == 0 then return '' end
        if  type(s) ~= 'string' then return nil end

        local retval
        if len == 16 then
            retval = s:sub(3,4)..s:sub(1,2)
        elseif len == 24 then
            retval = s:sub(5,6)..s:sub(3,4)..s:sub(1,2)
        elseif len == 32 then
            retval = s:sub(7,8)..s:sub(5,6)..s:sub(3,4)..s:sub(1,2)
        end
        return retval
    end,
    ------------ CONVERSIONS

    --
    -- Converts DECIMAL to HEX
    ConvertDecToHex = function(IN)
        local B,K,OUT,I,D = 16, "0123456789ABCDEF", "", 0
        while IN > 0 do
            I = I+1
            IN, D = math.floor(IN/B), math.modf(IN, B) + 1
            OUT = string.sub(K, D, D)..OUT
        end
        return OUT
    end,
    ---
    -- Convert Byte array to string of hex
    ConvertBytesToHex = function(bytes, reverse)
        if bytes == nil then return '' end
        if #bytes == 0 then return '' end
        local s={}
        if reverse then
            local j=1
            for i = #bytes, 1, -1 do
                s[i] = string.format("%02X", bytes[j])
                j = j + 1
            end
        else
            for i = 1, #bytes do
                s[i] = string.format("%02X", bytes[i])
            end
        end
        return table.concat(s)
    end,
    -- Convert byte array to string with ascii
    ConvertBytesToAscii = function(bytes)
        if bytes == nil then return '' end
        if #bytes == 0 then return '' end
        local s={}
        for i = 1, #(bytes) do
            s[i] = string.char(bytes[i])
        end
        return table.concat(s)
    end,
    ConvertHexToBytes = function(s)
        local t={}
        if s == nil then return t end
        if #s == 0 then return t end
        for k in s:gmatch"(%x%x)" do
            table.insert(t,tonumber(k,16))
        end
        return t
    end,
    ConvertAsciiToBytes = function(s, reverse)
        local t = {}
        if s == nil then return t end
        if #s == 0 then return t end

        for k in s:gmatch"(.)" do
            table.insert(t, string.byte(k))
        end

        if not reverse then
            return t
        end

        local rev = {}
        if reverse then
            for i = #t, 1,-1 do
                table.insert(rev, t[i] )
            end
        end
        return rev
    end,

    ConvertHexToAscii = function(s, useSafechars)
        if s == nil then return '' end
        if #s == 0 then return '' end
        local t={}
        for k in s:gmatch"(%x%x)" do

            local n = tonumber(k,16)
            local c
            if useSafechars and ( (n < 32) or (n == 127) ) then
                c = '.';
            else
                c = string.char(n)
            end
            table.insert(t,c)
        end
        return table.concat(t)
    end,

    ConvertAsciiToHex = function(s)
        if s == nil then return '' end
        if #s == 0 then return '' end
        local t={}
        for k in s:gmatch"(.)" do
            table.insert(t, string.format("%02X", string.byte(k)))
        end
        return table.concat(t)
    end,

    hexlify = function(s)
        local u = require('utils')
        return u.ConvertAsciiToHex(s)
    end,

    Chars2num = function(s)
        return (s:byte(1)*16777216)+(s:byte(2)*65536)+(s:byte(3)*256)+(s:byte(4))
    end,

    -- use length of string to determine 8,16,32,64 bits
    bytes_to_int = function(str,endian,signed)
        local t = {str:byte(1, -1)}
        if endian == "big" then --reverse bytes
            local tt = {}
            for k = 1, #t do
                tt[#t-k+1] = t[k]
            end
            t = tt
        end
        local n = 0
        for k = 1, #t do
            n = n + t[k] * 2^((k-1) * 8)
        end
        if signed then
            n = (n > 2^(#t*8-1) -1) and (n - 2^(#t*8)) or n -- if last bit set, negative.
        end
        return n
    end,

    -- a simple implementation of a sleep command. Thanks to Mosci
    -- takes number of seconds to sleep
    Sleep = function(n)
        local clock = os.clock
        local t0 = clock()
        while clock() - t0 <= n do end
        return nil
    end,

    -- function convertStringToBytes(str)
    -- local bytes = {}
    -- local strLength = string.len(str)
    -- for i=1,strLength do
        -- table.insert(bytes, string.byte(str, i))
    -- end

    -- return bytes
-- end

-- function convertBytesToString(bytes)
    -- local bytesLength = table.getn(bytes)
    -- local str = ""
    -- for i=1,bytesLength do
        -- str = str .. string.char(bytes[i])
    -- end

    -- return str
-- end

-- function convertHexStringToBytes(str)
    -- local bytes = {}
    -- local strLength = string.len(str)
    -- for k=2,strLength,2 do
        -- local hexString = "0x" .. string.sub(str, (k - 1), k)
        -- table.insert(bytes, hex.to_dec(hexString))
    -- end

    -- return bytes
-- end

-- function convertBytesToHexString(bytes)
    -- local str = ""
    -- local bytesLength = table.getn(bytes)
    -- for i=1,bytesLength do
        -- local hexString = string.sub(hex.to_hex(bytes[i]), 3)
        -- if string.len(hexString) == 1 then
            -- hexString = "0" .. hexString
        -- end
        -- str = str .. hexString
    -- end

    -- return str
-- end

}
return Utils
