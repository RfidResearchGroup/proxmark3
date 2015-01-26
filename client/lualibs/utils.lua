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
			answer=io.read()
			if answer == 'Y' or answer == "y" then
				return true
			elseif answer == 'N' or answer == 'n' then 
				return false
			end
		until false
	end,
	---
	-- Asks the user for input
	input = function (message , default)
		local answer
		if default ~= nil then
			message = message .. " (default: ".. default.. " )"
		end
		message = message .." \n > "
		io.write(message)
		io.flush()
		answer=io.read()
		if answer == '' then answer = default end

		return answer
	end,
	
	------------ FILE READING
	ReadDumpFile = function (filename)
	
		if filename == nil then 
			return nil, 'Filename is empty'
		end
		if #filename == 0 then
			return nil, 'Filename length is zero'
		end

		infile = io.open(filename, "rb")
		if infile == nil then 
			return nil, string.format("Could not read file %s",filename)
		end
		local t = infile:read("*all")
		len = string.len(t)
		local  _,hex = bin.unpack(("H%d"):format(len),t)
		io.close(infile)
		return hex
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
	
	------------ CRC-16 ccitt checksums
	
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

	-- input parameter is a string
	-- Swaps the endianess and returns a number,  
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
	-- Swaps the endianess and returns a string,  
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
		local B,K,OUT,I,D=16,"0123456789ABCDEF","",0
		while IN>0 do
			I=I+1
			IN , D = math.floor(IN/B), math.modf(IN,B)+1
			OUT=string.sub(K,D,D)..OUT
		end
		return OUT
	end,
	---
	-- Convert Byte array to string of hex
	ConvertBytesToHex = function(bytes)
		if #bytes == 0 then
			return ''
		end
		local s={}
		for i = 1, #(bytes) do
			s[i] =   string.format("%02X",bytes[i]) 
		end
		return table.concat(s)
	end,	
	-- Convert byte array to string with ascii
    ConvertBytesToAscii = function(bytes)
		if #bytes == 0 then
			return ''
		end
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
	ConvertAsciiToBytes = function(s)
		local t={}
		if s == nil then return t end
		if #s == 0 then return t end
		
		for k in s:gmatch"(.)" do
			table.insert(t, string.byte(k))
		end
		return t
	end,
	ConvertHexToAscii = function(s)
		local t={}
		if s == nil then return t end
		if #s == 0 then return t end
		for k in s:gmatch"(%x%x)" do
			table.insert(t, string.char(tonumber(k,16)))
		end
		return  table.concat(t)	
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