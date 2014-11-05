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
	--
	-- Converts DECIMAL to HEX
    ConvertDec2Hex = function(IN)
		local B,K,OUT,I,D=16,"0123456789ABCDEF","",0
		while IN>0 do
			I=I+1
			IN,D=math.floor(IN/B),math.mod(IN,B)+1
			OUT=string.sub(K,D,D)..OUT
		end
		return OUT
	end,
	---
	-- Convert Byte array to string of hex
	ConvertBytes2String = function(bytes)
		local s = {}
		for i = 1, #(bytes) do
			s[i] = string.format("%02X",bytes[i]) 
		end
		return table.concat(s)
	end,	

	ConvertStringToBytes = function(s)
		local t={}
		for k in s:gmatch"(%x%x)" do
			table.insert(t,tonumber(k,16))
		end
		return t
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