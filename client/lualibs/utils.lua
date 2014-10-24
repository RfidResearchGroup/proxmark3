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
		s = {}
		for i = 1, #(bytes) do
			s[i] =   string.format("%02X",bytes[i]) 
		end
		return table.concat(s)
	end,	
}
return Utils