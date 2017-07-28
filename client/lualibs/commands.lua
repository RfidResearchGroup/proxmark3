--[[
Handle Proxmark USB Commands 
--]]

local _commands = require('usb_cmd')

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
		--o.arg1 = "test"
		o.arg1 = o.arg1 or 0
		o.arg2 = o.arg2 or 0
		o.arg3 = o.arg3 or 0 
		local data = o.data or "0"

		if(type(data) == 'string') then
			-- We need to check if it is correct length, otherwise pad it
			local len = string.len(data)
			if(len < 1024) then  
				--Should be 1024 hex characters to represent 512 bytes of data 
				data = data .. string.rep("0",1024 - len ) 
			end
			if(len > 1024) then
				-- OOps, a bit too much data here
				print( ( "WARNING: data size too large, was %s chars, will be truncated "):format(len) )
				--
				data = data:sub(1,1024)
			end
		else 
			print(("WARNING; data was NOT a (hex-) string, but was %s"):format(type(data)))
		end
		o.data = data
		
		return o
	end,
	parse = function (packet)
		local count,cmd,arg1,arg2,arg3,data = bin.unpack('LLLLH512',packet)
		return Command:new{cmd = cmd, arg1 = arg1, arg2 = arg2, arg3 = arg3, data = data}
	end,
}
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
return _commands
