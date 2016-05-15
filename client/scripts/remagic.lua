local getopt = require('getopt')

example = "script run remagic"
author = "Iceman"
desc =
[[
This is a script that tries to bring back a chinese magic card (1k generation1) 
from the dead when it's block 0 has been written with bad values.
or mifare Ultralight magic card which answers to chinese backdoor commands

Arguments:
	-h		this help
	-u		remagic a Ultralight tag w 7 bytes UID.
]]
--- 
-- A debug printout-function
function dbg(args)
	if DEBUG then
		print("###", args)
	end
end 
--- 
-- This is only meant to be used when errors occur
function oops(err)
	print("ERROR: ",err)
end
--- 
-- Usage help
function help()
	print(desc)
	print("Example usage")
	print(example)
end

local function cmdUltralight()
	return {
    --[[
    --]]
	[0] = "hf 14a raw -p -a -b 7 40",
	[1] = "hf 14a raw -p -a 43",
	[2] = "hf 14a raw -c -a A2005380712A",
	[3] = "hf 14a raw -p -a -b 7 40",
	[4] = "hf 14a raw -p -a 43",	
	[5] = "hf 14a raw -c -a A2010200D980",
	[6] = "hf 14a raw -p -a -b 7 40",
	[7] = "hf 14a raw -p -a 43",
	[8] = "hf 14a raw -c -a A2025B480000",
	[9] = "hf 14a raw -c -a 5000",
	}
end
local function cmdClassic()
	return {
    --[[
    --]]
	[0] = "hf 14a raw -p -a -b 7 40",
	[1] = "hf 14a raw -p -a 43",
	[2] = "hf 14a raw -c -p -a A000",
	[3] = "hf 14a raw -c -p -a 01020304049802000000000000001001",
	[4] = "hf 14a raw -c -a 5000",
	}
end
--- 
-- The main entry point
function main(args)

	local i
	local cmds = {}
	local isUltralight = false
	
	-- Read the parameters
	for o, a in getopt.getopt(args, 'hu') do
		if o == "h" then return help() end
		if o == "u" then isUltralight = true end
	end

	core.clearCommandBuffer()
	
	if isUltralight then
		cmds = cmdUltralight()
	else
		cmds = cmdClassic()
	end
	
	for i = 0, #cmds do
		if cmds[i]  then 
			print ( cmds[i] )
			core.console( cmds[i] )
		end
	end
end

main(args)
