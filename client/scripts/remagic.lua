local getopt = require('getopt')

example = "script run remagic"
author = "Iceman"

desc =
[[
This is a script that tries to bring back a chinese magic card (1k generation1) 
from the dead when it's block 0 has been written with bad values.

Arguments:
	-h 		this help
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

--- 
-- The main entry point
function main(args)

	
	-- Read the parameters
	for o, a in getopt.getopt(args, 'h') do
		if o == "h" then help() return end
	end
	
	local _cmds = {
    --[[
    --]]
	[0] = "hf 14a raw -p -a -b 7 40",
	[1] = "hf 14a raw -p -a 43",
	[2] = "hf 14a raw -c -p -a A000",
	[3] = "hf 14a raw -c -p -a 01 02 03 04 04 98 02 00 00 00 00 00 00 00 10 01",
	}
	core.clearCommandBuffer()
	
	local i
	--for _,c in pairs(_cmds) do 
	for i = 0, 3 do
	    print ( _cmds[i] )
		core.console( _cmds[i] )
	end
end

main(args)
