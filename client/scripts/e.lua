local getopt = require('getopt')
local utils = require('utils')

example = "script calculates many checksums (CRC) over the provided hex input"
author = "Iceman"
desc =
[[
This script calculates many checksums (CRS) over the provided hex input. 

Arguments:
	-b 				data in hex
	-w				width of the CRC algorithm. <optional> defaults to all known CRC presets.
Examples : 
	script run e -b 010203040506070809
	script run e -b 010203040506070809 -w 16
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
	return nil,err
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

	local data = '01020304'
	local width = 0

	-- Read the parameters
	for o, a in getopt.getopt(args, 'hb:w:') do
		if o == "h" then return help() end
		if o == "b" then data = utils.ConvertHexToa end
		if o == "w" then width = a end
	end

	print('Width of CRC: '..width..'  bytes: '..data)
	print('')
	print('Model','CRC', 'CRC_Reverse')
	
	local lists = core.reveng_models(width)
	for _,i in pairs(lists) do
		local one = core.reveng_runmodel(i, data, 0,0)
		local two = core.reveng_runmodel(i, data, 1,0)
		
		print(i, one, two)
	end
	
	if 1 == 1 then
	 return
	end 
end

main(args)