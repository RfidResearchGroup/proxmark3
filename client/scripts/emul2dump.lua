local getopt = require('getopt')
local bin = require('bin')
local dumplib = require('html_dumplib')

example =[[
	1. script run emul2dump
	2. script run emul2dump -i myfile.eml
	3. script run emul2dump -i myfile.eml -o myfile.bin
]]
author = "Iceman"
usage = "script run emul2dump [-i <file>] [-o <file>]"
desc =[[
This script takes an dumpfile on EML (ASCII) format and converts it to the PM3 dumpbin file to be used with "hf mf restore"

Arguments:
	-h              This help
	-i <filename>	Specifies the dump-file (input). If omitted, 'dumpdata.eml' is used	
	-o <filename>	Specifies the output file. If omitted, <currdate>.bin is used. 	
]]

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
--
-- Exit message
function ExitMsg(msg)
	print( string.rep('--',20) )
	print( string.rep('--',20) )
	print(msg)
	print()
end

local function main(args)
	
	local input = "dumpdata.eml"
	local output  = os.date("%Y-%m-%d_%H%M%S.bin");
	
	-- Arguments for the script
	for o, a in getopt.getopt(args, 'hi:o:') do
		if o == "h" then return help() end		
		if o == "i" then input = a	end
		if o == "o" then output = a end
	end

	local filename, err = dumplib.convert_eml_to_bin(input,output)
	if err then return oops(err) end

	ExitMsg(("Wrote a BIN dump to the file %s"):format(filename))
end

main(args)