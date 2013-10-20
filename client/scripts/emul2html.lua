-- The getopt-functionality is loaded from pm3/getopt.lua
-- Have a look there for further details
getopt = require('getopt')
bin = require('bin')
dumplib = require('html_dumplib')

example = "script run emul2html -o dumpdata.eml "
author = "Martin Holst Swende"
usage = "script run htmldump [-i <file>] [-o <file>]"
desc =[[
This script takes a dumpfile on EML (ASCII) format and produces a html based dump, which is a 
bit more easily analyzed. 

Arguments:
	-h 				This help
	-i <file>		Specifies the dump-file (input). If omitted, 'dumpdata.eml' is used	
	-o <filename>	Speciies the output file. If omitted, <curdate>.html is used. 	

]]

-------------------------------
-- Some utilities 
-------------------------------

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

local function main(args)

	local input = "dumpdata.eml"
	local output = os.date("%Y-%m-%d_%H%M%S.html");
	for o, a in getopt.getopt(args, 'i:o:h') do
		if o == "h" then return help() end		
		if o == "i" then input = a end
		if o == "o" then output = a end
	end
	local filename, err = dumplib.convert_eml_to_html(input,output)
	if err then return oops(err) end

	print(("Wrote a HTML dump to the file %s"):format(filename))
end

--[[
In the future, we may implement so that scripts are invoked directly 
into a 'main' function, instead of being executed blindly. For future
compatibility, I have done so, but I invoke my main from here.  
--]]
main(args)