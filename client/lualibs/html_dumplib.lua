bin = require('bin')


-------------------------------
-- Some utilities 
-------------------------------

--- 
-- A debug printout-function
local function dbg(args)
	
    if type(args) == "table" then
		local i = 1
		while args[i] do
			print("###", args[i])
			i = i+1
		end
	else
		print("###", args)
	end	
end	
--- 
-- This is only meant to be used when errors occur
local function oops(err)
	print("ERROR: ",err)
	return nil, err
end

local function save_HTML(javascript, filename)

	-- Read the HTML-skel file
	local skel = require("htmlskel")
	html = skel.getHTML(javascript);

	-- Open the output file
	
	local outfile = io.open(filename, "w")
	if outfile == nil then 
		return oops(string.format("Could not write to file %s",tostring(filename)))
	end
	-- Write the data into it
	outfile:write(html)
	io.close(outfile)

	-- Done
	return filename

end

local function save_TEXT(data,filename)
	-- Open the output file
	local outfile = io.open(filename, "w")
	if outfile == nil then 
		return oops(string.format("Could not write to file %s",tostring(filename)))
	end
	
	outfile:write(data)
	io.close(outfile)
	return filename   
end

local function save_BIN(data, filename)
	-- Open the output file
	
	local outfile = io.open(filename, "wb")
	if outfile == nil then 
		return oops(string.format("Could not write to file %s",tostring(filename)))
	end
	
	-- Write the data into it
	local i = 1
	while data[i] do
		outfile:write(data[i])
		i = i+1
	end
	
	io.close(outfile)
	return filename   
end

local function convert_ascii_dump_to_JS(infile)
	local t = infile:read("*all")
	
	local output = "[";
	for line in string.gmatch(t, "[^\n]+") do 
	    if string.byte(line,1) ~= string.byte("+",1) then
                  output = output .. "'"..line.."',\n"
        end
	end
	output = output .. "]"
	return output
end

local function convert_binary_dump_to_JS(infile, blockLen)
	 local bindata = infile:read("*all")
	 len = string.len(bindata)

	if len % blockLen ~= 0 then 
		return oops(("Bad data, length (%d) should be a multiple of blocklen (%d)"):format(len, blockLen))
	end

	local _,hex = bin.unpack(("H%d"):format(len),bindata)

	-- Now that we've converted binary data into hex, we doubled the size. 
	-- One byte, like 0xDE is now 
	-- the characters 'D' and 'E' : one byte each. 
	-- Thus:
	blockLen = blockLen * 2

	local js,i = "[";
	for i = 1, string.len(hex),blockLen do
		js = js .."'" ..string.sub(hex,i,i+blockLen -1).."',\n"
	end
	js = js .. "]"
	return js
end

local function convert_ascii_dump_to_BIN(infile)
	local t = infile:read("*all")
	
	local output = {};
	for line in string.gmatch(t, "[^\n]+") do 
		if string.byte(line) ~= string.byte("+") then
			for c in (line or ''):gmatch('..') do
				output[#output+1] = string.char( tonumber(c,16) )
			end
		end
	end
	return output
end


---
-- Converts a .eml-file into a HTML/Javascript file. 
-- @param input the file to convert
-- @param output the file to write to
-- @return the name of the new file. 
local function convert_eml_to_html(input, output)
	input = input or 'dumpdata.eml'
	output = output or input .. 'html'

	local infile = io.open(input, "r")
	if infile == nil then 
		return oops(string.format("Could not read file %s",tostring(input)))
	end

	-- Read file, get JS
	local javascript = convert_ascii_dump_to_JS(infile)
	io.close(infile)
	return save_HTML(javascript, output )
end

--- Converts a binary dump into HTML/Javascript file
-- @param input the file containing the dump  (defaults to dumpdata.bin)
-- @param output the file to write to
-- @param blockLen, the length of each block. Defaults to 16 bytes
local function convert_bin_to_html(input, output, blockLen)
	input = input or 'dumpdata.bin'
	blockLen = blockLen or 16
	output = output or input .. 'html'

	local infile = io.open(input, "rb")
	if infile == nil then 
		return oops(string.format("Could not read file %s",tostring(input)))
	end
	-- Read file, get JS
	local javascript = convert_binary_dump_to_JS(infile, blockLen)
	io.close(infile)

	return save_HTML(javascript, output )
end

--- Converts a eml dump into a binary file
-- @param input the file containing the eml-dump  (defaults to dumpdata.eml)
-- @param output the file to write to  ( defaults to dumpdata.bin)
local function convert_eml_to_bin(input, output)
	input = input or 'dumpdata.eml'
	output = output or 'dumpdata.bin'

	local infile = io.open(input, "rb")
	if infile == nil then 
		return oops(string.format("Could not read file %s",tostring(input)))
	end
	-- Read file, get BIN
	local data = convert_ascii_dump_to_BIN(infile)
	io.close(infile)

	return save_BIN(data, output )
end


return {
	convert_bin_to_html = convert_bin_to_html,
	convert_eml_to_html = convert_eml_to_html,
	convert_eml_to_bin = convert_eml_to_bin,
    SaveAsBinary = save_BIN,
	SaveAsText = save_TEXT,
    SaveAsBinary = save_BIN,
	SaveAsText = save_TEXT,
}
