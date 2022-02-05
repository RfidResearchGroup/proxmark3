local getopt = require('getopt')
local ansicolors = require('ansicolors')

--Copyright
copyright = ''
author = 'nisgola'
version = 'v1'

-- Script description
desc = [[
This is a script that write Sector Trailers to the emulator memory.

By default, both keys A and B are set to 0xFFFFFFFFFFFF.
The Access Bytes are set to 0xFF0780 and User Bytes to 0x00.
]]
example = [[
    -- Use default formatting
    1. script run hf_mf_efmt

    -- Change keys A and B
    2. script run hf_mf_efmt -a 112233445566 -b AABBCCDDEEFF

    -- Define access bits and User byte
    3. script run hf_mf_efmt -x 00f0ff -u 12

    -- Format as 4K card
    4. script run hf_mf_efmt -4
]]

-- Usage info
usage = [[
script run hf_mf_efmt [-h] [-4] [-a <hex>] [-b <hex>] [-x <hex>] [-u <hex>]
]]

-- Arguments
arguments = [[
    -h          this help
    -4		Format as 4K card instead of the default 1K
    -a <hex>    define key A
    -b <hex>    define key B
    -x <hex>    define Access Byts
    -u <hex>	define User Byte

]]

-- Help function
local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print(ansicolors.cyan..'Usage'..ansicolors.reset)
    print(usage)
    print(ansicolors.cyan..'Arguments'..ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan..'Example usage'..ansicolors.reset)
    print(example)
end

-- Print error
local function oops(err)
    print('ERROR:', err)
    core.clearCommandBuffer()
    return nil, err
end

--  Command function
local function cmdFormatEmul()
    local arr = {}
    for i = 0, 15 do
        local blk = 3 + (4*i)
        arr[i] = 'hf mf esetblk --blk '..blk..' -d '..KeyA..''..Accessbit..''..User..''..KeyB..''
    end

-- This looks horrible, but I don't know anything about Lua
    if S70 then
	for i = 16, 31 do
	local blk = 3 + (4*i)
        arr[i] = 'hf mf esetblk --blk '..blk..' -d '..KeyA..''..Accessbit..''..User..''..KeyB..''
	end
	for i = 32, 40 do
		local blk = 127 + (16*(i-32))
	        arr[i] = 'hf mf esetblk --blk '..blk..' -d '..KeyA..''..Accessbit..''..User..''..KeyB..''
	end
    end
    return arr
end
local function sendCmds( cmds )
    for i = 0, #cmds do
        if cmds[i]  then
            print ( cmds[i]  )
            core.console( cmds[i] )
            core.clearCommandBuffer()
        end
    end
end

-- main function
function main(args)

	local i
	local cmds = {}
	
	-- Receive parameters
	for o, a in getopt.getopt(args, 'ha:b:x:u:4') do
		if o == 'h' then return help() end
		if o == 'a' then KeyA = a end
		if o == 'b' then KeyB = a end
		if o == 'x' then Accessbit = a end
		if o == 'u' then User = a end
		if o == '4' then S70 = true end
	end

	-- Validate inputs
	KeyA = KeyA or 'FFFFFFFFFFFF'
	if #(KeyA) ~= 12 then
		return oops( string.format('Wrong length of the Key A (was %d) expected 12', #KeyA))
	end
	KeyB = KeyB or 'FFFFFFFFFFFF'
	if #(KeyB) ~= 12 then
		return oops( string.format('Wrong length of the Key B (was %d) expected 12', #KeyB))
	end
	Accessbit = Accessbit or 'FF0780'
	if #(Accessbit) ~= 6 then
		return oops( string.format('Wrong length of the Acces bit (was %d) expected 6', #Accessbit))
	end
	User = User or '00'
	if #(User) ~= 2 then
		return oops( string.format('Wrong lenght for the user defined byte, (was %d) expected 2', #User))
	end

	-- Send commands to proxmark
	core.clearCommandBuffer()
	sendCmds( cmdFormatEmul() )
end
main (args)
