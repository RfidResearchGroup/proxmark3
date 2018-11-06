local getopt = require('getopt')
local bin = require('bin')

author = "Bogito"
version = 'v1.0.0'
desc =[[
This script will read the flash memory of RDV4 and print the stored passwords.
It was meant to be used as a help tool after using the BogRun standalone mode.
]]
usage = [[
Usage:
	script run read_pwd_mem -h -o <offset> -l <length>

Arguments:
	-h             : this help
	-o <OFFSET>    : Memory offset. Default is 0.
	-l <LENGTH>    : Length in bytes. Default is 256.
]]
example =[[
Examples:
	-- This will scan the first 256 bytes of flash memory for stored passwords
	script run read_pwd_mem

	-- This will scan 256 bytes of flash memory at offset 64 for stored passwords
	script run read_pwd_mem -o 64

	-- This will scan 32 bytes of flash memory at offset 64 for stored passwords
	script run read_pwd_mem -o 64 -l 32
]]

-- Usage help
local function help()
	print(desc)
	print(usage)
	print(example)
end

local function main(args)

	local data, err, quadlet, pwdcnt
	local offset = 0
	local length = 256
	
	-- Read the parameters
	for o, a in getopt.getopt(args, 'ho:l:') do
		if o == "h" then return help() end
		if o == "o" then offset = tonumber(a) end
		if o == "l" then length = tonumber(a) end
	end
	
	if length < 0 or length > 256 then
		return print('Error: Length is not valid. Must be less than 256')
	end
	
	if ((offset < 0) or (offset % 4 ~= 0)) then
		return print('Error: Offset is not valid. Mod-4 values are only allowed.')
	end
	
	print('Offset: ' .. offset)
	print('Length: ' .. length)
	print()

    data, err = core.GetFromFlashMem(offset, length)

	if err then 
		print(err)
		return
	end
	
    local count, s = bin.unpack('H'..length, data)
	
	pwdcnt = 0
	for i = 1,(length/4),1 
	do
		quadlet = string.sub(s, (i-1)*8+1, i*8)
		if quadlet == "FFFFFFFF" then break end
		print(string.format("[%02d]",i) .. ' ' .. quadlet)
		pwdcnt = pwdcnt + 1

	end
	print()
	print('Found passwords: ' .. pwdcnt)
	
end

main(args)
