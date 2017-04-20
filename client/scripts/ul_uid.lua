local getopt = require('getopt')
local utils =  require('utils')

local bxor = bit32.bxor

example = "script run ul_uid"
author = "Iceman"
desc =
[[
This is a script that tries to set UID on a mifare Ultralight magic card which answers to chinese backdoor commands 

Arguments:
	-h		this help
	-u		UID (14 hexsymbols)
]]
--- 
-- A debug printout-function
function dbg(args)
    if type(args) == "table" then
		local i = 1
		while args[i] do
			dbg(args[i])
			i = i+1
		end
	else
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

	print( string.rep('--',20) )
	print( string.rep('--',20) )	
	print()

	local uid = '04112233445566'
	
	-- Read the parameters
	for o, a in getopt.getopt(args, 'hu:') do
		if o == "h" then return help() end
		if o == "u" then uid = a end
	end

	-- uid string checks
	if uid == nil then return oops('empty uid string') end
	if #uid == 0 then return oops('empty uid string') end
	if #uid ~= 14 then return oops('uid wrong length. Should be 7 hex bytes') end

	local uidbytes = utils.ConvertHexToBytes(uid)
	
	local bcc1 = bxor(bxor(bxor(uidbytes[1], uidbytes[2]), uidbytes[3]), 0x88)
	local bcc2 = bxor(bxor(bxor(uidbytes[4], uidbytes[5]), uidbytes[6]), uidbytes[7])
	
	local block0 = string.format('%02X%02X%02X%02X', uidbytes[1], uidbytes[2], uidbytes[3], bcc1)
	local block1 = string.format('%02X%02X%02X%02X', uidbytes[4], uidbytes[5], uidbytes[6], uidbytes[7])
	local block2 = string.format('%02X%02X%02X%02X', bcc2, 0x48, 0x00, 0x00)
	
	print('new UID | '..uid)
	
	core.clearCommandBuffer()

	-- write block 0
	core.console("hf 14a raw -p -a -b 7 40")
	core.console("hf 14a raw -p -a 43")
	core.console("hf 14a raw -c -a A200"..block0)

	-- write block 1
	core.console("hf 14a raw -p -a -b 7 40")
	core.console("hf 14a raw -p -a 43")
	core.console("hf 14a raw -c -a A201"..block1)

	-- write block 2	
	core.console("hf 14a raw -p -a -b 7 40")
	core.console("hf 14a raw -p -a 43")
	core.console("hf 14a raw -c -a A202"..block2)

	--halt
	core.console("hf 14a raw -c -a 5000")
end

main(args)
