local bin = require('bin')
local getopt = require('getopt')
local utils =  require('utils')

local bxor=bit32.bxor

example =[[
	 script run calc_mizip
	 script run calc_mizip -u 11223344
]]
author = "Iceman"
usage = "script run calc_mizip -u <uid>"
desc =[[
This script calculates mifare keys based on uid diversification for mizip. 
Algo not found by me.
Arguments:
	-h             : this help
	-u <UID>       : UID
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
	return nil,err
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
function exitMsg(msg)
	print( string.rep('--',20) )
	print( string.rep('--',20) )
	print(msg)
	print()
end

local _xortable = {
    --[[ sector key A/B, 6byte xor
    --]]
	{"001","09125a2589e5","F12C8453D821"},
	{"002","AB75C937922F","73E799FE3241"},
	{"003","E27241AF2C09","AA4D137656AE"},
	{"004","317AB72F4490","B01327272DFD"},
}
local function printRow(sector, keyA, keyB)
	print('|'..sector..'|  '..keyA..'  |  '..keyB..'  |' )
end
local function keyStr(p1, p2, p3, p4, p5, p6)
	return string.format('%02X%02X%02X%02X%02X%02X',p1, p2, p3, p4, p5, p6)
end
local function calckey(uid, xorkey, keytype)
	local p1,p2,p3,p4,p5,p6
	if keytype == 'A' then 
		p1 = bxor( uid[1], xorkey[1])
		p2 = bxor( uid[2], xorkey[2])
		p3 = bxor( uid[3], xorkey[3])
		p4 = bxor( uid[4], xorkey[4])
		p5 = bxor( uid[1], xorkey[5])
		p6 = bxor( uid[2], xorkey[6])
	else
		p1 = bxor( uid[3], xorkey[1])
		p2 = bxor( uid[4], xorkey[2])
		p3 = bxor( uid[1], xorkey[3])
		p4 = bxor( uid[2], xorkey[4])
		p5 = bxor( uid[3], xorkey[5])
		p6 = bxor( uid[4], xorkey[6])
	end
	return keyStr(p1,p2,p3,p4,p5,p6)
end 
local function main(args)

	print( string.rep('==', 30) )
	print()
			
	local i,j, pwd
	local uid = '11223344'
	
	-- Arguments for the script
	for o, a in getopt.getopt(args, 'hu:') do
		if o == "h" then return help() end		
		if o == "u" then uid = a end		
	end

	-- uid string checks
	if uid == nil then return oops('empty uid string') end
	if #uid == 0 then return oops('empty uid string') end
	if #uid ~= 8 then return oops('uid wrong length. Should be 4 hex bytes') end

	local uidbytes = utils.ConvertHexToBytes(uid)

	print('|UID|', uid)
	print('|---|----------------|----------------|')
	print('|sec|key A           |key B           |')
	print('|---|----------------|----------------|')
	printRow('000', keyStr(0xA0,0xA1,0xA2,0xA3,0xA4,0xA5), keyStr(0xB4,0xC1,0x32,0x43,0x9e,0xef) )

    for k, v in pairs(_xortable) do
		local keyA = calckey(uidbytes, utils.ConvertHexToBytes(v[2]), 'A')
		local keyB = calckey(uidbytes, utils.ConvertHexToBytes(v[3]), 'B')
		printRow(v[1], keyA, keyB  )
	end
	print('|---|----------------|----------------|')	
end

main(args)