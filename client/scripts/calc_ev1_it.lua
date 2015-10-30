local bin = require('bin')
local getopt = require('getopt')
local utils =  require('utils')

local bxor=bit32.bxor

example =[[
	 script run calc_ev1_it
	 script run calc_ev1_it -u 11223344556677
]]
author = "Iceman"
usage = "script run calc_ev1_it -u <uid> "
desc =[[
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
    --[[ position, 4byte xor
    --]]
	{"00","4f2711c1"},
	{"01","07D7BB83"},
	{"02","9636EF07"},
	{"03","B5F4460E"},
	{"04","F271141C"},
	{"05","7D7BB038"},
	{"06","636EF871"},
	{"07","5F4468E3"},
	{"08","271149C7"},
	{"09","D7BB0B8F"},
	{"0A","36EF8F1E"},
	{"0B","F446863D"},
	{"0C","7114947A"},
	{"0D","7BB0B0F5"},
	{"0E","6EF8F9EB"},
	{"0F","44686BD7"},
	{"10","11494fAF"},
	{"11","BB0B075F"},
	{"12","EF8F96BE"},
	{"13","4686B57C"},
	{"14","1494F2F9"},
	{"15","B0B07DF3"},
	{"16","F8F963E6"},
	{"17","686B5FCC"},
	{"18","494F2799"},
	{"19","0B07D733"},
	{"1A","8F963667"},
	{"1B","86B5F4CE"},
	{"1C","94F2719C"},
	{"1D","B07D7B38"},
	{"1E","F9636E70"},
	{"1F","6B5F44E0"},
}

local function findEntryByUid( uid )

	-- xor UID4,UID5,UID6,UID7
	-- mod 0x20 (dec 32)
	local pos = (bxor(bxor(bxor(uid[4],uid[5]), uid[6]),uid[7])) % 32

	-- convert to hexstring
	pos = string.format('%02X', pos)
	
    for k, v in pairs(_xortable) do
		if ( v[1]  == pos ) then
			return utils.ConvertHexToBytes(v[2])
		end
	end
	return nil
end

local function main(args)

	print( string.rep('--',20) )
	print( string.rep('--',20) )	
	print()
			
	local i,j, pwd
	local uid = '04111211121110'
	
	-- Arguments for the script
	for o, a in getopt.getopt(args, 'hu:') do
		if o == "h" then return help() end		
		if o == "u" then uid = a end		
	end

	-- uid string checks
	if uid == nil then return oops('empty uid string') end
	if #uid == 0 then return oops('empty uid string') end
	if #uid ~= 14 then return oops('uid wrong length. Should be 7 hex bytes') end

	local uidbytes = utils.ConvertHexToBytes(uid)

    local entry = findEntryByUid(uidbytes)
	if entry == nil then return oops("Can't find a xor entry") end

	--  PWD CALC	
	--	PWD0  =  T0 xor B xor C xor D
	--	PWD1  =  T1 xor A xor C xor E 
	--	PWD2  =  T2 xor A xor B xor F 
	--	PWD3  =  T3 xor G 
  
    local pwd0 = bxor( bxor( bxor( entry[1], uidbytes[2]), uidbytes[3]), uidbytes[4])
	local pwd1 = bxor( bxor( bxor( entry[2], uidbytes[1]), uidbytes[3]), uidbytes[5])
	local pwd2 = bxor( bxor( bxor( entry[3], uidbytes[1]), uidbytes[2]), uidbytes[6])
	local pwd3 = bxor( entry[4], uidbytes[7])
	
	print('UID | '..uid)
	print(string.format('PWD | %02X%02X%02X%02X', pwd0, pwd1, pwd2, pwd3))
end

main(args)