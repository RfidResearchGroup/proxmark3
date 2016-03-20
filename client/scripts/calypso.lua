local cmds = require('commands')
local getopt = require('getopt')
local lib14b = require('read14b')
local utils = require('utils')

example = "script runs 14b raw commands to query a CAPLYPSO tag"
author = "Iceman, 2016"
desc =
[[
This is a script to communicate with a CALYSPO / 14443b tag using the '14b raw' commands

Arguments:
	-b 				123
Examples : 
	script run f -b 11223344
	script run f

Examples : 

# 1. Connect and don't disconnect
script run f  
# 2. Send mf auth, read response
script run f
# 3. disconnect
script run f

]]

--[[
This script communicates with  /armsrc/iso14443b.c, 
Check there for details about data format and how commands are interpreted on the 
device-side.  
]]

---
--
local function calypso_switch_on_field()
	local flags = lib14b.ISO14B_COMMAND.ISO14B_CONNECT
	local c = Command:new{cmd = cmds.CMD_ISO_14443B_COMMAND, arg1 = flags}
	return lib14b.sendToDevice(c, true) 
end
---
-- Disconnect (poweroff) the antenna forcing a disconnect of a 14b tag.
local function calypso_switch_off_field()
	local flags = lib14b.ISO14B_COMMAND.ISO14B_DISCONNECT
	local c = Command:new{cmd = cmds.CMD_ISO_14443B_COMMAND, arg1 = flags}
	return lib14b.sendToDevice(c, true) 
end

local function calypso_parse(result)
	local r = Command.parse(result)
	local len = r.arg2 * 2
	r.data = string.sub(r.data, 0, len);
	if r.arg1 == 0 then
		return r, nil
	end 
	return nil,nil
end
--- 
-- A debug printout-function
local function dbg(args)
	if DEBUG then
		print("###", args)
	end
end 
--- 
-- This is only meant to be used when errors occur
local function oops(err)
	print("ERROR: ",err)
	calypso_switch_off_field()
	return nil,err
end
--- 
-- Usage help
local function help()
	print(desc)
	print("Example usage")
	print(example)
end
--
-- helper function,  give current count of items in lua-table.
local function tablelen(T)
  local count = 0
  for _ in pairs(T) do count = count + 1 end
  return count
end
---
-- helper function, gives a sorted table from table t,  
-- order can be a seperate sorting-order function.
local function spairs(t, order)
    -- collect the keys
    local keys = {}
    for k in pairs(t) do keys[#keys+1] = k end

    -- if order function given, sort by it by passing the table and keys a, b,
    -- otherwise just sort the keys 
    if order then
        table.sort(keys, function(a,b) return order(t, a, b) end)
    else
        table.sort(keys)
    end

    -- return the iterator function
    local i = 0
    return function()
        i = i + 1
        if keys[i] then
            return keys[i], t[keys[i]]
        end
    end
end
---
-- Sends a usbpackage ,  "hf 14b raw" 
-- if it reads the response, it converts it to a lua object "Command" first and the Data is cut to correct length.
local function calypso_send_cmd_raw(data, ignoreresponse )

	local command, flags, result, err
	flags = lib14b.ISO14B_COMMAND.ISO14B_RAW +
			lib14b.ISO14B_COMMAND.ISO14B_APPEND_CRC

	data = data or "00"

	command = Command:new{cmd = cmds.CMD_ISO_14443B_COMMAND, 
							arg1 = flags, 	
							arg2 = #data/2,	-- LEN of data, half the length of the ASCII-string hex string
							arg3 = 0,
							data = data}	-- data bytes (commands etc)
	result, err = lib14b.sendToDevice(command, false) 
	
	if ignoreresponse then return response, err end
	
	if result then
		local r = calypso_parse(result)
		return r, nil
	end
	return respone, err
end
---
-- calypso_card_num : Reads card number from ATR and
-- writes it in the tree in decimal format.
local function calypso_card_num(card)
	if not card then return end
	local card_num = tonumber( card.uid:sub(1,8),16 )
	print('Card UID', card.uid)
	print('Card Number', card_num) 
end
---
-- analyse CALYPSO apdu status bytes.
local function calypso_apdu_status(apdu)
	-- last two is CRC
	-- next two is APDU status bytes.
	local status = false
	local mess = 'FAIL'
	local sw = apdu:sub( #apdu-7, #apdu-4)
	if sw == '9000' then
		mess = 'OK'
		status = true
	end
	print ('SW', sw, mess )
	return status
end

local _calypso_cmds = {
	["01.Select ICC file"]	=	'02 94 a4 08 00 04 3f 00 00 02',
	["02.ICC"]				=	'02 94 b2 01 04 1d',
	["03.Select EnvHol file"]=	'02 94 a4 08 00 04 20 00 20 01',
	["04.EnvHol1"]			=	'02 94 b2 01 04 1d',
	["05.Select EvLog file"]	=	'02 94 a4 08 00 04 20 00 20 10',
	["06.EvLog1"]			=	'06 00b2 0104 1d',
	["07.EvLog2"]			=	'06 00b2 0204 1d',
	["08.EvLog3"]			=	'06 00b2 0304 1d',
	["09.Select ConList file"]=	'42 01 04 0a 00a4 0800 04 2000 2050',
	["10.ConList"]			=	'42 01 06 06 00b2 0104 1d',
	["11.Select Contra file"]=	'42 01 08 0a 00a4 0800 04 2000 2020',
	["12.Contra1"]			=	'42 01 0a 06 00b2 0104 1d',
	["13.Contra2"]			=	'42 01 0c 06 00b2 0204 1d',
	["14.Contra3"]			=	'42 01 0e 06 00b2 0304 1d',
	["15.Contra4"]			=	'42 01 00 06 00b2 0404 1d',
	["16.Select Counter file"]=	'42 01 02 0a 00a4 0800 04 2000 2069',
	["17.Counter"]			=	'42 01 04 06 00b2 0104 1d',
	["18.Select SpecEv file"]=	'42 01 06 0a 00a4 08 0004 2000 2040',
	["19.SpecEv1"]			=	'42 01 08 06 00b2 0104 1d',
}

--- 
-- The main entry point
function main(args)

	local data, apdu, flags, uid, cid, result, err, card
	-- Read the parameters
	for o, a in getopt.getopt(args, 'h') do
		if o == "h" then return help() end
	end
	
	calypso_switch_on_field()
			
	-- Select 14b tag.
	card, err = lib14b.waitFor14443b()	
	if not card then return oops(err) end
	
	calypso_card_num(card)
	cid = card.cid

	--[[
	NAME        VALUE  APDU_POS
	PCB         0x0A   0
	CID         0x00   1
	CLA         0x94   2
	SELECT FILE 0xA4   3
	READ FILE   0xB2   3
	P1                 4
	P2                 5
	LEN_
	         0  1  2  3  4  5  6  7
	apdu = '0a 00 94 a4 08 00 04 3f 00 00 02'  --select ICC file
	DF_NAME = "1TIC.ICA" 
	--]]
	--for i = 1,10 do
		--result, err = calypso_send_cmd_raw('0294a40800043f000002',false)  --select ICC file
		for i, apdu in spairs(_calypso_cmds) do
			print('>>', i )
			apdu = apdu:gsub("%s+","")
			result, err = calypso_send_cmd_raw(apdu , false)
			if result then 
				calypso_apdu_status(result.data)
				print('<<', result.data )
			else
				print('<< no answer')
			end
		end
	calypso_switch_off_field()
end
---
-- a simple selftest function, tries to convert 
function selftest()
	DEBUG = true
	dbg("Performing test")
	dbg("Tests done")
end
-- Flip the switch here to perform a sanity check. 
-- It read a nonce in two different ways, as specified in the usage-section
if "--test"==args then 
	selftest()
else 
	-- Call the main 
	main(args)
end