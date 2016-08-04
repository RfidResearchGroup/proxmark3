local cmds = require('commands')
local getopt = require('getopt')
local lib14b = require('read14b')
local utils = require('utils')
local iso7816 = require('7816_error')

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
	print('GOT:', r.data)
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
	desc, err = iso7816.tostring(sw)
	print ('SW', sw, desc, err )

	status = ( sw == '9000' )
	
	return status
end

local _calypso_cmds = {

-- Break down of command bytes:
--  A4 = select
--  Master File  3F00
--  0x3F = master file 
--  0x00 = master file id, is constant to 0x00.

--  DF Dedicated File  38nn
--  can be seen as directories
--  0x38  
--  0xNN  id
--	["01.Select ICC file"]	=	'0294 a4 080004 3f00 0002',

-- 	EF Elementary File 
--  EF1 Pin file
--  EF2 Key file
--  Grey Lock file
--  Electronic deposit file
--  Electronic Purse file
--  Electronic Transaction log file

	
	--["01.Select ICC file"]	=	'0294 a4 00 0002 3f00',
	["01.Select ICC file"]	=	'0294 a4 080004 3f00 0002',
	["02.ICC"]				=	'0394 b2 01 041d',
	["03.Select EnvHol file"] =	'0294 a4 080004 2000 2001',
	["04.EnvHol1"]			=	'0394 b2 01 041d',
	["05.Select EvLog file"] =	'0294 a4 080004 2000 2010',
	["06.EvLog1"]			=	'0394 b2 01 041d',
	["07.EvLog2"]			=	'0294 b2 02 041d',
	["08.EvLog3"]			=	'0394 b2 03 041d',
	["09.Select ConList file"] ='0294 a4 080004 2000 2050',
	["10.ConList"]			=	'0394 b2 01 041d',
	["11.Select Contra file"] =	'0294 a4 080004 2000 2020',
	["12.Contra1"]			=	'0394 b2 01 041d',
	["13.Contra2"]			=	'0294 b2 02 041d',
	["14.Contra3"]			=	'0394 b2 03 041d',
	["15.Contra4"]			=	'0294 b2 04 041d',
	["16.Select Counter file"]=	'0394 a4 080004 2000 2069',
	["17.Counter"]			=	'0294 b2 01 041d',
	["18.Select SpecEv file"]=	'0394 a4 080004 2000 2040',
	["19.SpecEv1"]			=	'0294 b2 01 041d',
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
	apdu = '02 94 a4 08 00 04 3f 00 00 02'  --select ICC file
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