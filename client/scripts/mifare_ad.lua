
-- Ability to read what card is there
local getopt = require('getopt')
local cmds = require('commands')
local taglib = require('taglib')
local lib14a = require('read14a')

local desc = 
[[This script will automatically check Mifare cards for MADs
(Mifare Application Directory)

Arguments:
	-d 				debug logging on
	-h 				this help

]]
local example = "script run xxx"
local author = "Mazodude"
--- 
-- This is only meant to be used when errors occur
local function oops(err)
	print("ERROR: ",err)
	return nil,err
end

--- 
-- Usage help
local function help()
	print(desc)
	print("Example usage")
	print(example)
end

local function debug(...)
	if DEBUG then 
		print("debug:", ...)
	end
end

local function show(data)
	if DEBUG then
	    local formatString = ("H%d"):format(string.len(data))
	    local _,hexdata = bin.unpack(formatString, data)
	    debug("Hexdata" , hexdata)
	end
end

local function bits(num)
    local t={}
    while num>0 do
        rest=num%2
        table.insert(t,1,rest)
        num=(num-rest)/2
    end return table.concat(t)
end
--- Shut down tag communication
-- return no return values
local function close()
	debug("Closing connection")
	core.clearCommandBuffer()
	local x = string.format("hf 14a raw -r")
	debug(x)
	core.console(x)
	debug("done")
	--data, err = waitCmd(true)
	--data, err = waitCmd(false)

end


-- waits for answer from pm3 device
local function checkCommand(command)
	core.clearCommandBuffer()
	local usb = command:getBytes()
	core.SendCommand(usb)
	local result = core.WaitForResponseTimeout(cmds.CMD_ACK, 1500)

	if result then
		local count, cmd, arg0 = bin.unpack('LL',result)
		if(arg0==1) then
			local count, arg1, arg2, data = bin.unpack('LLH511',result,count)
			sector = data
			return sector
		else
			return nil
		end
	else
		print("Timeout while waiting for response. Increase TIMEOUT in mifare_ad.lua to wait longer")
		return nil, "Timeout while waiting for device to respond"
	end
end

---_ Gets data from a sector
-- @return sector if successfull
-- @return nil, errormessage if unsuccessfull
local function getSector(sector,typ)
	local data, err

	core.clearCommandBuffer()

	-- // params
	-- uint8_t sectorNo = arg0;
	-- uint8_t keyType = arg1;
	-- uint64_t ui64Key = 0;
	-- ui64Key = bytes_to_num(datain, 6);
	local sectorNo = sector
	local keyType = 0
	local key = ""
	if typ == 1 then
		key = "A0A1A2A3A4A5"
	end
	debug(("Testing to auth with key %s"):format(key))
	-- print(key);
	local command = Command:new{cmd = cmds.CMD_MIFARE_READSC,
								arg1 = sectorNo,
								arg2 = keyType,
								arg3 = 0,
								data = key}
	local data = checkCommand(command)
	-- debug(command)
	-- print(data)
	if (data == nil) then return err, ("Could not auth with card - this tag does not have MADs") end
	if string.len(data) < 32 then
		return nil, ("Expected at least 32 bytes, got %d - this tag does not have MADs"):format(string.len(data))
	end
	return data
end


--- This function is a lua-implementation of
-- cmdhf14a.c:waitCmd(uint8_t iSelect)
local function waitCmd(iSelect)
	local response = core.WaitForResponseTimeout(cmds.CMD_ACK,1000)
	if response then
		local count,cmd,arg0,arg1,arg2 = bin.unpack('LLLL',response)
		local iLen = arg0
		if iSelect then	iLen = arg1 end
	    debug(("Received %i octets (arg0:%d, arg1:%d)"):format(iLen, arg0, arg1))
	    if iLen == 0 then return nil, "No response from tag" end
		local recv = string.sub(response,count, iLen+count-1)
	    return recv
	end
	return nil, "No response from device"
end



local function main( args)
	debug("script started")
	local err, data, data2,k,v,i
	-- Read the parameters
	for o, a in getopt.getopt(args, 'hd') do
		if o == "h" then help() return end
		if o == "d" then DEBUG = true end
	end

	local tag, err = lib14a.read(false, true)
	if not tag then return oops("No card present") end
	core.clearCommandBuffer()
	print(("UID: %s"):format(tag.uid))
	print(("SAK: %x"):format(tag.sak))

	local typ = 1
	if 0x18 == sak then --NXP MIFARE Classic 4k | Plus 4k | Ev1 4k
		typ = 4
	elseif 0x08 == sak then -- NXP MIFARE CLASSIC 1k | Plus 2k | Ev1 1K
		typ= 1
	elseif 0x09 == sak then -- NXP MIFARE Mini 0.3k
		typ = 0
	elseif  0x10 == sak then-- "NXP MIFARE Plus 2k"
		typ = 2
	elseif  0x01 == sak then-- "NXP MIFARE TNP3xxx 1K"
		typ = 1
	else
		debug("Defaulting to CLASSIC")
	end

	-- # | data    |  Sector | 00/ 0x00
	-- ----+------------------------------------------------
	-- 0 | 5C 71 B0 14 89 88 04 00 C0 8E 3C 90 49 50 12 13
	-- 1 | 80 0F 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	-- 2 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 12 48
	-- 3 | A0 A1 A2 A3 A4 A5 78 77 88 E9 B0 B1 B2 B3 B4 B5

	-- E9 = 1 1 1010 01
	-- C1 = 1 1 0000 01
	-- 69 = 0 1 1010 01
	-- 99 = 1 0 0110 01

	-- Need to check the sector trailer GPB
	-- First, get Sector 0 block 3 byte 10
	local sector, err = getSector(0,1)
	if err then return oops(err) end
	-- -- Now, parse out the block data
	sector = sector:sub(0,128)
	debug(sector)
	local trailer = sector:sub(97,128)
	debug(trailer)
	local gpb = string.sub(trailer,19,20)
	debug(("Checking block 0 sector 3 byte 10"))
	debug(("Got byte: %s"):format(gpb))
	local gpbbits = bits(tonumber(gpb,16))
	debug(gpbbits)
	local adv = gpbbits:sub(7,8)
	print(("ADV: %s"):format(adv))
	local rfu = gpbbits:sub(3,6)
	print(("RFU: %s"):format(rfu))
	local ma = gpbbits:sub(2,2)
	print(("MA: %s"):format(ma))
	local da = gpbbits:sub(1,1)
	print(("DA: %s"):format(da))
	-- prlog(block)
	if adv == "01" then
		print('Card has MADs v1')
	end
	if adv == "10" then
		print('Card has MADs v2')
	end

	-- Deactivate field
	close()
end
main(args)