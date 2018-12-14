
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
			block = data:sub(33,64)
			return block
		else
			return nil
		end
	else
		print("Timeout while waiting for response. Increase TIMEOUT in mifare_ad.lua to wait longer")
		return nil, "Timeout while waiting for device to respond"
	end
end

---_ Gets data from a block
-- @return block if successfull
-- @return nil, errormessage if unsuccessfull
local function getBlock(block)
	local data, err

	core.clearCommandBuffer()

	-- // params
	-- uint8_t sectorNo = arg0;
	-- uint8_t keyType = arg1;
	-- uint64_t ui64Key = 0;
	-- ui64Key = bytes_to_num(datain, 6);
	local sectorNo = 0
	local keyType = 0
	local key = "A0A1A2A3A4A5";
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
	-- -- Now, parse out the block data
	b0 = string.sub(data,3,4)
	return b0
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

	-- First, get block 1 byte 1
	local block, err = getBlock(0)
	if err then return oops(err) end
	debug(("Checking block 0 sector 1 byte 1"))
	debug(("Got byte: %s"):format(block))
	-- prlog(block)
	if block == "0F" then
		print('Card has MADs v1')
	end
	--(iceman) Should be able to detect MAD v2 aswell..

	-- Deactivate field
	close()
end
main(args)