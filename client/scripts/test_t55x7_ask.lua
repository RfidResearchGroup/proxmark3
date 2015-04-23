local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local utils = require('utils')

local format=string.format
local floor=math.floor

example =[[
	1. script run test_t55x7_ask
]]
author = "Iceman"
usage = "script run test_t55x7_ask"
desc =[[
This script will program a T55x7 TAG with the configuration: block 0x00 data 0x000100
The outlined procedure is as following:

--ASK 
	00 00 80 40
--           max 2
--        manchester
--     bit rate
 
"lf t55xx write 0 00008040"
"lf t55xx detect"
"lf t55xx info"

Loop:
	change the configuretion block 0 with:
    -xx 00 xxxx = RF/8 
    -xx 04 xxxx = RF/16
	-xx 08 xxxx = RF/32
	-xx 0C xxxx = RF/40
	-xx 10 xxxx = RF/50
	-xx 14 xxxx = RF/64
	-xx 18 xxxx = RF/100
	-xx 1C xxxx = RF/128


testsuit for the ASK/MANCHESTER demod

Arguments:
	-h             : this help
]]

local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local DEBUG = true -- the debug flag

--BLOCK 0 = 00008040 ASK / MAN
local config1 = '00'
local config2 = '8040'

local procedurecmds = {
	[1] = '%s%02X%s',
	[2] = 'lf t55xx detect',
	[3] = 'lf t55xx info',
}
--- 
-- A debug printout-function
function dbg(args)
	if not DEBUG then
		return
	end
	
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
--
-- Exit message
function ExitMsg(msg)
	print( string.rep('--',20) )
	print( string.rep('--',20) )
	print(msg)
	print()
end

function test()
	local y
	local block = "00"
	for y = 0x0, 0x1d, 0x4 do
		for _ = 1, #procedurecmds do
			local pcmd = procedurecmds[_]
			
			if #pcmd == 0 then  
			
			elseif _ == 1 then

				local config = pcmd:format(config1, y, config2)
				dbg(('lf t55xx write 0 %s'):format(config))			
				config = tonumber(config,16) 
				
				local writecmd = Command:new{cmd = cmds.CMD_T55XX_WRITE_BLOCK,arg1 = config, arg2 = block, arg3 = "00", data = "00"}
				local err = core.SendCommand(writecmd:getBytes())
				if err then return oops(err) end
				local response = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)

			else
				dbg(pcmd)
				core.console( pcmd )
			end			
		end
		core.clearCommandBuffer()	
	end
	print( string.rep('--',20) )
end

local function main(args)

	print( string.rep('--',20) )
	print( string.rep('--',20) )

	-- Arguments for the script
	for o, arg in getopt.getopt(args, 'h') do
		if o == "h" then return help() end
	end

	core.clearCommandBuffer()
	test()
	print( string.rep('--',20) )
end
main(args)