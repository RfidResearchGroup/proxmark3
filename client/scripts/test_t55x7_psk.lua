local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local utils = require('utils')

example =[[
	1. script run test_t55x7_psk
	2. script run test_t55x7_psk -o 

]]
author = "Iceman"
usage = "script run test_t55x7_psk"
desc =[[
This script will program a T55x7 TAG with the configuration: block 0x00 data 0x00088040
The outlined procedure is as following:

"lf t55xx write 0 00088040"
"lf read"
"data samples"
"data pskdet"
"data psknrz"
"data pskindala"
"data psknrzraw"

Loop OUTER:
	change the configuretion block 0 with:
    -xxxx8xxx = PSK RF/2 with Manchester modulation
    -xxxx1xxx = PSK RF/2 with PSK1 modulation (phase change when input changes)
    -xxxx2xxx = PSK RF/2 with PSk2 modulation (phase change on bitclk if input high)
    -xxxx3xxx = PSK RF/2 with PSk3 modulation (phase change on rising edge of input)
	Loop INNER
	    for each outer configuration, also do 
			XXXXX0XX = PSK RF/2
			XXXXX4XX = PSK RF/4
			XXXXX8XX = PSK RF/8

In all 12 individual test for the PSK demod

Arguments:
	-h             : this help
]]

local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local DEBUG = true -- the debug flag

	
-- local procedurecmds = {
	-- [1] = '%s%s%s%s',
	-- [2] = 'lf read',
	-- --[3] = '',
	-- [3] = 'data samples',
	-- [4] = 'data pskdetectclock',
	-- [5] = 'data psknrzrawdemod',
	-- [6] = 'data pskindalademod',
-- }

-- --BLOCK 0 = 00 08 80 40 PSK
             -- -----------
			   -- 08------- bitrate
				  -- 8----- modulation PSK1
				   -- 0---- PSK ClockRate
				      -- 40 max 2 blocks

local procedurecmds = {
	[1] = '00%02X%X%X40',
	[2] = 'lf t55xx detect',
	--[3] = '',
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

function test(modulation)
	local bitrate
	local clockrate
	local block = "00"
	for bitrate = 0x0, 0x1d, 0x4 do
	
		for clockrate = 0,8,4 do

			for _ = 1, #procedurecmds do
				local cmd = procedurecmds[_]
				
				if #cmd == 0 then  
				
				elseif _ == 1 then

					dbg("Writing to T55x7 TAG")

					local config = cmd:format(bitrate, modulation, clockrate)
					dbg(('lf t55xx write 0 %s'):format(config))
					
					config = tonumber(config,16) 
					local writecmd = Command:new{cmd = cmds.CMD_T55XX_WRITE_BLOCK,arg1 = config, arg2 = block, arg3 = "00", data = "00"}
					local err = core.SendCommand(writecmd:getBytes())
					if err then return oops(err) end
					local response = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)
				else
					dbg(cmd)
					core.console( cmd )
				end
			end
			core.clearCommandBuffer()	
		end
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

	test(1)  -- PSK1
	--test(2) -- PSK2
	--test(3) -- PSK3
	
	print( string.rep('--',20) )
end
main(args)

-- Where it iterates over 
  -- xxxx8xxx = PSK RF/2 with Manchester modulation
  -- xxxx1xxx = PSK RF/2 with PSK1 modulation (phase change when input changes)
  -- xxxx2xxx = PSK RF/2 with PSk2 modulation (phase change on bitclk if input high)
  -- xxxx3xxx = PSK RF/2 with PSk3 modulation (phase change on rising edge of input)

    -- XXXXX0XX = PSK RF/2
    -- XXXXX4XX = PSK RF/4
    -- XXXXX8XX = PSK RF/8
