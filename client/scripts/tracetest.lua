local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local utils = require('utils')
local dumplib = require('html_dumplib')

example =[[
	1. script run tracetest
]]
author = "Iceman"
usage = "script run tracetest"
desc =[[
This script will load several traces files in ../traces/ folder and do 
"data load"
"lf search 1 u" 

The following tracefiles will be loaded:  
   em*.pm3
   m*.pm3

Arguments:
	-h             : this help
]]

local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local DEBUG = true -- the debug flag
--- 
-- A debug printout-function
function dbg(args)
	if not DEBUG then
		return
	end
	
    if type(args) == "table" then
		local i = 1
		while result[i] do
			dbg(result[i])
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


local function main(args)

	print( string.rep('--',20) )
	print( string.rep('--',20) )
	
	local cmdDataLoad = 'data load %s';
	local tracesEM = "find '../traces/' -iname 'em*.pm3' -type f"
	local tracesMOD = "find '../traces/' -iname 'm*.pm3' -type f"

	local write2File = false
	local outputTemplate = os.date("testtest_%Y-%m-%d_%H%M%S")

	-- Arguments for the script
	for o, arg in getopt.getopt(args, 'h') do
		if o == "h" then return help() end		
	end
	
	core.clearCommandBuffer()
	
	local files = {}
	
	-- Find a set of traces staring with EM
	local p = assert( io.popen(tracesEM))
	for file in p:lines() do
		table.insert(files, file)
	end
	p.close();
	
	-- Find a set of traces staring with MOD
	p = assert( io.popen(tracesMOD) )
	for file in p:lines() do
		table.insert(files, file)
	end
	p.close();
	
	local cmdLFSEARCH = "lf search 1 u" 
	
	-- main loop
	io.write('Starting to test traces > ')
	for _,file in pairs(files) do

		local x = "data load "..file
		dbg(x)
		core.console(x) 
		
		dbg(cmdLFSEARCH)
		core.console(cmdLFSEARCH)
		
		core.clearCommandBuffer()
		
		if core.ukbhit() then
			print("aborted by user")
			break
		end
	end
	io.write('\n')

	print( string.rep('--',20) )

end
main(args)