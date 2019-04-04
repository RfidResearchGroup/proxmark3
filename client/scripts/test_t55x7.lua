local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local utils = require('utils')

local format=string.format
local floor=math.floor

copyright = ''
author = "Iceman"
version  = ''
desc =[[
This script will program a T55x7 TAG with a configuration and four blocks of data.
It will then try to detect and read back those block data and compare if read data matches the expected data.


lf t55xx wipe
lf t55xx detect
lf t55xx write b 1 d 00000000
lf t55xx write b 2 d ffffffff
lf t55xx write b 3 d 80000000
lf t55xx write b 4 d 00000001

Loop:

try write different configuration blocks, and read block1-4 and comparing the read values with the values used to write.

testsuit for T55XX commands demodulation

]]
example = [[
    1. script run test_t55x7
]]
usage = [[

script run test_t55x7

Arguments:
    -h       this help
]]

local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local DEBUG = true -- the debug flag

local data_blocks_cmds = {    
    [1] = '00000000',
    [2] = 'ffffffff',
    [3] = '80000000',
    [4] = '00000001',
}

---
-- A debug printout-function
local function dbg(args)
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
local function oops(err)
    print("ERROR: ",err)
end
---
-- Usage help
local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print("Example usage")
    print(example)
end
---
-- Exit message
local function exitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end

local function WipeCard()

   local wipe_cmds = {
        [1] = 'lf t55xx wipe',
        [2] = 'lf t55xx detect',
   }
    for _ = 1, #wipe_cmds do
        local c = wipe_cmds[_]
        dbg(c);  core.console(c)
    end
    
    local wipe_data_cmd = "lf t55xx write b %s d %s"
    for _ = 1, #data_blocks_cmds do
        local val = data_blocks_cmds[_]
        local c = string.format(wipe_data_cmd, _, val);
        core.console(c)
    end
end
---
-- lf t55xx read
local function CheckReadBlock(block)
    local data, msg
    -- blockno, page1, override, pwd
    data, msg = core.t55xx_readblock(block, "0", "0", "")
    if not data then
        return ""
    end
    return ('%08X'):format(data)
end

local function test()
    
    -- PSK1 Modulations to test.  (2blocks)
    local process_block0_cmds = {
        [1] = '00001040',
        [2] = '00041040', 
        [3] = '00081040',
        [4] = '000c1040',
        [5] = '00101040',
        [6] = '00141040',
        [7] = '00181040',
        [8] = '001c1040',
    }

    local y
    local block = "00"

    for _ = 1, #process_block0_cmds do
    
        local p_config_cmd = process_block0_cmds[_]
        core.clearCommandBuffer()

        -- Write Config block
        dbg(('lf t55xx write b 0 d %s'):format(p_config_cmd))
        local config = tonumber(p_config_cmd, 16)
        local writecmd = Command:new{cmd = cmds.CMD_T55XX_WRITE_BLOCK,arg1 = config, arg2 = block, arg3 = '00', data = '00'}
        local err = core.SendCommand(writecmd:getBytes())
        if err then return oops(err) end
        local response = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)

        -- Detect 
        local res, msg = core.t55xx_detect()
        if not res then 
            print("can't detect modulation, skip to next config")
        else
            -- Loop block1-2
            for _ = 1, #data_blocks_cmds do
                local val = data_blocks_cmds[_]
                local blockdata, msg = CheckReadBlock(_)
                if blockdata ~= val then
                    print( ('Test %s == %s Failed'):format(val, blockdata))
                    core.console( format('rem -- block %d  value %s failed', _, val))
                else
                    print( ('Test %s == %s OK'):format(val, blockdata))
                end
            end
        end       
    end
end

local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )

    -- Arguments for the script
    for o, arg in getopt.getopt(args, 'h') do
        if o == "h" then return help() end
    end

    core.clearCommandBuffer()

    print('Starting test,  wiping card')
    WipeCard()
    print('Detecting card')
    local res, msg = core.t55xx_detect()
    if res then
        print('Starting test')
        test()
    else
        print("can't detect modulation. Test failed. Ending.")
    end
    
--    test()
    exitMsg('Tests finished')
    
end
main(args)
