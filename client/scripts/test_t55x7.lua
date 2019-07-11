local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local utils = require('utils')

local format = string.format
local floor = math.floor

copyright = ''
author = "Iceman"
version  = 'v1.0.1'
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

local DEBUG = true -- the debug flag
local TIMEOUT = 1500
local total_tests = 0
local total_pass = 0

local data_blocks_cmds = {
    [1] = '00000000',
    [2] = 'ffffffff',
    [3] = '80000000',
    [4] = '00000001',
}

---
-- A debug printout-function
local function dbg(args)
    if not DEBUG then return end
    if type(args) == 'table' then
        local i = 1
        while args[i] do
            dbg(args[i])
            i = i+1
        end
    else
        print('###', args)
    end
end
---
-- This is only meant to be used when errors occur
local function oops(err)
    print('ERROR:', err)
    core.clearCommandBuffer()
    return nil, err
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
    print(usage)
end
---
-- Exit message
local function exitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end
---
-- ask/fsk/psk configuration blocks to test
local function GetConfigs( modulation )

    local t = {}

    t['PSK1'] = {
                [1] = '00001040',
                [2] = '00041040',
                [3] = '00081040',
                [4] = '000c1040',
                [5] = '00101040',
                [6] = '00141040',
                [7] = '00181040',
                [8] = '001c1040',
            }

    t['PSK2'] = {
                [1] = '00002040',
                [2] = '00042040',
                [3] = '00082040',
                [4] = '000c2040',
                [5] = '00102040',
                [6] = '00142040',
                [7] = '00182040',
                [8] = '001c2040',
            }

    t['PSK3'] = {
                [1] = '00003040',
                [2] = '00043040',
                [3] = '00083040',
                [4] = '000c3040',
                [5] = '00103040',
                [6] = '00143040',
                [7] = '00183040',
                [8] = '001c3040',
            }

    t['FSK1'] = {
                [1] = '00004040',
                [2] = '00004040',
                [3] = '00044040',
                [4] = '00084040',
                [5] = '000c4040',
                [6] = '00104040',
                [7] = '00144040',
                [8] = '00184040',
                [9] = '001c4040',
            }

    t['FSK2'] = {
                [1] = '00005040',
                [2] = '00045040',
                [3] = '00085040',
                [4] = '000c5040',
                [5] = '00105040',
                [6] = '00145040',
                [7] = '00185040',
                [8] = '001c5040',
            }

    t['FSK1A'] = {
                [1] = '00006040',
                [2] = '00046040',
                [3] = '00086040',
                [4] = '000c6040',
                [5] = '00106040',
                [6] = '00146040',
                [7] = '00186040',
                [8] = '001c6040',
            }

    t['FSK2A'] = {
                [1] = '00007040',
                [2] = '00047040',
                [3] = '00087040',
                [4] = '000c7040',
                [5] = '00107040',
                [6] = '00147040',
                [7] = '00187040',
                [8] = '001c7040',
            }

    t['ASK'] = {
                [1] = '00008040',
                [2] = '00048040',
                [3] = '00088040',
                [4] = '000c8040',
                [5] = '00108040',
                [6] = '00148040',
                [7] = '00188040',
                [8] = '001c8040',
            }

    t['BI'] = {
                [1] = '00010040',
                [2] = '00050040',
                [3] = '00090040',
                [4] = '000d0040',
                [5] = '00110040',
                [6] = '00150040',
                [7] = '00190040',
                [8] = '001d0040',
            }

    return t[modulation:upper()]
end
---
-- lf t55xx wipe
local function WipeCard()

    print('Wiping card')
    core.console('lf t55xx wipe')

    print('Detecting card')
    local res, msg = core.t55xx_detect()
    if not res then
        oops("Can't detect modulation. Test failed.")
        core.console('rem [ERR:DETECT:WIPED] Failed to detect after wipe')
        return false
    else
        local wipe_data_cmd = 'lf t55xx write b %s d %s'
        for _ = 1, #data_blocks_cmds do
            local val = data_blocks_cmds[_]
            local c = string.format(wipe_data_cmd, _, val)
            core.console(c)
        end
        return true
    end
end
---
-- lf t55xx read
local function CheckReadBlock(block)
    local data, msg
    -- blockno, page1, override, pwd
    data, msg = core.t55xx_readblock(block, '0', '0', '')
    if not data then
        return ''
    end
    return ('%08X'):format(data)
end

local function test(modulation)

    local process_block0_cmds = {}
    local y
    local password = '00000000'
    local block = '00'   -- configuration block 0
    local flags = '00'   -- page 0, no pwd, no testmode

    local s = ('Start test of %s'):format(modulation)
    print(s)

    process_block0_cmds = GetConfigs(modulation)

    if process_block0_cmds == nil then return oops('Cant find modulation '..modulation) end

    for _ = 1, #process_block0_cmds do

        local p_config_cmd = process_block0_cmds[_]
        local errors = 0
        core.clearCommandBuffer()

        -- Write Config block
        dbg(('lf t55xx write b 0 d %s'):format(p_config_cmd))

        local data = ('%s%s%s%s'):format(utils.SwapEndiannessStr(p_config_cmd, 32), password, block, flags)

        local wc = Command:newNG{cmd = cmds.CMD_T55XX_WRITE_BLOCK, data = data}
        local response, err = wc:sendNG(false, TIMEOUT)
        if not response then return oops(err) end

        -- Detect
        local res, msg = core.t55xx_detect()
        if not res then
            print("can't detect modulation, skip to next config")
            core.console(format('rem [ERR:DETECT:%s] Failed to detect modulation', p_config_cmd))
            core.console(format('rem [SUMMARY:%s] FAIL detection', p_config_cmd))
            total_tests = total_tests + #data_blocks_cmds
        else
            -- Loop block1-2
            for _ = 1, #data_blocks_cmds do
                total_tests = total_tests + 1
                local val = data_blocks_cmds[_]
                local blockdata, msg = CheckReadBlock(_)
                if blockdata:lower() ~= val:lower() then
                    print( ('Test %s == %s Failed'):format(val, blockdata))
                    core.console( format('rem [ERR:READ:%s:%d] block %d: read %s instead of %s', p_config_cmd, _, _, blockdata, val))
                    errors = errors+1
                else
                    print( ('Test %s == %s OK'):format(val, blockdata))
                    total_pass = total_pass + 1
                end
            end
            if errors >0 then
                core.console( format('rem [SUMMARY:%s] FAIL %d test%s', p_config_cmd, errors, errors > 1 and "s" or ""))
            else
                core.console( format('rem [SUMMARY:%s] PASS all tests', p_config_cmd))
            end
        end
    end
end

local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )

    -- Arguments for the script
    for o, arg in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end

    core.clearCommandBuffer()
    local res

    -- Adjust this table to set which configurations should be tested
--    local test_modes = { 'PSK1', 'PSK2', 'PSK3', 'FSK1', 'FSK2', 'FSK1A', 'FSK2A', 'ASK', 'BI' }
    local test_modes = { 'ASK' }

    for _ = 1, #test_modes do
        res = WipeCard()
        if res then
            print (test_modes[_])
            test(test_modes[_])
        else
            exitMsg('Abort!')
            return
        end
    end

    exitMsg('Tests finished')
    core.console(
            format('rem [SUMMARY] Success rate: %d/%d tests passed%s'
                , total_pass
                , total_tests
                , total_pass < total_tests and ', help me improving that number!' or ' \\o/'
           )
    )
end
main(args)
