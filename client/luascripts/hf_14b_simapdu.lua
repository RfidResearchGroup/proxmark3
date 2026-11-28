local cmds = require('commands')
local getopt = require('getopt')
local ansicolors = require('ansicolors')

copyright = ''
author = 'Iceman'
version = 'v1.0.0'
desc = [[
Simulates an ISO/IEC 14443-4 type B tag whose APDUs are answered by this script.
The device forwards each I-block's APDU, the script sends the answer back.
This example answers SELECT with 9000 and anything else with 6D00, put your own
logic in `answer()`. No chaining: an answer must fit the reader's frame.
Press <Enter> or the pm3 button to stop.
]]
example = [[
    script run hf_14b_simapdu
    script run hf_14b_simapdu -u 11AA33BB
]]
usage = [[
script run hf_14b_simapdu [-h] [-u <hex>]
]]
arguments = [[
    -h             this help
    -u <hex>       4 byte UID/PUPI (default 820DE174)
]]

-- hf 14b sim flag, see ISO14B_SIM_FLAG_APDU in include/iso14b.h
local SIM_FLAG_APDU = '01'

local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print(ansicolors.cyan..'Usage'..ansicolors.reset)
    print(usage)
    print(ansicolors.cyan..'Arguments'..ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan..'Example usage'..ansicolors.reset)
    print(example)
end

-- APDU in, answer out, both hex strings
local function answer(apdu)
    if apdu:sub(1, 4) == '00A4' then
        return '9000'
    end
    return '6D00'
end

local function main(args)

    local pupi = '00000000'
    for o, a in getopt.getopt(args, 'hu:') do
        if o == 'h' then return help() end
        if o == 'u' then pupi = a end
    end

    if #pupi ~= 8 or pupi:match('^%x+$') == nil then
        print('UID/PUPI must be 4 hex bytes')
        return
    end

    print('Press <Enter> or the pm3 button to stop')
    core.SendCommandNG(cmds.CMD_HF_ISO14443B_SIMULATE, pupi..SIM_FLAG_APDU)

    while true do

        if core.kbd_enter_pressed() then
            core.SendCommandNG(cmds.CMD_BREAK_LOOP, '')
            core.WaitForResponseTimeout(cmds.CMD_HF_ISO14443B_SIMULATE, 1000)
            break
        end

        local resp = core.WaitForResponseTimeout(cmds.CMD_UNKNOWN, 100)
        if resp then
            local count, cmd, length, magic, status = bin.unpack('SSIc', resp)
            if cmd == cmds.CMD_HF_ISO14443B_SIMULATE then
                print('Simulation ended, status '..status)
                break
            end

            if cmd == cmds.CMD_HF_ISO14443B_SIM_APDU then
                local _, apdu = bin.unpack('H'..length, resp, 13)
                local ans = answer(apdu:upper())
                print('>> '..apdu..'   << '..ans)
                core.SendCommandNG(cmds.CMD_HF_ISO14443B_SIM_APDU, ans)
            end
        end
    end
end

main(args)
