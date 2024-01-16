local cmds = require('commands')
local getopt = require('getopt')
local lib14b = require('read14b')
local utils = require('utils')
local iso7816 = require('7816_error')
local ansicolors  = require('ansicolors')

copyright = ''
author = 'Iceman'
version = 'v1.0.2'
desc = [[
This is a script to communicate with a MOBIB tag using the '14b raw' commands
]]
example = [[
    script run hf_14b_mobib
    script run hf_14b_mobib -b 11223344

]]
usage = [[
script run hf_14b_mobib -h -b
]]
arguments = [[
      h   this helptext
      b   raw bytes to send
]]

--[[
This script communicates with  /armsrc/iso14443b.c,
Check there for details about data format and how commands are interpreted on the
device-side.
]]

local function mobib_parse(result)
    if result.Oldarg0 >= 0 then
        local len = result.Oldarg0 * 2
        if len > 0 then
            d = string.sub(result.Data, 0, len);
            return d, nil
        end
    end
    return nil, "mobib_parse failed"
end
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
    print('ERROR: ', err)
    lib14b.disconnect()
    return nil, err
end
---
-- Usage help
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
--
-- helper function,  give current count of items in lua-table.
local function tablelen(T)
  local count = 0
  for _ in pairs(T) do count = count + 1 end
  return count
end
---
-- helper function, gives a sorted table from table t,
-- order can be a separate sorting-order function.
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
local function mobib_send_cmd_raw(data, ignoreresponse )
    local flags = lib14b.ISO14B_COMMAND.ISO14B_APDU
    data = data or ""
    -- LEN of data, half the length of the ASCII-string hex string
    -- 2 bytes flags
    -- 4 bytes timeout
    -- 2 bytes raw len
    -- n bytes raw
    local flags_str  = ('%04x'):format(utils.SwapEndianness(('%04x'):format(flags), 16))
    local time_str  =  ('%08x'):format(0)
    local rawlen_str = ('%04x'):format(utils.SwapEndianness(('%04x'):format(( 8 + #data/2)), 16))
    local senddata = ('%s%s%s%s'):format(flags_str, time_str, rawlen_str,data)
    local c = Command:newNG{cmd = cmds.CMD_HF_ISO14443B_COMMAND, data = senddata}

    local result, err = c:sendNG(ignoreresponse, 2000)
    if result then
        if result.Oldarg0 >= 0 then
            return mobib_parse(result)
        else
            err = 'card response failed'
        end
    else
        err = 'No response from card'
    end
    return result, err
end
---
-- mobib_card_num : Reads card number from ATR and
-- writes it in the tree in decimal format.
local function mobib_card_num(card)
    if not card then return end
    local card_num = tonumber( card.uid:sub(1,8),16 )
    print('')
    print('Card UID    ' ..ansicolors.green..card.uid:format('%x')..ansicolors.reset)
    print('Card Number ' ..ansicolors.green..string.format('%u', card_num)..ansicolors.reset)
    print('-----------------------')
end
---
-- analyse CALYPSO apdu status bytes.
local function mobib_apdu_status(apdu)
    -- last two is CRC
    -- next two is APDU status bytes.
    local mess = 'FAIL'
    local sw = apdu:sub( #apdu-7, #apdu-4)
    desc, err = iso7816.tostring(sw)
    --print ('SW', sw, desc, err )
    local status = ( sw == '9000' )
    return status, desc, err
end

local CLA = '00'
local _calypso_cmds = {
    ['01.SELECT AID 1TIC.ICA']   = CLA..'a4 0400 08 315449432e494341',
    ['02.Select ICC file a']     = CLA..'a4 0000 02 3f00',
    ['03.Select ICC file b']     = CLA..'a4 0000 02 0002',
    ['04.ICC']                   = CLA..'b2 0104 1d',
    ['05.Select Holder file']    = CLA..'a4 0000 02 3f1c',
    ['06.Holder1']               = CLA..'b2 0104 1d',
    ['07.Holder2']               = CLA..'b2 0204 1d',
    ['08.Select EnvHol file a']  = CLA..'a4 0000 00',
    ['09.Select EnvHol file b']  = CLA..'a4 0000 02 2000',
    ['10.Select EnvHol file c']  = CLA..'a4 0000 02 2001',
    ['11.EnvHol1']               = CLA..'b2 0104 1d',
    ['11.EnvHol2']               = CLA..'b2 0204 1d',
    ['12.Select EvLog file']     = CLA..'a4 0000 02 2010',
    ['13.EvLog1']                = CLA..'b2 0104 1d',
    ['14.EvLog2']                = CLA..'b2 0204 1d',
    ['15.EvLog3']                = CLA..'b2 0304 1d',
    ['16.Select ConList file']   = CLA..'a4 0000 02 2050',
    ['17.ConList']               = CLA..'b2 0104 1d',
    ['18.Select Contra file']    = CLA..'a4 0000 02 2020',
    ['19.Contra1']               = CLA..'b2 0104 1d',
    ['20.Contra2']               = CLA..'b2 0204 1d',
    ['21.Contra3']               = CLA..'b2 0304 1d',
    ['22.Contra4']               = CLA..'b2 0404 1d',
    ['23.Contra5']               = CLA..'b2 0504 1d',
    ['24.Contra6']               = CLA..'b2 0604 1d',
    ['25.Contra7']               = CLA..'b2 0704 1d',
    ['26.Contra8']               = CLA..'b2 0804 1d',
    ['27.Contra9']               = CLA..'b2 0904 1d',
    ['28.ContraA']               = CLA..'b2 0a04 1d',
    ['29.ContraB']               = CLA..'b2 0b04 1d',
    ['30.ContraC']               = CLA..'b2 0c04 1d',
    ['31.Select Counter file']   = CLA..'a4 0000 02 2069',
    ['32.Counter']               = CLA..'b2 0104 1d',
    ['33.Select LoadLog file a'] = CLA..'a4 0000 00',
    ['34.Select LoadLog file b'] = CLA..'a4 0000 02 1000',
    ['35.Select LoadLog file c'] = CLA..'a4 0000 02 1014',
    ['36.LoadLog']               = CLA..'b2 0104 1d',
    ['37.Select Purcha file']    = CLA..'a4 0000 02 1015',
    ['38.Purcha1']               = CLA..'b2 0104 1d',
    ['39.Purcha2']               = CLA..'b2 0204 1d',
    ['40.Purcha3']               = CLA..'b2 0304 1d',
    ['41.Select SpecEv file a']  = CLA..'a4 0000 00',
    ['42.Select SpecEv file b']  = CLA..'a4 0000 02 2000',
    ['43.Select SpecEv file c']  = CLA..'a4 0000 02 2040',
    ['44.SpecEv1']               = CLA..'b2 0104 1d',
    ['45.SpecEv2']               = CLA..'b2 0204 1d',
    ['46.SpecEv3']               = CLA..'b2 0304 1d',
    ['47.SpecEv4']               = CLA..'b2 0404 1d',
}

---
-- The main entry point
function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    local data, apdu, flags, uid, cid, result, err, card
    -- Read the parameters
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
        if o == 'b' then bytes = a end
    end

--    lib14b.connect()

    -- Select 14b tag.
    card, err = lib14b.waitFor14443b()
    if not card then return oops(err) end

    mobib_card_num(card)
    cid = card.cid

    for i, apdu in spairs(_calypso_cmds) do
        print('>> '..ansicolors.yellow..i..ansicolors.reset)
        apdu = apdu:gsub('%s+', '')
        data, err = mobib_send_cmd_raw(apdu , false)
        if err then
            print('<< '..err)
        else
            if data then
                local status, desc, err = mobib_apdu_status(data)
                local d = data:sub(3, (#data - 8))
                if status then
                    print('<< '..d..' ('..ansicolors.green..'ok'..ansicolors.reset..')')
                else
                    print('<< '..d..' '..ansicolors.red..err..ansicolors.reset )
                end
            else
                print('<< no answer')
            end
        end
    end
    lib14b.disconnect()
end
---
-- a simple selftest function, tries to convert
function selftest()
    DEBUG = true
    dbg('Performing test')
    dbg('Tests done')
end
-- Flip the switch here to perform a sanity check.
-- It read a nonce in two different ways, as specified in the usage-section
if '--test'==args then
    selftest()
else
    -- Call the main
    main(args)
end
