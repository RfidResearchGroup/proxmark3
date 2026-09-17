local getopt = require('getopt')
local ansicolors  = require('ansicolors')

copyright = ''
author = 'Kenzy Carey'
version = 'v1.0.3'
desc = [[

  .-----------------------------------------------------------------.
 /  .-.                                                         .-.  \
|  /   \                    BruteSim                           /   \  |
| |\_.  |     (bruteforce simulation for multiple tags)       |    /| |
|\|  | /|                      by                             |\  | |/|
| `---' |                 Kenzy Carey                         | `---' |
|       |                                                     |       |
|       |-----------------------------------------------------|       |
\       |                                                     |       /
 \     /                                                       \     /
  `---'                                                         `---'

*SUPPORTED TAGS: pyramid, awid, fdxb, jablotron, noralsy, presco, visa2000, 14a, hid

This script uses the Proxmark3 implementations of simulation to bruteforce given ranges of id.
It uses both LF and HF simulations.

    -- Author note
    -- I wrote this as i was doing a PACS audit. This is far from complete, but is easily expandable.
    -- The idea was based on proxbrute, but i needed more options, and support for different readers.
    -- I don't know LUA, so I used Brian Redbeards lf_hid_bulkclone.lua script as a starting point, sorry if its kludgy.

]]
example = [[
    --  (the above example would bruteforce pyramid tags, starting at 10:1000, ending at 10:991, and waiting 1 second between each card)

    script run multi_bruteforce -r pyramid -f 10 -b 1000 -c 10 -t 1 -d down
]]
usage = [[
script run multi_bruteforce -r rfid_tag -f facility_code -b base_card_number -c count -t timeout -d direction
]]
arguments = [[
    -h       this help
    -r       *see below           RFID Tag: the RFID tag to emulate
             pyramid
             awid
             fdxb
             jablotron
             noralsy
             presco
             visa2000
             14a
             hid

    -f       0-999                facility code (dfx: country id, 14a: type)
    -b       0-65535              base card number to start from
    -c       1-65536              number of cards to try
    -t       .0-99999, pause      timeout between cards (use the word 'pause' to wait for user input)
    -d       up, down             direction to move through card numbers
]]

local DEBUG = true
local bor = bit32.bor
local bxor = bit32.bxor
local lshift = bit32.lshift
---
-- A debug printout-function
local function dbg(args)
    if not DEBUG then return end
    if type(args) == 'table' then
        local i = 1
        while result[i] do
            dbg(result[i])
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
    print(ansicolors.cyan..'Usage'..ansicolors.reset)
    print(usage)
    print(ansicolors.cyan..'Arguments'..ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan..'Example usage'..ansicolors.reset)
    print(example)
end
--
-- Exit message
local function exitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end
--
-- Check if a string is empty
local function isempty(s)
    return s == nil or s == ''
end

-- The code below was blatantly stolen from Brian Redbeard's lf_hid_bulkclone.lua script
local function toBits(num, bits)
    bits = bits or math.max(1, select(2, math.frexp(num)))
    local t = {}
    for b = bits, 1, -1 do
        t[b] = math.fmod(num, 2)
        num = math.floor((num - t[b]) / 2)
    end
    return table.concat(t)
end
--
-- check for parity in bit-string.
local function evenparity(s)
    local _, count = string.gsub(s, '1', '')
    local p = count % 2
    if (p == 0) then
        return false
    end
    return true
end
--
-- calcs hex for HID
local function cardHex(i, f)
    fac = lshift(f, 16)
    id = bor(i, fac)
    stream = toBits(id, 26)
    high = evenparity(string.sub(stream, 0, 12)) and 1 or 0
    low = not evenparity(string.sub(stream, 13)) and 1 or 0
    bits = bor(lshift(id, 1), low)
    bits = bor(bits, lshift(high, 25))
    preamble = bor(0, lshift(1, 5))
    bits = bor(bits, lshift(1, 26))
    return ('%04x%08x'):format(preamble, bits)
end
--
--
local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    if #args == 0 then return help() end

    for o, a in getopt.getopt(args, 'r:f:b:c:t:d:h') do -- Populate command like arguments
        if o == 'r' then rfidtag = a end
        if o == 'f' then facility = a end
        if o == 'b' then baseid = a end
        if o == 'c' then count = a end
        if o == 't' then timeout = a end
        if o == 'd' then direction = a end
        if o == 'h' then return print(usage) end
    end

    -- Check to see if -r argument was passed
    if isempty(rfidtag) then
        print('You must supply the flag -r (rfid tag)')
        print(usage)
        return
    end

    -- Check what RFID Tag we are using
    if rfidtag == 'pyramid' then
        consolecommand = 'lf pyramid sim' -- set the console command
        rfidtagname = 'Farpointe/Pyramid' -- set the display name
        facilityrequired = 1              -- set if FC is required
    elseif rfidtag == 'awid' then
        consolecommand = 'lf awid sim'
        rfidtagname = 'AWID'
        facilityrequired = 1
    elseif rfidtag == 'fdxb' then         -- I'm not sure why you would need to bruteforce this ¯\_(ツ)_/¯
        consolecommand = 'lf fdxb sim'
        rfidtagname = 'FDX-B'
        facilityrequired = 1
    elseif rfidtag == 'jablotron' then
        consolecommand = 'lf jablotron sim'
        rfidtagname = 'Jablotron'
        facilityrequired = 0
    elseif rfidtag == 'noralsy' then
        consolecommand = 'lf noralsy sim'
        rfidtagname = 'Noralsy'
        facilityrequired = 0
    elseif rfidtag == 'presco' then
        consolecommand = 'lf presco sim -d'
        rfidtagname = 'Presco'
        facilityrequired = 0
    elseif rfidtag == 'visa2000' then
        consolecommand = 'lf visa2000 sim'
        rfidtagname = 'Visa2000'
        facilityrequired = 0
    elseif rfidtag == '14a' then
        consolecommand = 'hf 14a sim -t'
        if facility == '1' then rfidtagname = 'MIFARE Classic' -- Here we use the -f option to read the 14a type instead of the facility code
        elseif facility == '2' then rfidtagname = 'MIFARE Ultralight'
        elseif facility == '3' then rfidtagname = 'MIFARE Desfire'
        elseif facility == '4' then rfidtagname = 'ISO/IEC 14443-4'
        elseif facility == '5' then rfidtagname = 'MIFARE Tnp3xxx'
        else
            print('Invalid 14a type (-f) supplied. Must be 1-5')
            print(usage)
            return
        end
        facilityrequired = 0              -- Disable the FC required check, as we used it for type instead of FC
    elseif rfidtag == 'hid' then
        consolecommand = 'lf hid sim -r'
        rfidtagname = 'HID'
        facilityrequired = 1
    else                                  -- Display error and exit out if bad RFID tag was supplied
        print('Invalid rfid tag (-r) supplied')
        print(usage)
        return
    end

    if isempty(baseid) then               -- Display error and exit out if no starting id is set
        print('You must supply the flag -b (base id)')
        print(usage)
        return
    end

    if isempty(count) then                -- Display error and exit out of no count is set
        print('You must supply the flag -c (count)')
        print(usage)
        return
    end

    if facilityrequired == 1 then         -- If FC is required
        facilitymessage = ' - Facility Code: ' -- Add FC to status message
        if isempty(facility) then         -- If FC was left blank, display warning and set FC to 0
            print('Using 0 for the facility code as -f was not supplied')
            facility = 0
        end
    else                                  -- If FC is not required
        facility = ''                     -- Clear FC
        facilitymessage = ''              -- Remove FC from status message
    end

    if isempty(timeout) then              -- If timeout was not supplied, show warning and set timeout to 0
        print('Using 0 for the timeout as -t was not supplied')
        timeout = 0
    end

    if isempty(direction) then            -- If direction was not supplied, show warning and set direction to down
        print("Using down for direction as -d was not supplied")
        direction = 'down'
    end

    if tonumber(count) < 1 then
        print('Count -c must be set to 1 or higher')
        return
    else
        count = count -1                  -- Make our count accurate by removing 1, because math
    end

    if direction == 'down' then           -- If counting down, set up our for loop to count down
        endid = baseid - count
        fordirection = -1
    elseif direction == 'up' then         -- If counting up, set our for loop to count up
        endid = baseid + count
        fordirection = 1
    else                                  -- If invalid direction was set, show warning and set up our for loop to count down
        print('Invalid direction (-d) supplied, using down')
        endid = baseid - count
        fordirection = -1
    end


    -- display status message
    print('')
    print('BruteForcing '..rfidtagname..''..facilitymessage..''..facility..' - CardNumber Start: '..baseid..' - CardNumber End: '..endid..' - TimeOut: '..timeout)
    print("")

    -- loop through for each count (-c)
    for cardnum = baseid, endid, fordirection do

        -- If rfid tag is set to HID, convert card to HEX using the stolen code above
        if rfidtag == 'hid' then cardnum = cardHex(cardnum, facility) end

        -- send command to proxmark
        core.console(consolecommand..' '..facility..' '..cardnum)

        if timeout == 'pause' then
            print('Press enter to continue ...')
            io.read()
        else
            os.execute('sleep '..timeout..'')
        end
    end

    -- ping the proxmark to stop emulation and see if its still responding
    core.console('hw ping')
end

main(args)
