-- Run me like this: ./client/proxmark3 /dev/ttyACM0 -l hf_bruteforce.lua

local getopt = require('getopt')

copyright = 'The GNU General Public License v3.0'
author = 'Daniel Underhay (updated), Keld Norman(original)'
version = 'v2.0.0'
usage = [[

pm3 --> script run hf_bruteforce -s start_id -e end_id -t timeout -T mifare_card_type

Arguments:
    -h       this help
    -s       0-0xFFFFFFFF         start id
    -e       0-0xFFFFFFFF         end id
    -t       0-99999, pause       timeout (ms) between cards (use the word 'pause' to wait for user input)
    -T       mfc, mfu             mfc for Mifare Classic or mfu for Mifare Ultralight


Example:

pm3 --> script run hf_bruteforce -s 0x11223344 -e 0x11223346 -t 1000 -T mfc

Bruteforce a 4 byte UID Mifare classic card number, starting at 11223344, ending at 11223346.


pm3 --> script run hf_bruteforce -s 0x11223344556677 -e 0x11223344556679 -t 1000 -T mfu

Bruteforce a 7 byte UID Mifare Ultralight card number, starting at 11223344556677, ending at 11223344556679.

]]


local DEBUG = true

---
-- Debug print function
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
-- When errors occur
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
    print('Example usage')
    print(example)
    print(usage)
end
---
--- Print user message
local function msg(msg)
 print( string.rep('--',20) )
 print('')
 print(msg)
 print('')
 print( string.rep('--',20) )
end
---
-- Start
local function main(args)

    local timeout = 0
    local start_id = 0
    local end_id = 0xFFFFFFFFFFFFFF
    local mftype = ''

    for o, a in getopt.getopt(args, 'e:s:t:h:T:') do
        if o == 's' then start_id = a end
        if o == 'e' then end_id = a end
        if o == 't' then timeout = a end
        if o == 'T' then mftype = a end
        if o == 'h' then return print(usage) end
    end

    -- template
    local command = ''

    if mftype == '' then
        return print(usage)
    elseif mftype == 'mfc' then
        command = 'hf 14a sim t 1 u %14X'
        msg('Bruteforcing Mifare Classic card numbers')
    elseif mftype == 'mfu' then
        command = 'hf 14a sim t 2 u %14X'
        msg('Bruteforcing Mifare Ultralight card numbers')
    end

    for n = start_id, end_id do
        local c = string.format( command, n )
        print('Running: "'..c..'"')
        core.console(c)
		core.console('msleep '..timeout);
        core.console('hw ping')
    end

end
main(args)
