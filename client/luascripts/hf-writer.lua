local utils = require('utils')
local getopt = require('getopt')
local read14a = require('read14a')
local uid = {} -- Array for eml files
local B = {} -- Array for B keys
local eml = {} -- Array for data in block 32 dig
local a = 0
local b = 0
local tab = string.rep('-', 64)

copyright = ''
author = 'Winds'
version = 'v1.0.0'
desc = [[
    That's script gives for you a easy way to write your an *.eml dumps, using a Proxmark 3.
    It's working for 4 and 7 bytes NXP MIFARE Classic 1K cards.
    The script has including an injection of UID changig for the Chinese Magic Cards GEN 3.
    
    Whith choosen an *.eml file you can do:

    1. Write it to the equals of current card UID.
    2. Write it to anther card with changable UID.
    3. Send command to lock UID for the Chinese Magic Cards GEN 3.
    4. Erease all data at the card and set the FFFFFFFFFFFF keys, and Access Conditions to 78778800.
]]
example = [[
    1. script run hf-writer
]]
usage = [[
    You should choose your *.eml dump from being list to write it to the card by wizard
]]

---
-- Usage help
local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print(example)
    print(usage)
end

local function read()
    u = read14a.read(true, true).uid
    return u
end

local function fkey()
    f = 'FFFFFFFFFFFF'
    return f
end

local function finish()
    read14a.disconnect()
    core.clearCommandBuffer()
end

local function wait()
    read14a.waitFor14443a()
end

local function main(args)
    -- Arguments for the script
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end

    --File lienght check for detect 4 or 7 bytes
    wait()
    print(tab)
    if string.len(read()) == 14 then -- Detect 7 byte card
        l = 29 -- 7 byte length of eml file
        s = 7
        e = 20
    else
        l = 23 -- 4 byte length of eml file
        s = 7
        e = 14
    end 
    ---Listern EML files at Client catalog
    for _ in io.popen([[dir ".\" /b]]):lines() do -- for UNIX: ls
        if string.find(_, '%.eml$') then
            if string.len(_) == l then -- There length of eml file
                a = a + 1
                uid[a] = string.sub(tostring(_), s, e) -- Cut UID from eml file
                print(' ' .. a .. ' ' .. '|' .. ' ' .. uid[a])
            end
        end
    end 

    print(tab)
    print(' Your card has ' .. read() .. ' UID number\n')
    print(' Choice your dump number to write (from 1 until ' .. a .. ')')
    print(tab)
    io.write(' --> ')   

    local no = tonumber(io.read())
    local dump = io.open('./hf-mf-' .. uid[no] .. '-data.eml', 'r');    

    print(tab)
    print(' You have been selected ' .. no .. ' card dump, it UID is ' .. uid[no])  
    ---EML get B key from opened EML file
    for _ in dump:lines() do table.insert(eml, _); end
    for i = 1, #eml do
        if (i % 4 == 0) then
            repeat
                b = b + 1
                B[b] = string.sub(tostring(eml[i]), (string.len(eml[i]) - 11),
                                  string.len(eml[i])) -- Cut key from block
            until b % 4 == 0
        end
    end 

    print(tab)  
    ---UID Changing
    if (utils.confirm(' Do the UID changing?') == true) then
        wait()
        core.console('hf 14a raw -s -c -t 2000 90f0cccc10' .. tostring(eml[1]))
        print(tab)
        print(' The new card UID is: ' .. read())
    end 

    print(tab)  
    ---UID Blocking
    if (utils.confirm(' Would you like to BLOCK the UID for any changing?') == true) then
        wait()
        core.console('hf 14a raw -s -c -t 2000 90fd111100')
    end 

    print(tab)  
    ---Wriiting block
    if (utils.confirm(' At this case are you using a Blank Card?') == true) then
        wait()
        for i = 1, #eml do
            core.console('hf mf wrbl ' .. (i - 1) .. ' B ' .. fkey() .. ' ' ..
                             tostring(eml[i]))
        end
        print(tab)
    else
        print(tab)
        if (utils.confirm(
            ' Do you wishing DELETE ALL DATA and rewrite all keys to ' .. fkey() ..
                '?') == true) then
            wait()
            for i = 1, #eml do
                if (i % 4 == 0) then
                    core.console(
                        'hf mf wrbl ' .. (i - 1) .. ' B ' .. tostring(B[i]) .. ' ' ..
                            fkey() .. '78778800' .. fkey())
                else
                    core.console(
                        'hf mf wrbl ' .. (i - 1) .. ' B ' .. tostring(B[i]) .. ' ' ..
                            string.rep('0', 32))
                end
            end
        else
            wait()
            for i = 1, #eml do
                core.console('hf mf wrbl ' .. (i - 1) .. ' B ' .. tostring(B[i]) ..
                                 ' ' .. tostring(eml[i]))
            end
        end
    end
    finish()
end
main(args)

---General thinks for the future:
---Add support another types of dumps: BIN, JSON
---Maybe it will be not only as `hf-writer`, like a universal dump manager.
---Add undependence from the operation system. At the moment code not working in Linux.
---Add more chinesse backdoors RAW commands for UID changing (find RAW for the 4 byte familiar chinese card, from native it soft: http://bit.ly/39VIDsU)
---Hide system messages when you writing a dumps, replace it to some of like [#####----------] 40%
