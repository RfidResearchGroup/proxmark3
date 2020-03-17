local utils = require('utils')
local read14a = require('read14a')
local uid = {} -- Array for eml files
local B = {} -- Array for B keys
local eml = {} -- Array for data in block 32 dig
local a = 0
local b = 0
local tab = string.rep('-', 64)

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

local function wait() read14a.waitFor14443a() end

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

if (utils.confirm(' Do the UID changing?') == true) then
    wait()
    core.console('hf 14a raw -s -c -t 2000 90f0cccc10' .. tostring(eml[1]))
    print(tab)
    print(' The new card UID is: ' .. read())
end

print(tab)

if (utils.confirm(' Would you like to BLOCK the UID for any changing?') == true) then
    wait()
    core.console('hf 14a raw -s -c -t 2000 90fd111100')
end

print(tab)

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
