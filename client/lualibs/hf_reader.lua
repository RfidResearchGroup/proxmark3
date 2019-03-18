--[[
THIS IS WORK IN PROGREESS, very much not finished.

This library utilises other libraries under the hood, but can be used as a generic reader for 13.56MHz tags.
]]

local reader14443A = require('read14a')
local reader14443B = require('read14b')
local reader15693 = require('read15')

---
-- This method library can be set waits or a 13.56 MHz tag, and when one is found, returns info about
-- what tag it is.
--
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
local function waitForTag()
    print("Waiting for card... press any key to quit")
    local readers = {reader14443A, reader14443B, reader15693}
    local i = 0;
    while not core.ukbhit() do
        i = (i % 3) +1
        r = readers[i]
        print("Reading with ",i)
        res, err = r.read()
        if res then return res end
        print(err)
            -- err means that there was no response from card
    end
    return nil, "Aborted by user"
end

return {
    waitForTag = waitForTag,
}
