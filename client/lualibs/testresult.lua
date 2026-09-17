--[[
    Verdict vocabulary shared by the test scripts under luascripts/tests/.
--]]

local ansicolors = require('ansicolors')

local Result = {}

Result.OK   = '( ' .. ansicolors.green  .. 'ok' .. ansicolors.reset .. ' )'
Result.FAIL = '( ' .. ansicolors.red    .. 'fail' .. ansicolors.reset .. ' )'
Result.NEW  = '( ' .. ansicolors.yellow .. 'new'  .. ansicolors.reset .. ' )'
Result.SKIP = '( -- )'

Result.RULE = string.rep('-', 108)

local Counter = {}
Counter.__index = Counter

function Result.counter()
    return setmetatable({ pass = 0, fail = 0, other = 0 }, Counter)
end

function Counter:add(ok)
    if ok == nil then
        self.other = self.other + 1
    elseif ok then
        self.pass = self.pass + 1
    else
        self.fail = self.fail + 1
    end
    return ok
end

function Counter:total()
    return self.pass + self.fail + self.other
end

---
-- Returns the number of failures, so a caller can use it as an exit status.
function Counter:summary()

    if self:total() == 0 then
        print('[!] no tests were run ' .. Result.FAIL)
        return 1
    end

    if self.fail == 0 and self.other == 0 then
        print('[+] all tests ' .. Result.OK)
    else
        print(('[!] %d / %d tests '):format(self.pass, self:total()) .. Result.FAIL)
    end
    return self.fail
end

return Result
