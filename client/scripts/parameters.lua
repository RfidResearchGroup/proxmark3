-- The getopt-functionality is loaded from pm3/getopt.lua
-- Have a look there for further details
getopt = require('getopt')

copyright = ''
usage = 'script run parameters.lua -a 1 -blala -c -de'
author = 'Martin Holst Swende'
version = 'v1.0.1'
desc = [[
This is an example script to demonstrate handle parameters in scripts.
For more info, check the comments in the code
]]
example = [[
]]
usage = [[
]]
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

local function main(args)

    print('These parameters were passed')
    --[[
    When passing parameters,
    x:      means that a value should follow x
    y       means that 'y' is a flag, either on or off
    So, the string a:b:def means that we support up to
    5 parameters; two with values and three flags. The following
    should be valid:

    script run parameters.lua -a 1 -blala -c -de

    Notice two things:
    1. 'blala' works just like 'b lala', both set 'b' to 'lala'
    2. Flags can be put together, '-de' is the same as '-d -e'
    3. The format -b=lala is *not* supported
    4. The format b lala (without -) is *not* supported
    --]]

    for o, a in getopt.getopt(args, 'ha:b:ced') do
        if o == 'h' then return help() end
        print(o, a)
    end
end


--[[
In the future, we may implement so that scripts are invoked directly
into a 'main' function, instead of being executed blindly. For future
compatibility, I have done so, but I invoke my main from here.
--]]
main(args)
