local getopt = require('getopt')

copyright = 'Copyright (c) 2019 IceSQL AB. All rights reserved.'
author = 'Christian Herrmann'
version = 'v1.0.0'
desc = [[
This script initialize a Proxmark3 RDV4.0 with
  - uploading dictionary files to flashmem
  - configuring the LF T55X7 device settings
 ]]
example = [[

     script run init_rdv4
]]
usage = [[
script run init_rdv4 -h

Arguments:
    -h             : this help
]]

local DEBUG = true
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
    print('Example usage')
    print(example)
    print(usage)
end
---
-- The main entry point
function main(args)
    local dash = string.rep('--', 20)

    print( dash )
    print( dash )
    print()

    -- Read the parameters
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end

    print('Prepping your Proxmark3 RDV4')

    -- Upload dictionaries
    print('Uploading dictionaries to RDV4 flashmemory')
    print(dash)
    core.console('mem load f mfc_default_keys m')
    core.console('mem load f t55xx_default_pwds t')
    core.console('mem load f iclass_default_keys i')
    print(dash)

    -- T55x7 Device configuration
    print('Configure T55XX device side to match RDV4')
    print(dash)
    core.console('lf t55xx deviceconfig r 0 a 29 b 17 c 15 d 47 e 15 p')
    core.console('lf t55xx deviceconfig r 1 a 29 b 17 c 18 d 50 e 15 p')
    core.console('lf t55xx deviceconfig r 2 a 29 b 17 c 18 d 40 e 15 p')
    core.console('lf t55xx deviceconfig r 3 a 29 b 17 c 15 d 31 e 15 f 47 g 63 p')

    print('')
    print('')
    core.console('hw status')
    print(dash)

    print('all done!')

end

main(args)
