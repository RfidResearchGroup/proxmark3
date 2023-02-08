local getopt = require('getopt')
local ansicolors  = require('ansicolors')

copyright = ''
author = 'Shain Lakin'
version = 'v1.0.0'
desc =[[

This script modifies the DT NeXT implant (NTAG216) configuration pages.

- NeXT Defaults -

Default hf mfu info:
----------------------------------------------------------------------
[=] --- Tag Configuration
[=]   cfg0 [227/0xE3]: 04 00 00 E3
[=]                     - strong modulation mode disabled
[=]                     - page 227 and above need authentication
[=]   cfg1 [228/0xE4]: 00 05 00 00
[=]                     - Unlimited password attempts
[=]                     - NFC counter disabled
[=]                     - NFC counter not protected
[=]                     - user configuration writeable
[=]                     - write access is protected with password
[=]                     - 05, Virtual Card Type Identifier is default
[=]   PWD  [229/0xE5]: 00 00 00 00 - (cannot be read)
[=]   PACK [230/0xE6]: 00 00       - (cannot be read)
[=]   RFU  [230/0xE6]:       00 00 - (cannot be read)
----------------------------------------------------------------------

Default blocks 0xE0 to 0xE6:
-------------------------------------
[=] 224/0xE0 | 00 00 00 00 | 0 | ....
[=] 225/0xE1 | 4E 45 78 54 | 0 | NExT
[=] 226/0xE2 | 00 00 7F BD | 0 | ....
[=] 227/0xE3 | 04 00 00 E3 | 0 | ....
[=] 228/0xE4 | 00 05 00 00 | 0 | ....
[=] 229/0xE5 | 44 4E 47 52 | 0 | DNGR
[=] 230/0xE6 | 00 00 00 00 | 0 | ....
-------------------------------------
]]

example =[[

Set a new password of SUDO using the default password of DNGR:

    script run hf_ntag_dt -x pass -p DNGR -n SUDO

Enable password protection from hex block 04 onwards (User memory):

    script run hf_ntag_dt -x protect -p DNGR -a 04

Enable password protection from hex block E3 onwards (Configuration Pages):

    script run hf_ntag_dt -x protect -p DNGR -a E3

Disable password protection:

    script run hf_ntag_dt -x protect -p DNGR -a FF

Enable the counter and enable read + write password protection on password protected pages
(protected block start page specified using -x protect mode):

    script run hf_ntag_dt -x conf -p DNGR -c enable -m rw

Disable the counter and enable write only password protection on password protected pages
(protected block start specified using -x protect mode):

    script run hf_ntag_dt -x conf -p DNGR -c disable -m w

]]
usage = [[

    script run hf_ntag_dt -x pass -p <password> -n <new_password>
    script run hf_ntag_dt -x protect -p <password> -a <auth0_block>
    script run hf_ntag_dt -x conf -p <password> -c <enable/disable> -m <r/rw>

]]
arguments = [[
    -h      this help
    -x      mode (pass, protect, conf)
    -p      password (ascii)
    -n      new password (ascii)
    -a      auth0 block (hex)
    -c      counter (enable/disable)
    -m      protection mode (r/rw)
]]
---
--- Usage help
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
--- String to hex function
local function strhex(str)
    return (str:gsub(".", function(char) return string.format("%2x", char:byte()) end))
 end
---
-- Main
local function main(args)

    for o, a in getopt.getopt(args, 'b:m:c:a:p:x:n:h') do
        if o == 'm' then prot_mode = a end
        if o == 'c' then counter = a end
        if o == 'a' then auth0_block = a end
        if o == 'p' then passwd = strhex(a) end
        if o == 'x' then mode = a end
        if o == 'n' then new_pass = strhex(a) end
        if o == 'h' then return help() end
    end

    if mode == 'pass' then
        command = 'hf mfu wrbl -b 229 -d '..new_pass..' -k '..passwd
        msg('Writing '..new_pass..' to PASSWD block (229/0xE5) : \n\n'..command)
        core.console(command)
        command = 'hf mfu rdbl -b 0 -k '..new_pass..''
        msg('Verifying password is correctly set : \n\n'..command)
        core.console(command)
    elseif mode == 'conf' then
        if counter == 'enable' then
            if prot_mode == 'r' then
                command = 'hf mfu wrbl -b 228 -d 10050000 -k '..passwd
                msg('Enabling counter and setting write access to protected pages as password protected : \n\n'..command)
                core.console(command)
            elseif prot_mode == 'rw' then
                command = 'hf mfu wrbl -b 228 -d 90050000 -k '..passwd
                msg('Enabling counter and setting read/write access to protected pages as password protected : \n\n'..command)
                core.console(command)
            end
        elseif counter == 'disable' then
            if prot_mode == 'w' then
                command = 'hf mfu wrbl -b 228 -d 00050000 -k '..passwd
                msg('Disabling counter and setting write password protection on protected pages : \n\n'..command)
                core.console(command)
            elseif prot_mode == 'rw' then
                command = 'hf mfu wrbl -b 228 -d 80050000 -k '..passwd
                msg('Disabling counter and setting read/write password protection on protected pages : \n\n'..command)
                core.console(command)
            end
        end
    elseif mode == 'protect' then
        command = 'hf mfu wrbl -k '..passwd..' -b 227 -d 040000'..auth0_block
        msg('Enabling password protection from block '..auth0_block..' onwards : \n\n'..command)
        core.console(command)
    else
        return print(usage)
    end

    if command == '' then return print(usage) end


end
main(args)
