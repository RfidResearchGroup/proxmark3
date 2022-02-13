-- #!/usr/bin/env lua
-- os.execute("clear")
-- core.console('clear')

local DEBUG = true

-------------------------------------------------------------------------------------------------------------
-- USAGE:
-------------------------------------------------------------------------------------------------------------
-- Run me like this (connected via USB): ./pm3 -l ntag_bruteforce.lua
-- Run me like this (connected via Blueshark addon): ./client/proxmark3 /dev/rfcomm0 -l ./ntag_bruteforce.lua
-------------------------------------------------------------------------------------------------------------
-- VER  | AUTHOR         | DATE         | CHANGE
-------------------------------------------------------------------------------------------------------------
-- 1.0  | Keld Norman,   | 30 okt. 2021 | Initial version
-- 1.1  | Keld Norman,   | 30 okt. 2021 | Added: Press enter to stop the script
-- 1.2  | Keld Norman,   | 15 Nov. 2021 | Added: Check for correct hex values for bruteforcing
-- 1.3  | Keld Norman,   | 15 Nov. 2021 | Added: Added a skip ping option
-------------------------------------------------------------------------------------------------------------
-- TODO:
-------------------------------------------------------------------------------------------------------------
-- Output file not implemented yet
-------------------------------------------------------------------------------------------------------------
-- SPEEDTEST
-------------------------------------------------------------------------------------------------------------
-- BRUTEFORCE ALL HEX COMBINATIONS:
--
-- With the -t 10 ( lowest possible delay ) and FFFFFFFF attempts or in decimal 4.294.967.295 combinations
--
-- My test showed that this script can do 255 password attempts in approxemately 170 seconds
--
-- That is : 255 / 170 = 1,5 attempt/second
--
-- So ..  4.294.967.295 combinations / 1,5 per second = 2.863.311.530 seconds and it is roughly 90 years
--
-------------------------------------------------------------------------------------------------------------
-- PASSWORD LISTS:
-------------------------------------------------------------------------------------------------------------
-- Crunch can generate all (14.776.336) combinations of 4 chars with a-z + A-Z + 0-9 like this:
--
-- crunch 4 4 "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" -o keys/4_chars_and_digits.list
--
-- for LINE in $(cat keys/4_chars_and_digits.list) ; do echo -n ${LINE} |xxd -p -u;done > keys/4_chars_and_digits_hex.list
--
-------------------------------------------------------------------------------------------------------------
-- Required includes
-------------------------------------------------------------------------------------------------------------
local getopt      = require('getopt')
local ansicolors  = require('ansicolors')
local md5         = require('md5')
-------------------------------------------------------------------------------------------------------------
-- Variables
-------------------------------------------------------------------------------------------------------------
local command = ''
local timeout = 10 -- do not set this below 10 (if so it will not test the password)
local option, argument
local use_ping = true
local bruteforce = true
local ntagformat = false
local input_file_valid = false
local password_is_ascii = true
local pass_text = "Passwords in file is treated as: ASCII"
local bruteforce_status_file = 'ntag_status.txt'
-------------------------------------------------------------------------------------------------------------
copyright = ''
script    = 'Script      : ntag_bruteforce.lua'
author    = 'Author      : Keld Norman'
version   = 'Version     : 1.3.0'
-------------------------------------------------------------------------------------------------------------
desc      = [[Description : Bruteforces 7 byte UID NTAG protected with a 32 bit password
      .-.
     /   \         .-.
    /     \       /   \       .-.     .-.     _   _
+--/-------\-----/-----\-----/---\---/---\---/-\-/-\/\/---
  /         \   /       \   /     '-'     '-'
 /           '-'         '-'
 ]]
-------------------------------------------------------------------------------------------------------------
example = [[
Example of how to run the script with bruteforcing of continuously HEX numbers with 1 secound delay between tests:

    script run ntag_bruteforce -s 00000000 -e FFFFFFFF -t 1000  -o /var/log/ntag_bruteforce.log

Example of how to run the script and bruteforc the card using passwords from the input file with 1s delay between tests

    script run ntag_bruteforce -i /home/my_4_char_passwords_list.txt -o /var/log/ntag_bruteforce.log
]]

-------------------------------------------------------------------------------------------------------------
usage = [[
script run ntag_bruteforce [-s <start_id>] [-e <end_id>] [-t <timeout>] [ -o <output_file> ] [ -p ] [ -h for help ]
script run ntag_bruteforce [-i <input_file>] [-t <timeout>] [ -o <output_file> ] [ -n | -x ] [ -p ] [ -h for help ]

DESCRIPTION
This script will test either an 8 digit hexadecimal code or 4 char stings (will be converted to an 8 digit hex string )
against NFC cards of the type NTAG21x protected by a 32 bit password.
Read more about NTAGs here: https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf

]]
-------------------------------------------------------------------------------------------------------------
arguments = [[
    -h                            This help
    -i       input_file           Read 4 char ASCII values to test from this file (will override -s and -e )
    -o       output_file          Write output to this file
    -t       0-99999, pause       Timeout (ms) between cards 1000 = 1 second (use the word 'pause' to wait for user input)
    -p                            Skip Ping

    # Either use the continuously test:
    -s       0-0xFFFFFFFF         Start HEX value
    -e       0-0xFFFFFFFF         End   HEX value

    # Or use a list of passwords from a file:
    -x       Passwords in HEX     Password file (-i) contains HEX values (4 x 2hex -> 32 bit/line like: 00112233)
    -n       NTAG Tools format    Bruteforce with first 8 hex values of a md5 hash of the password
                                  The password will be prefixed with hex value 20 (space) if the string/password is < 4 chars
]]
-------------------------------------------------------------------------------------------------------------
-- FUNCTIONS
-------------------------------------------------------------------------------------------------------------
-- Check availability of file
local function file_check(file_name)
 local exists = io.open(file_name, "r")
 if not exists then
  exists = false
 else
  exists = true
 end
 return exists
end

-- read lines from a file
local function read_lines_from(file)
 print(ansicolors.yellow..'\nPlease wait while loading password file..'..ansicolors.reset)
 readlines = {}
 for line in io.lines(file) do
  readlines[#readlines + 1] = line
 end
 print(ansicolors.yellow..'\nLoading password file finished'..ansicolors.reset)
 return readlines
end

-- write to file
local function writeOutputBytes(bytes, outfile)
 local fileout,err = io.open(outfile,"wb")
 if err then
  print("### ERROR - Faild to open output-file "..outfile)
  return false
 end
 for i = 1, #bytes do
  fileout:write(string.char(tonumber(bytes[i], 16)))
 end
 fileout:close()
 print("\nwrote "..#bytes.." bytes to "..outfile)
 return true
end

-- find number of entrys in a table
local function tablelength(table)
 local count = 0
 for _ in pairs(table) do count = count + 1 end
 return count
end

-- debug print function
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

-- when errors occur
local function oops(err)
 print(ansicolors.red..'\n### ERROR - '..err..ansicolors.reset)
 core.clearCommandBuffer()
 return nil, err
end

-- Usage help
local function help()
 print(copyright)
 print(script)
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

--- Print user message
local function msg(msg)
 print( string.rep('--',20) )
 print('')
 print(msg)
 print('')
 print( string.rep('--',20) )
end

-- Convert a string in to a hex string
local function convert_string_to_hex(str)
 return (
  str:gsub('.', function (c)
    return string.format('%02X', string.byte(c))
   end
  )
 )
end

-- Check if string is 4 chars ascii (32 bit) = 8 chars hex
local function check_if_string_is_hex(value)
 local patt = "%x%x%x%x%x%x%x%x"
 if string.find(value, patt) then
  return true
 else
  return false
 end
end

-- Check if number is a 0x???????? numbe (32 bit hex value)
local function check_if_number_is_hex(value)
 local num = tonumber(value)  -- would return nil...
 if not num then
  return false
 end
 if (num < 0x00000000 or num > 0xffffffff) then  -- ...and fail here
  return false
 end
 return true
end

-------------------------------------------------------------------------------------------------------------
-- MAIN FUNCTION
-------------------------------------------------------------------------------------------------------------
local function main(args)
 local i = 0
 local bytes = {}
 local start_id = 0x00000000
 local end_id = 0xFFFFFFFF
 local infile, outfile
 -- stop if no args is given
 if #args == 0 then
  print(ansicolors.red..'\n### ERROR - Missing parameters'..ansicolors.reset)
  return help()
 end
-------------------------------------------------------------------------------------------------------------
-- Get arguments
-------------------------------------------------------------------------------------------------------------
 for option, argument in getopt.getopt(args, ':s:e:t:i:o:pnxh') do
  -- error in options
  if optind == '?' then
   return print('Unrecognized option', args[optind -1])
  end
  -- no options
  if option == '' then
   return help()
  end
  -- start hex value
  if option == 's' then
   start_id = argument
  end
  -- end hex value
  if option == 'e' then
   end_id = argument
  end
  -- timeout
  if option == 't' then
   timeout = argument
  end
  -- input file
  if option == 'i' then
   infile = argument
   if (file_check(infile) == false) then
    return oops('Input file: '..infile..' not found')
   else
    input_file_valid = true
   end
   bruteforce = false
  end
  -- skip ping
  if option == 'p' then
   use_ping = false
  end
  -- passwordlist is hex values
  if option == 'x' then
   password_is_ascii = false
   pass_text = "Passwords in file is treated as: HEX"
   bruteforce = false
  end
  -- output file
  if option == 'o' then
   outfile = argument
   if (file_check(argument)) then
    local answer = utils.confirm('\nThe output-file '..argument..' already exists!\nthis will delete the previous content!\ncontinue?')
    if (answer == false) then
     return oops('Quiting')
    end
   end
  end
  -- bruteforce NTAG Tools encryption
  if option == 'n' then
   ntagformat = true
   bruteforce = false
  end
  -- help
  if option == 'h' then
   return help()
  end
 end
 -- min timeout is set to 1 sec if it is empty
 timeout = tonumber(timeout)
 if timeout < 10 then
  timeout = 10
 end
-------------------------------------------------------------------------------------------------------------
-- BRUTEFORCE
-------------------------------------------------------------------------------------------------------------
 -- select bruteforce method
 if bruteforce then
  if not check_if_number_is_hex(start_id) then
   print(ansicolors.red..'\n### ERROR - start_id value '..start_id..' is out of the range of a 32-bit integer (0 to 0xFFFFFFFF) - Did you forget to add 0x ?'..ansicolors.reset)
   return
  end
  if not check_if_number_is_hex(end_id) then
   print(ansicolors.red..'\n### ERROR - end_id value '..end_id..' is out of the range of a 32-bit integer (0 to 0xFFFFFFFF) - Did you forget to add 0x ?'..ansicolors.reset)
   return
  end
  -----------------------------------------------------
  -- START BRUTEFORCE WITH CONTINUOUSLY HEX NUMBERS  --
  -----------------------------------------------------
  command = 'hf mfu info -k %08X'
  msg('Bruteforcing NTAG Passwords\n\nStart value: '..start_id..'\nStop value : '..end_id..'\nDelay between tests: '..timeout..' ms')
  for hexvalue = start_id, end_id do
   if core.kbd_enter_pressed() then -- abort if key is pressed
    print("aborted by user")
    break
   end
   local cmd = string.format( command, hexvalue )
   core.console(cmd)
   print('[=] Tested password '..ansicolors.yellow..ansicolors.bright..string.format("%08X",hexvalue)..ansicolors.reset)
   print('[=] Ran command: "'..cmd..'"')
   --core.console('msleep -t'..timeout);
   if use_ping then
    print('[=] -------------------------------------------------------------')
    core.console('hw ping')
   end
   print('[=] -------------------------------------------------------------')
  end
  -----------------------------------------------------
  -- END BRUTEFORCE WITH CONTINUOUSLY HEX NUMBERS    --
  -----------------------------------------------------
 else
  if not input_file_valid then
   return oops('Can not bruteforce without a password list file ( -i password_list_file.txt ) ')
  end
  -----------------------------------------------------
  -- START BRUTEFORCE WITH PASSWORDS FROM A FILE    --
  -----------------------------------------------------
  local password
  local counter = 1
  local skip_to_next = 0
  local passwords_left_to_try
  local lines = read_lines_from(infile)
  local count_lines = tablelength(lines)
  msg('Bruteforcing NTAG Passwords\n\nUsing passwords from file: '..infile..'\nTesting '..count_lines..' passwords\nDelay between tests: '..timeout..' ms\n\n'..pass_text)
  while lines[counter] do
   if core.kbd_enter_pressed() then -- abort if key is pressed
    print("aborted by user")
    break
   end
   password = lines[counter]
   if ntagformat then -- "NFC Tools" uses md5 of the password and caps it to 8 chars
    local md5message = md5.sumhexa(password)
    -- print ('[=] Password is: "'..password..'" md5: '..md5message)
    password = string.sub(md5message,1,8)
   else
    if password_is_ascii then
     ------------
     -- ASCII
     ------------
     if string.len(password) > 4 then
      print('[!] Skipping password to long: '..password)
      skip_to_next = 1
     else
      password = convert_string_to_hex(password)
     end
    else
     ------------
     -- HEX
     ------------
     if string.len(password) ~= 8 then
      print('[!] WARNING - Skipping password not 8 chars (32 bit HEX): '..password)
      skip_to_next = 1
     else
      if not check_if_string_is_hex(password) then
       print('[!] WARNING - Skipping password not a valid hex string: '..password)
       skip_to_next = 1
      end
     end
    end
   end
   if skip_to_next == 0 then
   command = 'hf mfu info -k %4s'
    local cmd = string.format( command, password )
    core.console(cmd)
    if lines[counter] ~= password then -- show hex value (if not the password was a hex value already)
     print('[=] Tested password: "'..ansicolors.yellow..ansicolors.bright..lines[counter]..ansicolors.reset..'" (Hex: '..password..')')
    else
     print('[=] Tested password: "'..ansicolors.yellow..ansicolors.bright..lines[counter]..ansicolors.reset..'"')
    end
    passwords_left_to_try = count_lines - counter
    print('[+] Passwords left to try: '..ansicolors.green..ansicolors.bright..passwords_left_to_try..ansicolors.reset..' of '..ansicolors.green..ansicolors.bright..count_lines..ansicolors.reset)
    print('[=] Ran command: "'..cmd..'"')
    core.console('msleep -t'..timeout);
    if use_ping then
    print('[=] -------------------------------------------------------------')
     core.console('hw ping')
    end
    print('[=] -------------------------------------------------------------')
   end
   counter = counter+1
   skip_to_next = 0
  end
  -----------------------------------------------------
  -- END BRUTEFORCE WITH PASSWORDS FROM A FILE       --
  -----------------------------------------------------
 end
end
-------------------------------------------------------------------------------------------------------------
main(args)
-------------------------------------------------------------------------------------------------------------
