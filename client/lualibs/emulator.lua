local cmds = require('commands')
local utils = require('utils')
local reader = require('read14a')

local Emulator = {
   _VERSION = 'emulator.lua 0.1.0',
   _DESCRIPTION = 'emulator memory interface',
   BLOCK_SZ = 512,
   BLOCK_COUNT = 512 / 16
}

function Emulator:set_mem (data, clear_first)
    if clear_first then
        -- Clear out the emulator memory first
        local memclrCmd = Command:newMIX{cmd = cmds.CMD_MIFARE_EML_MEMCLR}

        local _, err = memclrCmd.sendMIX()
        if err then
            print('Failed to clear emulator memory:', err)
            return false
        else
            print('Cleared emulator memory')
        end
    end

   -- Can fit 32 16 byte blocks per command (512 total bytes max)
   for i = 0, (data:len() / self.BLOCK_SZ) do
      local cur_out_block = data:sub((i*self.BLOCK_SZ) + 1, (i*self.BLOCK_SZ) + self.BLOCK_SZ)
      print(string.format('Transmission #%u: %u bytes', i, cur_out_block:len()))

      -- arg1: start block number
      -- arg2: block count
      local memsetCmd = Command:newMIX{cmd = cmds.CMD_MIFARE_EML_MEMSET,
                                       data = utils.hexlify(cur_out_block),
                                       arg1 = i * self.BLOCK_COUNT,
                                       arg2 = self.BLOCK_COUNT}

      -- Send command and wait for response
      local _, err = memsetCmd.sendMIX()
      if err then
         print('Failed setting memory', err)
         return false
      end
   end

   print('Emulator memory set')
   return true
end

-- Read <size> bytes from emulator memory
function Emulator:get_mem (size)
   local MAX_BLOCKS = 4
   local result = ''

   -- We can request a maximum of 4 blocks (16 bytes each) per command,
   -- according to mifarecmd.c
   for i = 0, (size / (MAX_BLOCKS * 16)) do
      -- arg1: start block number
      -- arg2: block count (max 4)
      local getmemCmd = Command:newMIX{cmd = cmds.CMD_MIFARE_EML_MEMGET,
                                       arg1 = i * MAX_BLOCKS,
                                       arg2 = MAX_BLOCKS,
                                       arg3 = 0}

      local response, err = getmemCmd.sendMIX()
      if err then
         print('Failed getting memory:', err)
         return false
      end

      -- USB data begins after four 64-bit values
      local data_begin = ((64/8) * 4) + 1
      response = string.sub(response, data_begin)

      -- Truncate to the received 16 byte blocks
      response = string.sub(response, 1, 16 * MAX_BLOCKS)

      result = result .. response
   end

   return string.sub(result, 1, size)
end

return Emulator
