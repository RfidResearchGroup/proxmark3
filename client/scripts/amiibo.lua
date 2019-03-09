local utils = require('utils')
local cmds = require('commands')
local Amiibo = require('amiibolib')
local reader = require('read14a')
local bin = require('bin')
local emu = require('emulator')
local luamiibo_open, err = package.loadlib("./libluamiibo.so", "luaopen_luamiibo")

if err then
   print(err)
   return
end

local luamiibo = luamiibo_open()

local function nfc_read_amiibo ()

   local command = Command:new{cmd = cmds.CMD_MIFAREU_READCARD, arg1 = 0, arg2 = 135}

   local result, err = reader.sendToDevice(command)
   if result then
      -- Do Mifare Ultralight read
      local count, cmd, arg0, data_len, offset = bin.unpack('LLLL', result)

      if arg0 == 0 then
         return nil, "Card select failed"
      end

      -- Do GetFromBigBuf
      local data = core.GetFromBigBuf(offset, data_len)

      return data, err
   else
      return nil, "Couldn't read Amiibo"
   end
end


local function emulate_amiibo (amiibo_data)
   -- Make UID args
   -- Use known ID/sig for known ECDSA signature - REPLACE ME!
   local uid_bytes = '\x00\x04\xFF\xFF\xFF\xFF\xFF\xFF'
   local ecc_sig = ''
      .. '\x00\x00\x00\x00\x00\x00\x00\x00'
      .. '\x00\x00\x00\x00\x00\x00\x00\x00'
      .. '\x00\x00\x00\x00\x00\x00\x00\x00'
      .. '\x00\x00\x00\x00\x00\x00\x00\x00'

   if amiibo_data:len() == 520 then
      -- Add common ending bytes
      print('Added missing ending bytes')
      amiibo_data = amiibo_data
         .. '\x01\x00\x0F\xBD\x00\x00\x00\x04'
         .. '\x5F\x00\x00\x00\x00\x00\x00\x00'
         .. '\x00\x00\x00\x00'
   end

   if amiibo_data:len() == 572 then
      -- Get ECC signature and use original serial
      uid_bytes = '\x00' .. amiibo_data:sub(1,3) .. amiibo_data:sub(5,8)
      ecc_sig = amiibo_data:sub(541, 572)
      print('Amiibo image contains ECC signature', hexlify(ecc_sig))
      --amiibo_data = amiibo_data:sub(1,540)
   elseif amiibo_data:len() == 540 then
      if uid_bytes ~= '\x00\x04\xFF\xFF\xFF\xFF\xFF\xFF' then
         print('Using known ECC sig pair')
      else
         print('No known ECC/sig pair; using null signature')
         uid_bytes = '\x00' .. amiibo_data:sub(1,3) .. amiibo_data:sub(5,8)
      end
      amiibo_data = amiibo_data .. ecc_sig
   else
      print('Unusual Amiibo image size', amiibo_data:len())
   end

   -- Send amiibo data to emulator memory. If the Amiibo was just scanned, this
   -- is already set!
   if not emu:set_mem(amiibo_data, false) then
      print('Failed to set emulator card memory')
      return
   end

   -- Get UID parts
   local count, uid_first, uid_second = bin.unpack('>I>I', uid_bytes)
   print(string.format('Simulating with UID: 0x%04x 0x%04x', uid_first, uid_second))

   -- Begin simulating NTAG215
   local simCmd = Command:new{cmd = cmds.CMD_SIMULATE_TAG_ISO_14443a, arg1 = 7, arg2 = uid_first, arg3 = uid_second}
   local _, err = reader.sendToDevice(simCmd)
   if err then
      print('Failed to start simulator', err)
      return
   else
      print('Starting simulator')
   end
end


local function test_packing()
   -- Load Pikachu dump instead
   local dumpfile = io.open("pika.bin", "rb")
   local pikachu = dumpfile:read("*all")

   local unpacked_pika = luamiibo.unpack(pikachu)
   local packed_data = luamiibo.pack(unpacked_pika)

   print('Original', utils.hexlify(pikachu))
   print('Unpacked', utils.hexlify(unpacked_pika))
   print('Packed', utils.hexlify(packed_data))
end


local function load_sim(argv)
   local tag = assert(io.open(argv[2], "rb"))
   local data = tag:read("*all")
   tag:close()

   emulate_amiibo(data)
   return
end


local function dump_sim(argv)
   local keypath = argv[2]
   if keypath == nil then
      keypath = 'amiitool_keys.bin'
   end
   luamiibo.load_keys(keypath)

   -- Read all 135 pages
   dump = emu:get_mem(540)

   if dump == false then
      print('Failed to read emulator memory')
   else
      local amiiboData = Amiibo:new{tag = dump}
      print('Dumped ' .. dump:len() .. ' bytes')
      print(hexlify(dump))
      print('Nickname: ' .. utils.hexlify(amiiboData:display_nickname()))

      -- Write dump to file
      local filename = argv[2]
      if filename ~= nil then
         local outfile = assert(io.open(filename, "wb"))
         outfile:write(dump)
         outfile:close()
         print('Wrote to ' .. filename)
      else
         print('No output file specified')
      end
   end
end


local function main(args)
   argv = {}
   for arg in string.gmatch(args, "%S+") do
      table.insert(argv, arg)
   end

   -- Load and emulate Amiibo from image
   if argv[1] == 'help' then
      print('read - scan amiibo')
      print('load <amiibo.bin> - load and simulate amiibo')
      print('dump [output_file] - dump card memory')
      print('help - print this help')
      return
   elseif argv[1] == 'load' then
      load_sim(argv)
      return
   elseif argv[1] == 'dump' then
      dump_sim(argv)
      return
   elseif argv[1] ~= 'read' and argv[1] ~= nil then
      print('Unknown command')
   end

   local keypath = argv[2]
   if keypath == nil then
      keypath = 'amiitool_keys.bin'
   end

   if luamiibo.load_keys(keypath) then
      print('Loaded retail keys from ' .. keypath)
   else
      print('Failed to load retail keys from ' .. keypath)
      return
   end

   local tag, err = nfc_read_amiibo()
   if err then
      print(err)
      return
   elseif tag:len() ~= 540 then
      print('Incorrect tag data size ' .. tag:len())
      return
   end

   parsed_tag = reader.parse1443a(tag)
   print('Tag type:', parsed_tag.name)
   print('Tag UID:', parsed_tag.uid)
   print('Tag len:', tag:len())
   --print('Tag data:', utils.hexlify(tag))

   local amiiboData = Amiibo:new{tag = tag}

   --print('Unpacked:', utils.hexlify(amiiboData.plain))
   --print('Repacked:', utils.hexlify(amiiboData:export_tag()))

   print('Figure ID:', utils.hexlify(amiiboData.figure_id))
   print('Settings init:', amiiboData.settings_initialized)

   if amiiboData.settings_initialized then
      print('Nickname:', amiiboData:display_nickname())
      print('Appdata writes:', amiiboData.appdata_counter)
   end

   print('UID:', utils.hexlify(amiiboData.uid))
   print('Write key:', utils.hexlify(amiiboData:get_pwd()))

   --print('Attempting emulation...')
   --emulate_amiibo(amiiboData:export_tag())
   return
end

main(args)
