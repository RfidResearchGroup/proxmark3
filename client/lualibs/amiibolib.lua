local luamiibo_open, err = package.loadlib("./libluamiibo.so", "luaopen_luamiibo")

if err then
   print(err)
   return
end

local luamiibo = luamiibo_open()

local FLAG_SETTINGS_INITIALIZED = 4
local FLAG_APPDATA_INITIALIZED = 3

local Amiibo = {}
Amiibo.__index = Amiibo

function Amiibo:new (o)
   o = o or {}
   setmetatable(o, self)

   if o.tag ~= nil then
      o:load_tag(o.tag)
   end
   return o
end

function Amiibo:load_tag (tag)
   self.plain = luamiibo.unpack(tag)

   -- UID
   local raw_uid = string.sub(self.plain, 469, 469 + 8)
   self.uid = string.sub(raw_uid, 1, 3) .. string.sub(raw_uid, 5, 8)

   -- Settings
   local count, flags = bin.unpack('C', string.sub(self.plain, 45, 45))
   self.setting_flags = flags
   self.settings_initialized = self:check_flag(FLAG_SETTINGS_INITIALIZED)
   self.appdata_initialized = self:check_flag(FLAG_APPDATA_INITIALIZED)

   local _, appdatacounter =  bin.unpack('>S', string.sub(self.plain, 49, 50))
   self.appdata_counter = appdatacounter

   self.figure_id = string.sub(self.plain, 477, 477 + 8)

   -- UTF-16 nickname string
   self.nickname = string.sub(self.plain, 57, 76)
end


function Amiibo:export_tag ()
   return luamiibo.pack(self.plain)
end


function Amiibo:check_flag (power)
   local flag = math.pow(2, power)
   return flag == bit32.band(self.setting_flags, flag)
end


function Amiibo:get_pwd ()
   local xorkey = "\xaa\x55\xaa\x55"

   local result = ''
   for i = 1, 4 do
      result = result ..
         bin.pack('C',
         bit32.bxor(self.uid:byte(i+1),
                    self.uid:byte(i+3),
                    xorkey:byte(i)))
   end

   return result
end

-- Hack to make UTF-16 nicknames into regular char string
-- Only works for ASCII nicknames
function Amiibo:display_nickname()
   local nickname_tmp = self.nickname

   local nickname = ''
   for i = 1, nickname_tmp:len() do
      if i % 2 == 0 then
         nickname = nickname .. nickname_tmp:sub(i, i)
      end
   end

   return nickname
end

return Amiibo
