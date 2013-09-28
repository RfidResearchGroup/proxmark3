
--[[This file is an adaptation from the following source:

https://github.com/attractivechaos/klib/blob/master/lua/klib.lua

]]

--[[
  The MIT License
  
  Copyright (c) 2011, Attractive Chaos <attractor@live.co.uk>
  
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
]]--


local function split(txt)
  local retval =  {};
  for i in string.gmatch(txt, "%S+") do
    table.insert(retval,i)
  end
  return retval
end


-- Description: getopt() translated from the BSD getopt(); compatible with the default Unix getopt()
--[[ Example:
  for o, a in os.getopt(arg, 'a:b') do
    print(o, a)
  end
]]--

local function getopt(args, ostr)
  -- Modification to handle strings instead of tables:
  if type(args) == 'string' then
    args = split(args)
  end

  local arg, place = nil, 0;
  return function ()
    if place == 0 then -- update scanning pointer
      place = 1
      if #args == 0 
        or args[1]:sub(1, 1) ~= '-' then 
        place = 0; return nil end
      if #args[1] >= 2 then
        place = place + 1
        if args[1]:sub(2, 2) == '-' then -- found "--"
          place = 0
          table.remove(args, 1);
          return nil;
        end
      end
    end
    local optopt = args[1]:sub(place, place);
    place = place + 1;
    local oli = ostr:find(optopt);
    if optopt == ':' or oli == nil then -- unknown option
      if optopt == '-' then return nil end
      if place > #args[1] then
        table.remove(args, 1);
        place = 0;
      end
      return '?';
    end
    oli = oli + 1;
    if ostr:sub(oli, oli) ~= ':' then -- do not need argument
      arg = nil;
      if place > #args[1] then
        table.remove(args, 1);
        place = 0;
      end
    else -- need an argument
      if place <= #args[1] then  -- no white space
        arg = args[1]:sub(place);
      else
        table.remove(args, 1);
        if #args == 0 then -- an option requiring argument is the last one
          place = 0;
          if ostr:sub(1, 1) == ':' then return ':' end
          return '?';
        else arg = args[1] end
      end
      table.remove(args, 1);
      place = 0;
    end
    return optopt, arg;
  end
end

return { getopt = getopt } 
