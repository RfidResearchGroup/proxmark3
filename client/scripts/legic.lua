--[[	
(example)	Legic-Prime Layout with 'Kaba Group Header'
      +----+----+----+----+----+----+----+----+
  0x00|MCD |MSN0|MSN1|MSN2|MCC | 60 | ea | 9f |		
      +----+----+----+----+----+----+----+----+
  0x08| ff | 00 | 00 | 00 | 11 |Bck0|Bck1|Bck2|
      +----+----+----+----+----+----+----+----+
  0x10|Bck3|Bck4|Bck5|BCC | 00 | 00 |Seg0|Seg1|
      +----+----+----+----+----+----+----+----+
  0x18|Seg2|Seg3|SegC|Stp0|Stp1|Stp2|Stp3|UID0|
      +----+----+----+----+----+----+----+----+
  0x20|UID1|UID2|kghC|
      +----+----+----+
--]]

example = "script run legic"
author  = "Mosci"
desc =
[[

This script helps you to read, create and modify Legic Prime Tags (MIM22, MIM256, MIM1024)
it's kinda interactive with following commands in three categories:

    Data I/O           Segment Manipulation        File I/O   
------------------     --------------------      ---------------
  rt => read    Tag     ds => dump   Segments     lf => load File
  wt => write   Tag     as => add    Segment      sf => save File 
  ct => copy io Tag     es => edit   Segment      xf => xor  File
  tc => copy oi Tag     ed => edit   Data     
  di => dump  inTag     rs => remove Segment
  do => dump outTag     cc => check  Segment-CRC                  
                        ck => check  KGH                
                        tk => toggle KGH-Flag
  q => quit             xc => get    KGH-Str      h => this Help 
 
 Data I/O 
 rt: 'read tag'         - reads a tag placed near to the PM3
 wt: 'write tag'        - writes the content of the 'virtual inTag' to a tag placed near to th PM3
                          without the need of changing anything - MCD,MSN,MCC will be read from the tag
                          before and applied to the output.
 ct: 'copy tag'         - copy the 'virtual Tag' to a second 'virtual TAG' - not usefull yet, but inernally needed
 tc: 'copy tag'         - copy the 'second virtual Tag' to 'virtual TAG' - not usefull yet, but inernally needed
 di: 'dump inTag'       - shows the current content of the 'virtual Tag'
 do: 'dump outTag'      - shows the current content of the 'virtual outTag'

 Segment Manipulation 
 (all manipulations happens only in the 'virtual inTAG' - they need to be written with 'wt' to take effect)
 ds: 'dump Segments'    - will show the content of a selected Segment
 as: 'add Segment'      - will add a 'empty' Segment to the inTag
 es: 'edit Segment'     - edit the Segment-Header of a selected Segment (len, WRP, WRC, RD, valid)
                          all other Segment-Header-Values are either calculated or not needed to edit (yet)
 ed: 'edit data'        - edit the Data of a Segment (Stamp & Payload)
 rs: 'remove segment'   - removes a Segment (except Segment 00, but this can be set to valid=0 for Master-Token)
 cc: 'check Segment-CRC'- checks & calculates (if check failed) the Segment-CRC of all Segments
 ck: 'check KGH-CRC'    - checks the and calculates a 'Kaba Group Header' if one was detected
                          'Kaba Group Header CRC calculation'
 tk: 'toggle KGH'       - toglle the (script-internal) flag for kgh-calculation for a segment
 xc: 'etra c'           - show string that was used to calculate the kgh-crc of a segment
  
 Input/Output
 lf: 'load file'        - load a (xored) file from the local Filesystem into the 'virtual inTag'
 sf: 'save file'        - saves the 'virtual inTag' to the local Filesystem (xored with Tag-MCC)
 xf: 'xor file'         - saves the 'virtual inTag' to the local Filesystem (xored with choosen MCC - use '00' for plain values)
 
]]

--- requirements
local utils   = require('utils')
local getopt  = require('getopt')

--- global variables / defines
local bxor    = bit32.bxor
local bbit    = bit32.extract
local input   = utils.input
local confirm = utils.confirm

--- Error-Handling & Helper
-- This is only meant to be used when errors occur
function oops(err)
	print("ERROR: ",err)
	return nil, err
end

---  
-- Usage help
function help()
	print(desc)
	print("Example usage")
	print(example)
end

--- 
-- table check helper
function istable(t) 
  return type(t) == 'table' 
end

---
-- put certain bytes into a new table
function bytesToTable(bytes, bstart, bend)
  local t={}
  for i=0, (bend-bstart) do
    t[i]=bytes[bstart+i]
  end
  return t
end

--- 
-- xor byte (if addr >= 0x22 - start counting from 1 => 23)
function xorme(hex, xor, index)
	if ( index >= 23 ) then
		return ('%02x'):format(bxor( tonumber(hex,16) , tonumber(xor,16) ))
	else
		return hex
	end
end

--- 
-- (de)obfuscate bytes
function xorBytes(inBytes, crc)
	local bytes = {}
	for index = 1, #inBytes do
		bytes[index] = xorme(inBytes[index], crc, index)
	end
	if (#inBytes == #bytes) then
		-- replace crc
		bytes[5] = string.sub(crc,-2)
		return bytes
	else
		print("error: byte-count missmatch")
		return false
	end
end

--- 
-- check availability of file
function file_check(file_name)
  local file_found=io.open(file_name, "r")      
  if file_found==nil then
    return false
  else
    return true
  end
end

---
-- read file into virtual-tag
function readFile(filename)
  local bytes = {}
  local tag = {}
	if (file_check(filename)==false) then
		return oops("input file: "..filename.." not found")
	else
		bytes = getInputBytes(filename)
		if (bytes == false) then return oops('couldnt get input bytes') 
    else
      -- make plain bytes
      bytes = xorBytes(bytes,bytes[5])
      -- create Tag for plain bytes
      tag=createTagTable()
      -- load plain bytes to tag-table
      tag=bytesToTag(bytes, tag)
    end
	end
  return tag
end

---
-- write bytes to file
-- write to file
function writeFile(bytes, filename)
  if (filename~='MylegicClone.hex') then
    if (file_check(filename)) then
	    local answer = confirm("\nthe output-file "..filename.." alredy exists!\nthis will delete the previous content!\ncontinue?")
      if (answer==false) then return print("user abort") end
    end
  end
  local line
	local bcnt=0
	local fho,err = io.open(filename, "w")
	if err then oops("OOps ... faild to open output-file ".. filename) end
  bytes=xorBytes(bytes, bytes[5])
	for i = 1, #bytes do
		if (bcnt == 0) then 
			line=bytes[i]
		elseif (bcnt <= 7) then 
			line=line.." "..bytes[i]
		end
		if (bcnt == 7) then
			-- write line to new file
			fho:write(line.."\n")
			-- reset counter & line
			bcnt=-1
			line=""
		end
		bcnt=bcnt+1
	end
	fho:close()
	print("\nwrote ".. #bytes .." bytes to " .. filename)
	return true
end

--- 
-- read from pm3 into virtual-tag
function readFromPM3()
  local tag, bytes, infile 
  --if (confirm("is the Tag placed onto the Proxmak3 and ready for reading?")) then
    --print("reading Tag ...")
    --infile=input("input a name for the temp-file:", "legic.temp")
		--if (file_check(infile)) then
		--	local answer = confirm("\nthe output-file "..infile.." alredy exists!\nthis will delete the previous content!\ncontinue?")
		--	if (answer==false) then return print("user abort") end
		--end
    infile="legic.temp"
    core.console("hf legic reader")
    core.console("hf legic save "..infile)
    --print("read temp-file into virtual Tag ...")
    tag=readFile(infile)
    return tag
  --else return print("user abort"); end
end

--- 
-- read file into table
function getInputBytes(infile)
	local line
	local bytes = {}
	local fhi,err = io.open(infile)
	if err then oops("faild to read from file ".. infile); return false; end
	while true do
		line = fhi:read()
		if line == nil then break end
		for byte in line:gmatch("%w+") do 
			table.insert(bytes, byte)
		end
	end
	fhi:close()
  print(#bytes .. " bytes from "..infile.." loaded")
	return bytes
end

---
-- read Tag-Table in bytes-table
function tagToBytes(tag)
  if (istable(tag)) then
    local bytes = {}
    local i, i2
    -- main token-data
    table.insert(bytes, tag.MCD)
    table.insert(bytes, tag.MSN0)
    table.insert(bytes, tag.MSN1)
    table.insert(bytes, tag.MSN2)
    table.insert(bytes, tag.MCC)
    table.insert(bytes, tag.DCFl)
    table.insert(bytes, tag.DCFh)
    table.insert(bytes, tag.raw)
    table.insert(bytes, tag.SSC)
    -- raw token data
    for i=0, #tag.data do
      table.insert(bytes, tag.data[i])
    end
    -- backup data
    for i=0, #tag.Bck do
      table.insert(bytes, tag.Bck[i])
    end
    -- token-create-time / master-token crc
    for i=0, #tag.MTC do
      table.insert(bytes, tag.MTC[i])
    end
    -- process segments
    if (type(tag.SEG[0])=='table') then
      for i=0, #tag.SEG do
        for i2=1, #tag.SEG[i].raw+1 do
          table.insert(bytes, #bytes+1, tag.SEG[i].raw[i2])
        end
        table.insert(bytes, #bytes+1, tag.SEG[i].crc)
        for i2=0, #tag.SEG[i].data-1 do
          table.insert(bytes, #bytes+1, tag.SEG[i].data[i2])
        end
      end
    end
    -- fill with zeros
    for i=#bytes+1, 1024 do
      table.insert(bytes, i, '00')
    end
    print(#bytes.." bytes of Tag dumped")
    return bytes
  end
  return oops("tag is no table in tagToBytes ("..type(tag)..")")
end

--- virtual TAG functions
-- create tag-table helper
function createTagTable()
  local t={  
        ['MCD'] = '00',
        ['MSN0']= '11',
        ['MSN1']= '22',
        ['MSN2']= '33',
        ['MCC'] = 'cc',
        ['DCFl']= 'ff',
        ['DCFh']= 'ff',
        ['Type']= 'GAM',
        ['OLE'] = 0,
        ['Stamp_len']= 18,
        ['WRP'] = '00',
        ['WRC'] = '00',
        ['RD']  = '00',
        ['raw'] = '9f',
        ['SSC'] = 'ff',
        ['data']= {},
        ['bck'] = {},
        ['MTC'] = {},
        ['SEG'] = {}
      }
  return t
end

--- 
-- put bytes into tag-table
function bytesToTag(bytes, tag)
  if(istable(tag)) then
    tag.MCD =bytes[1];
    tag.MSN0=bytes[2];
    tag.MSN1=bytes[3];
    tag.MSN2=bytes[4];
    tag.MCC =bytes[5];
    tag.DCFl=bytes[6];
    tag.DCFh=bytes[7];
    tag.raw =bytes[8];
    tag.SSC =bytes[9];
    tag.Type=getTokenType(tag.DCFl);
    tag.OLE=bbit("0x"..tag.DCFl,7,1)
    tag.WRP=("%d"):format(bbit("0x"..bytes[8],0,4))
    tag.WRC=("%d"):format(bbit("0x"..bytes[8],4,3))
    tag.RD=("%d"):format(bbit("0x"..bytes[8],7,1))
    tag.Stamp_len=(tonumber(0xfc,10)-tonumber(bbit("0x"..tag.DCFh,0,8),10))
    tag.data=bytesToTable(bytes, 10, 13)
    tag.Bck=bytesToTable(bytes, 14, 20)
    tag.MTC=bytesToTable(bytes, 21, 22)
    
    print("Tag-Type: ".. tag.Type)
    if (tag.Type=="SAM" and #bytes>23) then
      tag=segmentsToTag(bytes, tag)
      print((#tag.SEG+1).." Segment(s) found")
    end
    print(#bytes.." bytes for Tag processed")
    return tag
  end
  return oops("tag is no table in: bytesToTag ("..type(tag)..")")
end

---
-- dump tag-system area
function dumpCDF(tag)
  local res=""
  local i=0
  local raw=""
  if (istable(tag)) then
    res = res.."MCD: "..tag.MCD..", MSN: "..tag.MSN0.." "..tag.MSN1.." "..tag.MSN2..", MCC: "..tag.MCC.."\n"
    res = res.."DCF: "..tag.DCFl.." "..tag.DCFh..", Token_Type="..tag.Type.." (OLE="..tag.OLE.."), Stamp_len="..tag.Stamp_len.."\n"
    res = res.."WRP="..tag.WRP..", WRC="..tag.WRC..", RD="..tag.RD..", raw="..tag.raw..", SSC="..tag.SSC.."\n"
    
    -- credential
    if (tag.raw..tag.SSC=="9fff") then
      res = res.."Remaining Header Area\n"
      for i=0, (#tag.data) do
        res = res..tag.data[i].." "
      end
      res = res.."\nBackup Area\n"
      for i=0, (#tag.Bck) do
        res = res..tag.Bck[i].." "
      end
      res = res.."\nTime Area\n"
      for i=0, (#tag.MTC) do
        res = res..tag.MTC[i].." "
      end
    
    -- Master Token
    else
      res = res .."Master-Token Area\n"
      for i=0, (#tag.data) do
        res = res..tag.data[i].." "
      end
      for i=0, (#tag.Bck) do
        res = res..tag.Bck[i].." "
      end
      for i=0, (#tag.MTC-1) do
        res = res..tag.MTC[i].." "
      end
      res = res .. " MT-CRC: "..tag.MTC[1]
    end
    return res
  else print("no valid Tag in dumpCDF") end
end

---
-- dump single segment
function dumpSegment(tag, index)
  local i=index
  local i2
  local dp=0 --data-position in table
  local res="" --result
  local raw="" --raw-header
  -- segment
  if ( (istable(tag.SEG[i])) and tag.Type=="SAM") then 
    if (istable(tag.SEG[i].raw)) then
      for k,v in pairs(tag.SEG[i].raw) do
        raw=raw..v.." "
      end
    end
    
    -- segment header
    res = res.."Segment "..("%02d"):format(tag.SEG[i].index)..": "
    res = res .."raw header:"..string.sub(raw,0,-2)..", flag="..tag.SEG[i].flag..", (valid="..("%x"):format(tag.SEG[i].valid)..", last="..("%x"):format(tag.SEG[i].last).."), "
    res = res .."len="..("%04d"):format(tag.SEG[i].len)..", WRP="..("%02x"):format(tag.SEG[i].WRP)..", WRC="..("%02x"):format(tag.SEG[i].WRC)..", "
    res = res .."RD="..("%02x"):format(tag.SEG[i].RD)..", CRC="..tag.SEG[i].crc.." "
    res = res .."("..(checkSegmentCrc(tag, i) and "valid" or "error")..")"
    raw=""

    -- WRC protected
    if (tag.SEG[i].WRC>0) then
      res = res .."\nWRC protected area (Stamp):\n"
      for i2=dp, tag.SEG[i].WRC-1 do
        res = res..tag.SEG[i].data[dp].." "
        dp=dp+1
      end
    end
    
    -- WRP mprotected
    if (tag.SEG[i].WRP>tag.SEG[i].WRC) then
      res = res .."\nRemaining write protected area (Stamp):\n"
      for i2=dp, tag.SEG[i].WRP-tag.SEG[i].WRC-1 do
        res = res..tag.SEG[i].data[dp].." "
        dp=dp+1
      end
    end
    
    -- payload
    if (#tag.SEG[i].data-dp>0) then
     res = res .."\nRemaining segment payload:\n"
     for i2=dp, #tag.SEG[i].data-2 do
       res = res..tag.SEG[i].data[dp].." "
       dp=dp+1
     end
     if (tag.SEG[i].kgh) then 
       res = res..tag.SEG[i].data[dp].." (KGH: "..(checkKghCrc(tag, i) and "valid" or "error")..")"
     else  res = res..tag.SEG[i].data[dp] end
    end
    dp=0
    return res   
  else
    return print("Segment not found") 
  end
end

---
-- check all segmnet-crc
function checkAllSegCrc(tag)
  for i=0, #tag.SEG do
    crc=calcSegmentCrc(tag, i)
    tag.SEG[i].crc=crc
  end
end

---
-- check all segmnet-crc
function checkAllKghCrc(tag)
  for i=0, #tag.SEG do
    crc=calcKghCrc(tag, i)
    if (tag.SEG[i].kgh) then 
      tag.SEG[i].data[#tag.SEG[i].data-1]=crc
    end
  end
end

---
-- dump virtual Tag-Data
function dumpTag(tag)
  local i, i2
  local res
  local dp=0
  local raw=""
  -- sytstem area
  res ="\nCDF: System Area"
  res= res.."\n"..dumpCDF(tag)
  -- segments (user area)
  if(istable(tag.SEG[0])) then
    res = res.."\n\nADF: User Area"
    for i=0, #tag.SEG do
      res=res.."\n"..dumpSegment(tag, i).."\n"
    end
  end
  return res
end

--- 
-- determine TagType (bits 0..6 of DCFlow)
function getTokenType(DCFl)
  --[[
    0x00–0x2f IAM 
    0x30–0x6f SAM 
    0x70–0x7f GAM
  ]]--
  local tt = tonumber(bbit("0x"..DCFl,0,7),10)
  if (tt >= 0 and tt <= 47) then tt = "IAM"
  elseif (tt == 49) then tt = "SAM63"
  elseif (tt == 48) then tt = "SAM64"
  elseif (tt >= 50 and tt <= 111) then tt = "SAM"
  elseif (tt >= 112 and tt <= 127) then tt = "GAM"
  else tt = "???" end
  return tt
end

---
-- regenerate segment-header (after edit)
function regenSegmentHeader(segment)
  local seg=segment
  local raw = segment.raw
  local i
  -- len  bit0..7 | len=12bit=low nibble of byte1..byte0
  raw[1]=("%02x"):format(bbit("0x"..("%03x"):format(seg.len),0,8))
  -- high nibble of len  bit6=valid , bit7=last of byte 1 | ?what are bit 5+6 for? maybe kgh?
  raw[2]=("%02x"):format(bbit("0x"..("%03x"):format(seg.len),4.4)..bbit("0x"..("%02x"):format((seg.valid*64)+(seg.last*128)),0,8))
  -- WRP
  raw[3]=("%02x"):format(bbit("0x"..("%02x"):format(seg.WRP),0,8))
  -- WRC + RD
  raw[4]=("%02x"):format(bbit("0x"..("%03x"):format(seg.WRC),4,3)..bbit("0x"..("%02x"):format(seg.RD*128),0,8))
  -- flag
  seg.flag=string.sub(raw[2],0,1)
  --print(raw[1].." "..raw[2].." "..raw[3].." "..raw[4])
  if(#seg.data>(seg.len-5)) then
    print("current payload: ".. #seg.data .." - desired payload: ".. seg.len-5)
    print("Data-Length has being reduced: removing ".. #seg.data-(seg.len-5) .." bytes from Payload");
    for i=(seg.len-5), #seg.data-1 do
      table.remove(seg.data)
    end
  elseif (#seg.data<(seg.len-5)) then
    print("current payload: ".. #seg.data .." - desired payload: ".. seg.len-5)
    print("Data-Length has being extended: adding "..(seg.len-5)-#seg.data.." bytes to Payload");
    for i=#seg.data, (seg.len-5)-1 do
      table.insert(seg.data, '00')
    end
  end
  return seg
end

---
-- get segmemnt-data from byte-table
function getSegmentData(bytes, start, index)
  local segment={
    ['index'] = '00',
    ['flag']  = 'c',
    ['valid'] = 0,
    ['last']  = 0,
    ['len']   = 13,
    ['raw']   = {'00', '00', '00', '00'},
    ['WRP']   = 4,
    ['WRC']   = 0,
    ['RD']    = 0,
    ['crc']   = '00',
    ['data']  = {},
    ['kgh']   = false
  }
  if (bytes[start]) then 
    local i 
    -- #index
	  segment.index = index
	  -- flag = high nibble of byte 1
	  segment.flag = string.sub(bytes[start+1],0,1)
	  -- valid = bit 6 of byte 1
	  segment.valid = bbit("0x"..bytes[start+1],6,1)
	  -- last = bit 7 of byte 1
	  segment.last = bbit("0x"..bytes[start+1],7,1)
	  -- len = (byte 0)+(bit0-3 of byte 1)
    segment.len = tonumber(bbit("0x"..bytes[start+1],0,4)..bytes[start],16)
    -- raw segment header
    segment.raw = {bytes[start], bytes[start+1], bytes[start+2], bytes[start+3]}
	  -- wrp (write proteted) = byte 2
	  segment.WRP = tonumber(bytes[start+2],16)
	  -- wrc (write control) - bit 4-6 of byte 3
	  segment.WRC = tonumber(bbit("0x"..bytes[start+3],4,3),16)
	  -- rd (read disabled) - bit 7 of byte 3
	  segment.RD = tonumber(bbit("0x"..bytes[start+3],7,1),16)
	  -- crc byte 4
	  segment.crc = bytes[start+4]
    -- segment-data starts at segment.len - segment.header - segment.crc
    for i=0, (segment.len-5) do
      segment.data[i]=bytes[start+5+i]
    end
    return segment
  else return false; 
  end
end

--- 
-- put segments from byte-table to tag-table 
function segmentsToTag(bytes, tag)
  if(#bytes>23) then
    local start=23
    local i=-1
    if (istable(tag)) then
      repeat
        i=i+1
        tag.SEG[i]=getSegmentData(bytes, start, ("%02d"):format(i))
        if (tag.Type=="SAM") then
          if (checkKghCrc(tag, i)) then tag.SEG[i].kgh=true end
        end
        start=start+tag.SEG[i].len
      until ((tag.SEG[i].valid==0) or tag.SEG[i].last==1 or i==126)
      return tag
    else return oops("tag is no table in: segmentsToTag ("..type(tag)..")") end
  else print("no Segments: must be a MIM22") end
end 

--- CRC calculation and validation
-- build kghCrc credentials
function kghCrcCredentials(tag, segid) 
  local x='00'
  if (type(segid)=="string") then segid=tonumber(segid,10) end
  if (segid>0) then x='93' end
  local cred = tag.MCD..tag.MSN0..tag.MSN1..tag.MSN2..("%02x"):format(tag.SEG[segid].WRP)
  cred = cred..("%02x"):format(tag.SEG[segid].WRC)..("%02x"):format(tag.SEG[segid].RD)..x
  for i=0, #tag.SEG[segid].data-2 do
    cred = cred..tag.SEG[segid].data[i]
  end
  return cred
end

---
-- validate kghCRC to segment in tag-table
function checkKghCrc(tag, segid)
  if (type(tag.SEG[segid])=='table') then
    if (tag.data[3]=="11" and tag.raw=="9f" and tag.SSC=="ff") then
      local data=kghCrcCredentials(tag, segid)
      if (("%02x"):format(utils.Crc8Legic(data))==tag.SEG[segid].data[tag.SEG[segid].len-5-1]) then return true; end 
      else return false; end
  else oops("'Kaba Group header' detected but no Segment-Data found") end
end

---
-- calcuate kghCRC for a given segment 
function calcKghCrc(tag, segid)
  -- check if a 'Kaber Group Header' exists
    local i
    local data=kghCrcCredentials(tag, segid)
    return ("%02x"):format(utils.Crc8Legic(data))
end

---
-- build segmentCrc credentials
function segmentCrcCredentials(tag, segid) 
  local cred = tag.MCD..tag.MSN0..tag.MSN1..tag.MSN2
  cred = cred ..tag.SEG[segid].raw[1]..tag.SEG[segid].raw[2]..tag.SEG[segid].raw[3]..tag.SEG[segid].raw[4]
  return cred
end

---
-- validate segmentCRC for a given segment
function checkSegmentCrc(tag, segid)
    local data=segmentCrcCredentials(tag, segid)
    if (("%02x"):format(utils.Crc8Legic(data))==tag.SEG[segid].crc) then 
      return true
    end
    return false
end

---
-- calculate segmentCRC for a given segment
function calcSegmentCrc(tag, segid)
  -- check if a 'Kaber Group Header' exists
    local data=segmentCrcCredentials(tag, segid)
    return ("%02x"):format(utils.Crc8Legic(data))
end

--- create master-token

---
-- write virtual Tag to real Tag
-- write clone-data to tag
function writeToTag(plainBytes, taglen, filename)
  local bytes
	if(utils.confirm("\nplace your empty tag onto the PM3 to read & write\n") == false) then
    return
  end
	
	-- write data to file
	if (taglen > 0) then
		WriteBytes = utils.input("enter number of bytes to write?", taglen)

		-- load file into pm3-buffer
    if (type(filename)~="string") then filename=input("filename to load to pm3-buffer?","legic.temp") end
		cmd = 'hf legic load '..filename
		core.console(cmd)
		
		-- write pm3-buffer to Tag
		for i=0, WriteBytes do
			if ( i<5 or i>6) then
				cmd = ('hf legic write 0x%02x 0x01'):format(i)
				core.console(cmd)
        --print(cmd)
			elseif (i == 6) then
				-- write DCF in reverse order (requires 'mosci-patch')
				cmd = 'hf legic write 0x05 0x02'
				core.console(cmd)
        --print(cmd)
			else
				print("skipping byte 0x05 - will be written next step")
			end				
			utils.Sleep(0.2)
		end
	end
end

---
-- edit segment helper
function editSegment(tag, index)
  local k,v
  local edit_possible="valid len RD WRP WRC Stamp Payload"
  if (istable(tag.SEG[index])) then
    for k,v in pairs(tag.SEG[index]) do
      if(string.find(edit_possible,k)) then
        tag.SEG[index][k]=tonumber(input(k..": ", v),10)
      end
    end
  else print("Segment with Index: "..("%02d"):format(index).." not found in Tag")
    return false
  end
  regenSegmentHeader(tag.SEG[index]) 
  print("\n"..dumpSegment(tag, index).."\n")
  return tag
end

---
-- edit Segment Data
function editSegmentData(data)
  if (istable(data)) then
    for i=0, #data-1 do
      data[i]=input("Data"..i..": ", data[i])
    end 
    return data
  else
    print("no Segment-Data found")
  end
end

---
-- list available segmets in virtual tag
function segmentList(tag)
  local i
  local res = "" 
  if (istable(tag.SEG[0])) then
    for i=0, #tag.SEG do
      res = res .. tag.SEG[i].index .. "  "
    end
    return res
    else print("no Segments found in Tag")
      return false
  end
end

---
-- helper to selecting a segment
function selectSegment(tag)
  local sel
  if (istable(tag)) then 
    print("availabe Segments:\n"..segmentList(tag))
    sel=input("select Segment: ", '00')
    sel=tonumber(sel,10)
    if (sel) then return sel
    else return '0' end
  else
    print("\nno Segments found")
    return false
  end
end

---
-- add segment
function addSegment(tag)
  local i
  local segment={
    ['index'] = '00',
    ['flag']  = 'c',
    ['valid'] = 1,
    ['last']  = 1,
    ['len']   = 13,
    ['raw']   = {'0d', '40', '04', '00'},
    ['WRP']   = 4,
    ['WRC']   = 0,
    ['RD']    = 0,
    ['crc']   = '00',
    ['data']  = {},
    ['kgh']   = false
  }
  if (istable(tag.SEG[0])) then
    tag.SEG[#tag.SEG].last=0
    table.insert(tag.SEG, segment)
    for i=0, 8 do
      tag.SEG[#tag.SEG].data[i]=("%02x"):format(i)
    end
    tag.SEG[#tag.SEG].index=("%02d"):format(#tag.SEG)
    return tag
  else
    print("no Segment-Table found")
  end
end

---
--
function delSegment(tag, index)
  local i
  if (type(index)=="string") then index=tonumber(index,10) end
  if (index > 0) then
    table.remove(tag.SEG, index)
    for i=0, #tag.SEG do
      tag.SEG[i].index=("%02d"):format(i)
    end
  end
  if(istable(tag.SEG[#tag.SEG])) then tag.SEG[#tag.SEG].last=1 end
  return tag
end

---
-- helptext for modify-mode
function modifyHelp()
  local t=[[
  
    Data I/O           Segment Manipulation        File I/O   
------------------     --------------------      ---------------
  rt => read    Tag     ds => dump   Segments     lf => load File
  wt => write   Tag     as => add    Segment      sf => save File 
  ct => copy io Tag     es => edit   Segment      xf => xor  File
  tc => copy oi Tag     ed => edit   Data     
  di => dump  inTag     rs => remove Segment
  do => dump outTag     cc => check  Segment-CRC                  
                        ck => check  KGH                
                        tk => toggle KGH-Flag
  q => quit             xc => get    KGH-Str      h => this Help
  ]]                    
  return t
end

--- 
-- modify Tag (interactive)
function modifyMode()
  local i, outTAG, inTAG, outfile, infile, sel, segment, bytes, outbytes
  actions = {
     ["h"] = function(x) 
              print(modifyHelp().."\n".."tags im Memory:"..(istable(inTAG) and " inTAG" or "")..(istable(outTAG) and " outTAG" or ""))
            end,
    ["rt"] = function(x) inTAG=readFromPM3(); actions['di']('') end,
    ["wt"] = function(x)  
              if(istable(inTAG)) then
                local taglen=22
                for i=0, #inTAG.SEG do
                  taglen=taglen+inTAG.SEG[i].len+5
                end
                -- read new tag (output tag)
                outTAG=readFromPM3()
                outbytes=tagToBytes(outTAG)
                -- copy 'inputbuffer' to 'outputbuffer'
                inTAG.MCD  = outbytes[1]
                inTAG.MSN0 = outbytes[2]
                inTAG.MSN1 = outbytes[3]
                inTAG.MSN2 = outbytes[4]
                inTAG.MCC  = outbytes[5]
                -- recheck all segments-crc/kghcrc
                checkAllSegCrc(inTAG)
                checkAllKghCrc(inTAG)
                --get bytes from ready outTAG
                bytes=tagToBytes(inTAG)
                if (bytes) then   
                  writeFile(bytes, 'MylegicClone.hex')         
                  writeToTag(bytes, taglen, 'MylegicClone.hex')
                  actions['rt']('') 
                end
               end
              end,
    ["ct"] = function(x)  
                print("copy virtual input-TAG to output-TAG")
                outTAG=inTAG
            end,
    ["tc"] = function(x)  
                print("copy virtual output-TAG to input-TAG")
                inTAG=outTAG
            end,
    ["lf"] = function(x)  
              filename=input("enter filename: ", "legic.temp")
              inTAG=readFile(filename)
            end,
    ["sf"] = function(x)  
              if(istable(inTAG)) then
                outfile=input("enter filename:", "legic.temp")
                bytes=tagToBytes(inTAG)
                --bytes=xorBytes(bytes, inTAG.MCC)
                if (bytes) then             
                  writeFile(bytes, outfile)
                end
               end
              end,
    ["xf"] = function(x)  
              if(istable(inTAG)) then
                outfile=input("enter filename:", "legic.temp")
                crc=input("enter new crc: ('00' for a plain dump)", inTAG.MCC)
                print("obfuscate witth: "..crc)
                bytes=tagToBytes(inTAG)
                bytes[5]=crc
                if (bytes) then             
                  writeFile(bytes, outfile)
                end
              end
             end,
    ["di"] = function(x) if (istable(inTAG)) then print("\n"..dumpTag(inTAG).."\n") end end,
    ["do"] = function(x) if (istable(outTAG)) then print("\n"..dumpTag(outTAG).."\n") end end,
    ["ds"] = function(x) 
                sel=selectSegment(inTAG)
                if (sel) then print("\n"..(dumpSegment(inTAG, sel) or "no Segments available").."\n") end 
              end,
    ["es"] = function(x) 
              sel=selectSegment(inTAG)
              if (sel) then 
                if(istable(inTAG.SEG)) then
                  inTAG=editSegment(inTAG, sel)
                  inTAG.SEG[sel]=regenSegmentHeader(inTAG.SEG[sel])
              else print("no Segments in Tag") end 
              end
            end,
    ["as"] = function(x) 
              if (istable(inTAG.SEG[0])) then
                inTAG=addSegment(inTAG)
                inTAG.SEG[#inTAG.SEG-1]=regenSegmentHeader(inTAG.SEG[#inTAG.SEG-1])
                inTAG.SEG[#inTAG.SEG]=regenSegmentHeader(inTAG.SEG[#inTAG.SEG]) 
                else print("unsegmented Tag!")
              end
            end,
    ["rs"] = function(x) 
              if (istable(inTAG)) then
                sel=selectSegment(inTAG)
                inTAG=delSegment(inTAG, sel)
                for i=0, #inTAG.SEG do
                  inTAG.SEG[i]=regenSegmentHeader(inTAG.SEG[i])
                end
              end
            end,
    ["ed"] = function(x) 
              sel=selectSegment(inTAG)
              if (sel) then 
                inTAG.SEG[sel].data=editSegmentData(inTAG.SEG[sel].data) 
              end
            end,
     ["ts"] = function(x) 
                sel=selectSegment(inTAG)
                regenSegmentHeader(inTAG.SEG[sel]) 
              end,
     ["tk"] = function(x) 
                sel=selectSegment(inTAG)
                if(inTAG.SEG[sel].kgh) then inTAG.SEG[sel].kgh=false
                else inTAG.SEG[sel].kgh=true end
              end,
     ["k"] = function(x) 
               print(("%02x"):format(utils.Crc8Legic(x)))
              end,
     ["xc"] = function(x) 
               --get credential-string for kgh-crc on certain segment
               --usage: xc <segment-index>
               print("k "..kghCrcCredentials(inTAG, x))
              end,
     ["cc"] = function(x)  if (istable(inTAG)) then checkAllSegCrc(inTAG) end end,
     ["ck"] = function(x)  if (istable(inTAG)) then checkAllKghCrc(inTAG) end end,
     ["q"] = function(x)  end,
  }
  print("modify-modus! enter 'h' for help or 'q' to quit")
  repeat 
    ic=input("Legic command? ('h' for help - 'q' for quit)", "h")
    -- command actions
    if (type(actions[string.lower(string.sub(ic,0,1))])=='function') then
      actions[string.lower(string.sub(ic,0,1))](string.sub(ic,3))
    elseif (type(actions[string.lower(string.sub(ic,0,2))])=='function') then
      actions[string.lower(string.sub(ic,0,2))](string.sub(ic,4))
    else actions['h']('') end
  until (string.sub(ic,0,1)=="q")
end

--- main
function main(args)
	if (#args == 0 ) then modifyMode() end
  --- variables
  local inTAG, outTAG, outfile, interactive, crc, ofs, cfs, dfs
	-- just a spacer for better readability
  print()
  --- parse arguments
	for o, a in getopt.getopt(args, 'hrmi:do:c:') do  
    -- display help
    if o == "h" then return help(); end
    -- read tag from PM3
    if o == "r" then inTAG=readFromPM3() end
    -- input file
		if o == "i" then inTAG=readFile(a) end
    -- dump virtual-Tag 
    if o == "d" then dfs=true end
    -- interacive modifying
    if o == "m" then interactive=true; modifyMode() end
    -- xor (e.g. for clone or plain file)
    if o == "c" then cfs=true; crc=a end
    -- output file
		if o == "o" then outfile=a; ofs=true end		
  end
  
  -- file conversion (output to file)
  if (ofs) then
    -- dump infile / tag-read
    if (dfs) then 
      print("-----------------------------------------") 
      print(dumpTag(inTAG))
    end
    bytes=tagToBytes(inTAG)
    -- xor with given crc
    if (cfs) then 
      bytes[5]=crc 
    end
    -- write to outfile
    if (bytes) then 
      writeFile(bytes, outfile)
      -- reed new content into virtual tag 
      
      inTAG=bytesToTag(bytes, inTAG)
      -- show new content
      if (dfs) then  
        print("-----------------------------------------")
        print(dumpTag(outTAG)) 
      end
    end
  end
  
end

--- start
main(args)