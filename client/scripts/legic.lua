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
MCD   = Manufacturer ID
MSN   = Manufacturer SerialNumber
60 ea = DCF Low + DCF high
9f    = raw byte which holds the bits for OLE,WRP,WRC,RD
ff    = unknown but important
00    = unimportant
11    = unknown but important
Bck   = header-backup-area
00 00 = Year (00 = 2000) & Week (not important)
Seg   = Segment Header
SegC  =  Crc8 over the Segment Header
Stp   = Stamp (could be more as 4 - up to 7)
UID   = dec User-ID for online-Mapping
kghC  = crc8 over MCD + MSN0..MSN2 + UID


(example)	Legic-Cash on MIM256/1024 tag' (37 bytes)
      +----+----+----+----+----+----+----+----+
  0x00|Seg0|Seg1|Seg2|Seg3|SegC|STP0|STP1|STP2|		
      +----+----+----+----+----+----+----+----+
  0x08|STP3|STP4|STP5|STP6| 01 |CURh|CURl|LIMh|
      +----+----+----+----+----+----+----+----+
  0x10|LIMm|LIMl|CHKh|CHKl|BALh|BALm|BALl|LRBh|
      +----+----+----+----+----+----+----+----+
  0x18|LRBm|LRBl|CHKh|CHKl|SHDh|SHDm|SHDl|LRSh|
      +----+----+----+----+----+----+----+----+
  0x20|LRSm|LRSl| CV |CHKh|CHKl|
      +----+----+----+----+----+
STP = Stamp (seems to be always 7 bytes)
01  = unknown but important
CUR = currency in HEX (ISO 4217)
LIM = Cash-Limit
CHK = crc16 over byte-addr 0x05..0x12
BAL = Balance
LRB = ID of the reader that changed the balance
CHK = crc16 over BAL + LRB
SHD = shadow Balance
LRS = ID of the reader that changed the shadow balance (?? should be always the same as LRB)
CV  = Counter value for transactions
CHK = crc16 over SHD + LRS + CV
--]]

example = "script run legic"
author  = "Mosci"
version = "1.0.1"
desc =
[[

This script helps you to read, create and modify Legic Prime Tags (MIM22, MIM256, MIM1024)
it's kinda interactive with following commands in three categories:

    Data I/O                    Segment Manipulation               Token-Data
  -----------------             --------------------            -----------------
  rt => read    Tag             as => add    Segment            mt => make Token
  wt => write   Tag             es => edit   Segment Header     et => edit Token data
  ct => copy io Tag             ed => edit   Segment Data       tk => toggle KGH-Flag
  tc => copy oi Tag     rs => remove Segment
                                cc => check  Segment-CRC            File I/O      
  di => dump  inTag             ck => check  KGH                -----------------  
  do => dump  outTag                                            lf => load   File 
  ds => dump  Segments                                          sf => save   File 
  lc => dump  Legic-Cash                                        xf => xor to File
 d3p => dump  3rd Party Cash                                        
 r3p => raw   3rd Party Cash   

 
 rt: 'read tag'         - reads a tag placed near to the PM3
 wt: 'write tag'        - writes the content of the 'virtual inTag' to a tag placed near to th PM3
                          without the need of changing anything - MCD,MSN,MCC will be read from the tag
                          before and applied to the output.
 ct: 'copy tag'         - copy the 'virtual Tag' to a second 'virtual TAG' - not usefull yet, but inernally needed
 tc: 'copy tag'         - copy the 'second virtual Tag' to 'virtual TAG' - not usefull yet, but inernally needed
 di: 'dump inTag'       - shows the current content of the 'virtual Tag'
 do: 'dump outTag'      - shows the current content of the 'virtual outTag'
 ds: 'dump Segments'    - will show the content of a selected Segment
 as: 'add Segment'      - will add a 'empty' Segment to the inTag
 es: 'edit Segment'     - edit the Segment-Header of a selected Segment (len, WRP, WRC, RD, valid)
                          all other Segment-Header-Values are either calculated or not needed to edit (yet)
 ed: 'edit data'        - edit the Data of a Segment (ADF-Aera / Stamp & Payload specific Data)
 et: 'edit Token'       - edit Data of a Token (CDF-Area / SAM, SAM64, SAM63, IAM, GAM specific Data)
 mt: 'make Token'       - create a Token 'from scratch' (guided)
 rs: 'remove segment'   - removes a Segment (except Segment 00, but this can be set to valid=0 for Master-Token)
 cc: 'check Segment-CRC'- checks & calculates (if check failed) the Segment-CRC of all Segments
 ck: 'check KGH-CRC'    - checks the and calculates a 'Kaba Group Header' if one was detected
                          'Kaba Group Header CRC calculation'
 tk: 'toggle KGH'       - toglle the (script-internal) flag for kgh-calculation for a segment
 xc: 'etra c'           - show string that was used to calculate the kgh-crc of a segment
dlc: 'dump Legic-Cash'  - show balance and checksums of a legic-Cash Segment
d3p: 'dump 3rd Party'   - show balance, history and checksums of a (yet) unknown 3rd Party Cash-Segment
r3p: 'raw 3rd Party'    - show balance, history and checksums of a (yet) unknown 3rd Party Cash-Segment
e3p: 'edit 3rd Party'   - edit Data in 3rd Party Cash Segment
 lf: 'load file'        - load a (xored) file from the local Filesystem into the 'virtual inTag'
 sf: 'save file'        - saves the 'virtual inTag' to the local Filesystem (xored with Tag-MCC)
 xf: 'xor file'         - saves the 'virtual inTag' to the local Filesystem (xored with choosen MCC - use '00' for plain values)
 
]]
currentTag="inTAG"
--- 
-- requirements
local utils   = require('utils')
local getopt  = require('getopt')

--- 
-- global variables / defines
local bxor    = bit32.bxor
local bbit    = bit32.extract
local input   = utils.input
local confirm = utils.confirm

--- 
-- curency-codes for Legic-Cash-Segments (ISO 4217)
local currency = {
  ["03d2"]="EUR", 
  ["0348"]="USD", 
  ["033A"]="GBP",
  ["02F4"]="CHF"
}

--- 
-- This is only meant to be used when errors occur
function oops(err)
	print("ERROR: ",err)
	return nil, err
end

---  
-- Usage help
function help()
	print(desc)
	print(version)
	print("Example usage")
	print(example)
end

--- 
-- table check helper
function istable(t) 
  return type(t) == 'table' 
end

---
-- xor single byte
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
-- put certain bytes into a new table
function bytesToTable(bytes, bstart, bend)
  local t={}
  for i=0, (bend-bstart) do
    t[i]=bytes[bstart+i]
  end
  return t
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
-- write virtual Tag to real Tag
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
    -- unsegmented Master-Token
    -- only tag-data 
    else 
      for i=0, #tag.Bck do
        table.insert(tag.data, tag.Bck[i])
    end
      tag.data[#tag.data]=tag.MTC[0]
      tag.Bck=nil
      --tag.MTC[0]=tag.MTC[1]
      --tag.MTC[1]=nil
    end
    print(#bytes.." bytes for Tag processed")
    return tag
  end
  return oops("tag is no table in: bytesToTag ("..type(tag)..")")
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
    if(istable(tag.Bck)) then
      for i=0, #tag.Bck do
        table.insert(bytes, tag.Bck[i])
      end
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

---
-- make token
function makeToken()
  local mt={
    ['Type']    = {"SAM", "SAM63", "SAM64", "IAM", "GAM"},
    ['DCF']     = {"60ea", "31fa", "30fa", "80fa", "f0fa"},
    ['WRP']     = {"15", "2", "2", "2", "2"},
    ['WRC']     = {"01", "02", "02", "00", "00"},
    ['RD']      = {"01", "00", "00", "00", "00"},
    ['Stamp']   = {"00", "00", "00", "00", "00"},
    ['Segment'] = {"0d", "c0", "04", "00", "be", "01", "02", "03", "04", "01", "02", "03", "04"}
  }
  ttype=""
  for k, v in pairs(mt.Type) do
    ttype=ttype..k..") "..v.."  "
      end
  mtq=tonumber(input("select number for Token-Type\n"..ttype, '1'), 10)
  if (type(mtq)~="number") then return print("selection invalid!") 
  elseif (mtq>#mt.Type) then return print("selection invalid!")
  else print("Token-Type '"..mt.Type[mtq].."' selected") end
  local raw=calcHeaderRaw(mt.WRP[mtq], mt.WRC[mtq], mt.RD[mtq])
  local mtCRC="00"
  
  bytes={"01", "02", "03", "04", "cb", string.sub(mt.DCF[mtq], 0, 2), string.sub(mt.DCF[mtq], 3), raw,
         "00", "00", "00", "00", "00", "00", "00", "00",
         "00", "00", "00", "00", "00", "00"}
  if (mtq==1) then
    for i=0, #mt.Segment do
      table.insert(bytes, mt.Segment[i])
    end
    bytes[9]="ff"
      end
  -- fill bytes
  for i=#bytes, 1023 do table.insert(bytes, "00") end
  -- if Master-Token -> calc Master-Token-CRC
  if (mtq>1) then bytes[22]=calcMtCrc(bytes) end
  local tempTag=createTagTable()
  -- remove segment if MasterToken
  if (mtq>1) then tempTag.SEG[0]=nil end
  return bytesToTag(bytes, tempTag)
    end
    
--- 
-- edit token-data
function editTag(tag)
  -- for simulation it makes sense to edit everything
  local edit_sim="MCD MSN0 MSN1 MSN2 MCC DCFl DCFh WRP WRC RD"
  -- on real tags it makes only sense to edit DCF, WRP, WRC, RD
  local edit_real="DCFl DCFh WRP WRC RD"
  if (confirm("do you want to edit non-writeable values (e.g. for simulation)?")) then
    edit_tag=edit_sim
  else edit_tag=edit_real end
    
  if(istable(tag)) then
    for k,v in pairs(tag) do
      if(type(v)~="table" and type(v)~="boolean" and string.find(edit_tag, k)) then
        tag[k]=input("value for: "..k, v)
      end
    end
    
    if (tag.Type=="SAM") then ttype="Header"; else ttype="Stamp"; end
      if (confirm("do you want to edit "..ttype.." Data?")) then
      -- master-token specific
      if(istable(tag.Bck)==false) then
        -- stamp-data length=(0xfc-DCFh)
        -- on MT: SSC holds the Starting Stamp Character (Stamp0)
        tag.SSC=input(ttype.."0: ", tag.SSC)
        -- rest of stamp-bytes are in tag.data 0..n
        for i=0, (tonumber(0xfc ,10)-("%d"):format('0x'..tag.DCFh))-2 do
        tag.data[i]=input(ttype.. i+1 ..": ", tag.data[i])
     end
  else
        --- on credentials byte7 should always be 9f and byte8 ff 
        -- on Master-Token not (even on SAM63/64 not)
        -- tag.SSC=input(ttype.."0: ", tag.SSC)
        for i=0, #tag.data do
           tag.data[i]=input(ttype.. i ..": ", tag.data[i])
  end
end
  end
    
    bytes=tagToBytes(tag)
   
    --- check data-consistency (calculate tag.raw)
    bytes[8]=calcHeaderRaw(tag.WRP, tag.WRC, tag.RD)
   
    --- Master-Token specific
    -- should be triggered if a SAM was converted to a non-SAM (user-Token to Master-Token)
    -- or a Master-Token has being edited (also SAM64 & SAM63 - which are in fact Master-Token)
    if(tag.Type~="SAM" or bytes[6]..bytes[7]~="60ea") then 
      -- calc new Master-Token crc
      bytes[22]=calcMtCrc(bytes)   
    else
      -- ensure tag.SSC set to 'ff' on credential-token (SAM)
      bytes[9]='ff'
      -- if a Master-Token was converted to a Credential-Token
      -- lets unset the Time-Area to 00 00 (will contain Stamp-Data on MT)
      bytes[21]='00'
      bytes[22]='00'
end

    tag=bytesToTag(bytes, tag)
  end
end

---
-- calculates header-byte (addr 0x07)
function calcHeaderRaw(wrp, wrc, rd)
  local res
  wrp=("%02x"):format(tonumber(wrp, 10))
  rd=tonumber(rd, 16)
  res=("%02x"):format(tonumber(wrp, 16)+tonumber(wrc.."0", 16)+((rd>0) and tonumber("8"..(rd-1), 16) or 0))         
  return res
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
  -- segments (user-token area)
  if(tag.Type=="SAM") then
    res = res.."\n\nADF: User Area"
    for i=0, #tag.SEG do
      res=res.."\n"..dumpSegment(tag, i).."\n"
    end
  end
  return res
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
-- dump tag-system area
function dumpCDF(tag)
  local res=""
  local i=0
  local raw=""
  local bytes
  if (istable(tag)) then
    res = res.."MCD: "..tag.MCD..", MSN: "..tag.MSN0.." "..tag.MSN1.." "..tag.MSN2..", MCC: "..tag.MCC.."\n"
    res = res.."DCF: "..tag.DCFl.." "..tag.DCFh..", Token_Type="..tag.Type.." (OLE="..tag.OLE.."), Stamp_len="..tag.Stamp_len.."\n"
    res = res.."WRP="..tag.WRP..", WRC="..tag.WRC..", RD="..tag.RD..", raw="..tag.raw..((tag.raw=='9f') and (", SSC="..tag.SSC.."\n") or "\n")
    
    -- credential (end-user tag)
    if (tag.Type=="SAM") then
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
    
    -- Master Token specific
			else
      res = res .."Master-Token Area\nStamp: "
      res= res..tag.SSC.." "
      for i=0, tag.Stamp_len-2 do
        res = res..tag.data[i].." "
			end				
      res=res.."\nunused payload\n"
      for i=0, (#tag.data-tag.Stamp_len-1) do
        res = res..tag.data[i].." "
		end
      bytes=tagToBytes(tag)
      local mtcrc=calcMtCrc(bytes)
      res=res.."\nMaster-Token CRC: "
      res = res ..tag.MTC[1].." ("..((tag.MTC[1]==mtcrc) and "valid" or "error")..")"
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
      res = res .."\nWRC protected area:\n"
      for i2=dp, tag.SEG[i].WRC-1 do
        res = res..tag.SEG[i].data[dp].." "
        dp=dp+1
      end
    end
    
    -- WRP mprotected
    if ((tag.SEG[i].WRP-tag.SEG[i].WRC)>0) then
      res = res .."\nRemaining write protected area:\n"
      for i2=dp, (tag.SEG[i].WRP-tag.SEG[i].WRC)-1 do
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
  local lc=check4LegicCash(data)
  io.write("\n")
  if (istable(data)) then
    for i=0, #data-1 do
      data[i]=input("Data"..i..": ", data[i])
    end 
    if (lc) then data=fixLegicCash(data) end
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
  if (istable(tag.SEG[0])) then 
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
-- delete segment (except segment 00)
function delSegment(tag, index)
  if (istable(tag.SEG[0])) then
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
end

---
-- return bytes 'sstrat' to 'send' from a table
function dumpTable(tab, header, tstart, tend)
  res=""
  for i=tstart, tend do
    res=res..tab[i].." "
  end
  if (string.len(header)==0) then return res
  else return (header.." #"..(tend-tstart+1).."\n"..res) end
end

function dump3rdPartyCash1(tag , seg)
  local uid=tag.MCD..tag.MSN0..tag.MSN1..tag.MSN2
  local stamp=tag.SEG[seg].data[0].." "..tag.SEG[seg].data[1].." "..tag.SEG[seg].data[2]
  local datastamp=tag.SEG[seg].data[20].." "..tag.SEG[seg].data[21].." "..tag.SEG[seg].data[22]
  local balance=tonumber(tag.SEG[seg].data[32]..tag.SEG[seg].data[33] ,16)
  local balancecrc=utils.Crc8Legic(uid..tag.SEG[seg].data[32]..tag.SEG[seg].data[33])
  local mirror=tonumber(tag.SEG[seg].data[35]..tag.SEG[seg].data[36] ,16)
  local mirrorcrc=utils.Crc8Legic(uid..tag.SEG[seg].data[35]..tag.SEG[seg].data[36])
  local lastbal0=tonumber(tag.SEG[seg].data[39]..tag.SEG[seg].data[40] ,16)
  local lastbal1=tonumber(tag.SEG[seg].data[41]..tag.SEG[seg].data[42] ,16)
  local lastbal2=tonumber(tag.SEG[seg].data[43]..tag.SEG[seg].data[44] ,16)
  
  test=""
  -- display decoded/known stuff
  print("\n------------------------------")
  print("Tag-ID:\t\t      "..uid)
  print("Stamp:\t\t      "..stamp)   
  print("UID-Mapping: \t\t"..("%06d"):format(tonumber(tag.SEG[seg].data[46]..tag.SEG[seg].data[47]..tag.SEG[seg].data[48], 16)))
  print("------------------------------")           
  print("checksum 1:\t\t    "..tag.SEG[seg].data[31].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[seg].data, "", 19, 30)), tag.SEG[seg].data[31])..")")   
  print("checksum 2:\t\t    "..tag.SEG[seg].data[34].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[seg].data, "", 32, 33)), tag.SEG[seg].data[34])..")")
  print("checksum 3:\t\t    "..tag.SEG[seg].data[37].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[seg].data, "", 35, 36)), tag.SEG[seg].data[37])..")") 
  
  print("checksum 4:\t\t    "..tag.SEG[seg].data[55].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[seg].data, "", 46, 54)), tag.SEG[seg].data[55])..")")
  print("checksum 5:\t\t    "..tag.SEG[seg].data[62].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[seg].data, "", 56, 61)), tag.SEG[seg].data[62])..")") 
  print("checksum 6:\t\t    "..tag.SEG[seg].data[73].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[seg].data, "", 63, 72)), tag.SEG[seg].data[73])..")")
  print("checksum 7:\t\t    "..tag.SEG[seg].data[89].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[seg].data, "", 74, 88)), tag.SEG[seg].data[89])..")")  
  print("------------------------------")                    
  print(string.format("Balance:\t\t  %3.2f", balance/100).." ".."("..compareCrc(balancecrc, tag.SEG[seg].data[34])..")")
  print(string.format("Shadow:\t\t\t  %3.2f", mirror/100).." ".."("..compareCrc(balancecrc, tag.SEG[seg].data[37])..")")     
  print("------------------------------")                  
  print(string.format("History 1:\t\t  %3.2f", lastbal0/100))            
  print(string.format("History 2:\t\t  %3.2f", lastbal1/100))          
  print(string.format("History 3:\t\t  %3.2f", lastbal2/100))        
  print("------------------------------\n") 
end
---
-- compare two bytes
function compareCrc(calc, guess)
  calc=("%02x"):format(calc)
  if (calc==guess) then return "valid"
  else return "error "..calc.."!="..guess end
end

---
-- compare 4 bytes
function compareCrc16(calc, guess)
  calc=("%04x"):format(calc)
  if (calc==guess) then return "valid"
  else return "error "..calc.."!="..guess end
end

---
-- repair / fix (yet known) crc's of a '3rd Party Cash-Segment'
-- not all bytes know until yet !!
function fix3rdPartyCash1(uid, data)
  if(#data==95) then
    -- checksum 1
    data[31]=("%02x"):format(utils.Crc8Legic(uid..dumpTable(data, "", 19, 30)))
    -- checksum 2
    data[34]=("%02x"):format(utils.Crc8Legic(uid..data[32]..data[33]))
    -- checksum 3
    data[37]=("%02x"):format(utils.Crc8Legic(uid..data[35]..data[36]))
    -- checksum 4
    data[55]=("%02x"):format(utils.Crc8Legic(uid..dumpTable(data, "", 46, 54)))
    -- checksum 5
    data[62]=("%02x"):format(utils.Crc8Legic(uid..dumpTable(data, "", 56, 61)))
    -- checksum 6
    data[73]=("%02x"):format(utils.Crc8Legic(uid..dumpTable(data, "", 63, 72)))
    -- checksum 7
    data[89]=("%02x"):format(utils.Crc8Legic(uid..dumpTable(data, "", 74, 88)))
    return data
  end
end

---
-- edit uid 3rd party cash
function edit3rdUid(mapid, uid, data)
  mapid=("%06x"):format(tonumber(mapid, 10))
  data[46]=string.sub(mapid, 0 ,2)
  data[47]=string.sub(mapid, 3 ,4)
  data[48]=string.sub(mapid, 5 ,6)
  return fix3rdPartyCash1(uid, data)
end

---
-- edit balance 3rd party cash
function edit3rdCash(new_cash, uid, data)
  new_cash=("%04x"):format(new_cash)
  data[32]=string.sub(new_cash, 0,2)
  data[33]=string.sub(new_cash, 3,4)
  data[34]=("%02x"):format(utils.Crc8Legic(uid..new_cash))
  data[35]=string.sub(new_cash, 0,2)
  data[36]=string.sub(new_cash, 3,4)
  data[37]=("%02x"):format(utils.Crc8Legic(uid..new_cash))
  data[39]=string.sub(new_cash, 0,2)
  data[40]=string.sub(new_cash, 3,4)
  data[41]='00'
  data[42]='00'
  data[43]='00'
  data[44]='00'
  return fix3rdPartyCash1(uid, data)
end

---
-- repair / fix crc's of a 'Legic-Cash-Segment'
function fixLegicCash(data)
  if(#data==32 and data[7]=="01") then
    local crc1, crc2, crc3
    crc1=("%04x"):format(utils.Crc16(dumpTable(data, "", 0, 12)))
    crc2=("%04x"):format(utils.Crc16(dumpTable(data, "", 15, 20)))
    crc3=("%04x"):format(utils.Crc16(dumpTable(data, "", 23, 29)))
    data[13]=string.sub(crc1, 0, 2)
    data[14]=string.sub(crc1, 3, 4)
    data[21]=string.sub(crc2, 0, 2)
    data[22]=string.sub(crc2, 3, 4)
    data[30]=string.sub(crc3, 0, 2)
    data[31]=string.sub(crc3, 3, 4)
    return data
  end
end

---
-- chack for signature of a '3rd Party Cash-Segment'
-- not all bytes know until yet !!
function check43rdPartyCash1(uid, data)
  if(#data==95) then
    -- too explicit checking will avoid fixing ;-)
    if (compareCrc(utils.Crc8Legic(uid..dumpTable(data, "", 19, 30)), data[31])=="valid") then
      --if (compareCrc(utils.Crc8Legic(uid..data[32]..data[33]), data[34])=="valid") then
        --if (compareCrc(utils.Crc8Legic(uid..data[35]..data[36]), data[37])=="valid") then
         --if (compareCrc(utils.Crc8Legic(uid..dumpTable(data, "", 56, 61)), data[62])=="valid") then
            --if (compareCrc(utils.Crc8Legic(uid..dumpTable(data, "", 74, 88)), data[89])=="valid") then
              io.write("3rd Party Cash-Segment detected ")
              return true
              --end
          --end
          --end
      --end
    end 
  end
  return false
end

---
-- chack for signature of a 'Legic-Cash-Segment'
function check4LegicCash(data)
  if(#data==32) then
    local stamp_len=(#data-25)
    local stamp=""
    for i=0, stamp_len-1 do
      stamp=stamp..data[i].." "
    end
    if (data[7]=="01") then
      if (("%04x"):format(utils.Crc16(dumpTable(data, "", 0, 12))) == data[13]..data[14]) then
        if (("%04x"):format(utils.Crc16(dumpTable(data, "", 15, 20))) == data[21]..data[22]) then
          if (("%04x"):format(utils.Crc16(dumpTable(data, "", 23, 29))) == data[30]..data[31]) then
            io.write("Legic-Cash Segment detected ")
            return true
          end
        end
      end
    end
  end
  return false
end
---
-- calculate Master-Token crc
function calcMtCrc(bytes) 
  --print(#bytes)
  local cmd=bytes[1]..bytes[2]..bytes[3]..bytes[4]..bytes[7]..bytes[6]..bytes[8]
  local len=(tonumber(0xfc ,10)-("%d"):format('0x'..bytes[7]))
  for i=1, len do
    cmd=cmd..bytes[8+i]
  end
  local res=("%02x"):format(utils.Crc8Legic(cmd))
  return res
end

---
-- check all segmnet-crc
function checkAllSegCrc(tag)
  if (istable(tag.SEG[0])) then
    for i=0, #tag.SEG do
      crc=calcSegmentCrc(tag, i)
      tag.SEG[i].crc=crc
    end
    else return print("Matser-Token / unsegmented Tag") end
end

---
-- check all segmnet-crc
function checkAllKghCrc(tag)
  if (istable(tag.SEG[0])) then
    for i=0, #tag.SEG do
      crc=calcKghCrc(tag, i)
      if (tag.SEG[i].kgh) then 
        tag.SEG[i].data[#tag.SEG[i].data-1]=crc
      end
    end
  end
end

---
-- build kghCrc credentials
function kghCrcCredentials(tag, segid) 
  if (istable(tag) and istable(tag.SEG[0])) then
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
  if (istable(tag.SEG[0])) then
  -- check if a 'Kaber Group Header' exists
    local i
    local data=kghCrcCredentials(tag, segid)
    return ("%02x"):format(utils.Crc8Legic(data))
  end
end

---
-- build segmentCrc credentials
function segmentCrcCredentials(tag, segid) 
  if (istable(tag.SEG[0])) then
    local cred = tag.MCD..tag.MSN0..tag.MSN1..tag.MSN2
    cred = cred ..tag.SEG[segid].raw[1]..tag.SEG[segid].raw[2]..tag.SEG[segid].raw[3]..tag.SEG[segid].raw[4]
    return cred
    else return print("Master-Token / unsegmented Tag!") end
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
  if (istable(tag.SEG[0])) then
  -- check if a 'Kaber Group Header' exists
    local data=segmentCrcCredentials(tag, segid)
    return ("%02x"):format(utils.Crc8Legic(data))
  end
end

---
-- helptext for modify-mode
function modifyHelp()
  local t=[[
  
      Data I/O                  Segment Manipulation               Token-Data
  -----------------             --------------------            -----------------
  rt => read    Tag             as => add    Segment            mt => make Token
  wt => write   Tag             es => edit   Segment Header     et => edit Token data 
  ct => copy io Tag             ed => edit   Segment Data       tk => toggle KGH-Flag
  tc => copy oi Tag     rs => remove Segment
  tt => toggle  Tag             cc => check  Segment-CRC            File I/O      
  di => dump  inTag             ck => check  KGH                -----------------  
  do => dump  outTag           e3p => edit   3rd Party Cash     lf => load   File 
  ds => dump  Segment                                           sf => save   File 
 dlc => dump  Legic-Cash                                        xf => xor to File
 d3p => dump  3rd Party Cash                                        
 r3p => raw   3rd Party Cash                                        
    
                           
                                      q => quit
  ]]                    
  return t
end


--- 
-- modify Tag (interactive)
function modifyMode()
  local i, backupTAG,  outTAG, inTAG, outfile, infile, sel, segment, bytes, outbytes
  
  actions = {
     ["h"] = function(x) 
              print("  Version: "..version); 
              print(modifyHelp().."\n".."tags im Memory: "..(istable(inTAG) and ((currentTag=='inTAG') and "*mainTAG" or "mainTAG") or "").."  "..(istable(backupTAG) and ((currentTag=='backupTAG') and "*backupTAG" or "backupTAG") or ""))
            end,
    ["rt"] = function(x) 
                inTAG=readFromPM3(); 
                --actions.di() 
              end,
    ["wt"] = function(x)  
              if(istable(inTAG.SEG)) then 
                local taglen=22
                  if (istable(inTAG.Bck)) then
                for i=0, #inTAG.SEG do
                  taglen=taglen+inTAG.SEG[i].len+5
                end
                end
                
                local uid_old=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                -- read new tag (output tag)
                outTAG=readFromPM3()
                outbytes=tagToBytes(outTAG)
                -- copy 'inputbuffer' to 'outputbuffer'
                inTAG.MCD  = outbytes[1]
                inTAG.MSN0 = outbytes[2]
                inTAG.MSN1 = outbytes[3]
                inTAG.MSN2 = outbytes[4]
                inTAG.MCC  = outbytes[5]
                -- recheck all segments-crc/kghcrc (only on a credential)
                if(istable(inTAG.Bck)) then 
                checkAllSegCrc(inTAG)
                checkAllKghCrc(inTAG)
                  local uid_new=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                  for i=0, #inTAG.SEG do
                    if (check43rdPartyCash1(uid_old, inTAG.SEG[i].data)) then
                      io.write(" - fixing known checksums ... ")
                      inTAG.SEG[i].data=fix3rdPartyCash1(uid_new, inTAG.SEG[i].data)
                      io.write(" done\n")
                end
                  end
                end
                --get bytes from ready outTAG
                bytes=tagToBytes(inTAG)
                -- mater-token-crc
                if (inTAG.Type~="SAM") then bytes[22]=calcMtCrc(bytes) end
                if (bytes) then   
                  writeFile(bytes, 'MylegicClone.hex')         
                  writeToTag(bytes, taglen, 'MylegicClone.hex')
                  actions.rt('') 
                end
               end
              end,
    ---
    -- switich and copy virtual tags
              
    ["ct"] = function(x)  
                print("copy mainTAG to backupTAG")  
                  outTAG=deepCopy(inTAG)
                  backupTAG=deepCopy(inTAG)
            end,
    ["tc"] = function(x)  
                print("copy backupTAG to mainTAG")
                inTAG=deepCopy(backupTAG)
            end,
    ["tt"] = function(x)  
                print("toggle to "..((currentTag=='inTAG') and "backupTAG" or "mainTAG"))
                if(currentTag=="inTAG") then
                  outTAG=deepCopy(inTAG)
                  inTAG=deepCopy(backupTAG)
                  currentTag='backupTAG'
                else
                  inTAG=deepCopy(outTAG)
                  currentTag='inTAG'
                end
            end,
    ["lf"] = function(x)  
              if (file_check(x)) then filename=x
              else  filename=input("enter filename: ", "legic.temp") end
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
    ["di"] = function(x) 
                if (istable(inTAG)) then 
                  local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                  if(istable(inTAG.SEG[0])) then
                    for i=0, #inTAG.SEG do
                      if(check43rdPartyCash1(uid, inTAG.SEG[i].data)) then
                        io.write("in Segment index: "..inTAG.SEG[i].index.."\n")
                      elseif(check4LegicCash(inTAG.SEG[i].data)) then
                        io.write("in Segment index: "..inTAG.SEG[i].index.."\n")
                        lc=true; 
                        lci=inTAG.SEG[i].index;
                      end
                    end
                  end
                  print("\n"..dumpTag(inTAG).."\n") 
                  if (lc) then actions["dlc"](lci) end
                end 
              end,
    ["do"] = function(x) if (istable(backupTAG)) then print("\n"..dumpTag(backupTAG).."\n") end end,
    ["ds"] = function(x) 
                if (type(x)=="string" and string.len(x)>0) then sel=tonumber(x,10)
                else sel=selectSegment(inTAG) end
                if (sel) then print("\n"..(dumpSegment(inTAG, sel) or "no Segments available").."\n") end 
              end,
    ["es"] = function(x) 
              if (type(x)=="string" and string.len(x)>0) then sel=tonumber(x,10)
              else sel=selectSegment(inTAG) end
              if (sel) then 
                if(istable(inTAG.SEG[0])) then
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
                else print("Master-Token / unsegmented Tag!")
              end
            end,
    ["rs"] = function(x) 
              if (istable(inTAG.SEG[0])) then
                if (type(x)=="string" and string.len(x)>0) then sel=tonumber(x,10)
                else sel=selectSegment(inTAG) end
                inTAG=delSegment(inTAG, sel)
                for i=0, #inTAG.SEG do
                  inTAG.SEG[i]=regenSegmentHeader(inTAG.SEG[i])
                end
              end
            end,
    ["ed"] = function(x) 
              if (type(x)=="string" and string.len(x)>0) then sel=tonumber(x,10)
              else sel=selectSegment(inTAG) end
              if (sel) then 
                inTAG.SEG[sel].data=editSegmentData(inTAG.SEG[sel].data) 
              end
            end,
    ["et"] = function(x) 
                if (istable(inTAG)) then
                  editTag(inTAG)
                end
            end,
    ["mt"] = function(x) inTAG=makeToken(); actions.di() end,
     ["ts"] = function(x) 
               if (type(x)=="string" and string.len(x)>0) then sel=tonumber(x,10)
               else sel=selectSegment(inTAG) end
                regenSegmentHeader(inTAG.SEG[sel]) 
              end,
     ["tk"] = function(x) 
               if (istable(inTAG) and istable(inTAG.SEG[0])) then
                if (type(x)=="string" and string.len(x)>0) then sel=tonumber(x,10)
                else sel=selectSegment(inTAG) end
                if(inTAG.SEG[sel].kgh) then inTAG.SEG[sel].kgh=false
                else inTAG.SEG[sel].kgh=true end
               end
              end,
     ["k"] = function(x) 
              if (type(x)=="string" and string.len(x)>0) then
               print(("%02x"):format(utils.Crc8Legic(x)))
              end
              end,
    ["xb"] = function(x)
              end,
     ["xc"] = function(x) 
               if (istable(inTAG) and istable(inTAG.SEG[0])) then
                 if (type(x)=="string" and string.len(x)>0) then sel=tonumber(x,10)
                 else sel=selectSegment(inTAG) end 
                 print("k "..kghCrcCredentials(inTAG, sel)) 
               end 
              end,
    ["dlc"] = function(x) 
                local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                -- if segment index was user defined
                if (type(x)=="string" and string.len(x)>0) then 
                  x=tonumber(x,10)
                  print(string.format("User-Selected Index %02d", x))
                -- or try to find match
                else x=autoSelectSegment(inTAG, "legiccash") end
                local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                if (istable(inTAG.SEG[x])) then
                   io.write("in Segment "..inTAG.SEG[x].index.." :\n")
                   print("--------------------------------\n\tLegic-Cash Values\n--------------------------------")
                   local limit, curr, balance, rid, tcv
                   -- currency of balance & limit
                   curr=currency[inTAG.SEG[x].data[8]..inTAG.SEG[x].data[9]]
                   -- maximum balance
                   limit=string.format("%4.2f", tonumber(inTAG.SEG[x].data[10]..inTAG.SEG[x].data[11]..inTAG.SEG[x].data[12], 16)/100)
                   -- current balance
                   balance=string.format("%4.2f", tonumber(inTAG.SEG[x].data[15]..inTAG.SEG[x].data[16]..inTAG.SEG[x].data[17], 16)/100)
                   -- reader-id who wrote last transaction
                   rid=tonumber(inTAG.SEG[x].data[18]..inTAG.SEG[x].data[19]..inTAG.SEG[x].data[20], 16)
                   -- transaction counter value
                   tcv=tonumber(inTAG.SEG[x].data[29], 16)
                   print("Currency:\t\t "..curr)
                   print("Limit:\t\t\t "..limit)
                   print("Balance:\t\t "..balance)
                   print("Transaction Counter:\t "..tcv)
                   print("Reader-ID:\t\t "..rid.."\n--------------------------------\n")
                 end
                 --end 
              end,
    ["df"] = function(x)
                actions["lf"](x)
                res=""
                for i=0, #inTAG.SEG[1].data do
                  res=res..inTAG.SEG[1].data[i]
                end
                print(res)
              end,
    ["d3p"] = function(x)
                local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                -- if segment index was user defined
                if (type(x)=="string" and string.len(x)>0) then 
                  x=tonumber(x,10)
                  print(string.format("User-Selected Index %02d", x))
                -- or try to find match
                else x=autoSelectSegment(inTAG, "3rdparty") end
                  
                if (istable(inTAG) and istable(inTAG.SEG[x]) and inTAG.SEG[x].len == 100) then
                  uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                  if (check43rdPartyCash1(uid, inTAG.SEG[x].data)) then
                    dump3rdPartyCash1(inTAG, x)
                  end
                end
              end,
    ["r3p"] = function(x)
                local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                -- if segment index was user defined
                if (type(x)=="string" and string.len(x)>0) then 
                  x=tonumber(x,10)
                  print(string.format("User-Selected Index %02d", x))
                -- or try to find match
                else x=autoSelectSegment(inTAG, "3rdparty") end
                local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                if (istable(inTAG.SEG[x])) then
                    print("\n\t\tStamp  :  "..dumpTable(inTAG.SEG[x].data, "", 0 , 2))
                    print("\t\tBlock 0:  "..dumpTable(inTAG.SEG[x].data, "", 3 , 18))
                    print()
                    print("\t\tBlock 1:  "..dumpTable(inTAG.SEG[x].data, "", 19, 30))
                    print("checksum 1: Tag-ID .. Block 1 => LegicCrc8 = "..inTAG.SEG[x].data[31].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(inTAG.SEG[x].data, "", 19, 30)), inTAG.SEG[x].data[31])..")")
                    print()
                    print("\t\tBlock 2:  "..dumpTable(inTAG.SEG[x].data, "", 32, 33))
                    print("checksum 2: Block 2 => LegicCrc8 = "..inTAG.SEG[x].data[34].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(inTAG.SEG[x].data, "", 32, 33)), inTAG.SEG[x].data[34])..")")
                    print()
                    print("\t\tBlock 3:  "..dumpTable(inTAG.SEG[x].data, "", 35, 36))
                    print("checksum 3: Block 3 => LegicCrc8 = "..inTAG.SEG[x].data[37].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(inTAG.SEG[x].data, "", 35, 36)), inTAG.SEG[x].data[37])..")")
                    print()
                    print("\t\tyet unknown: "..inTAG.SEG[x].data[38])
                    print()
                    print("\t\tHisatory 1:  "..dumpTable(inTAG.SEG[x].data, "", 39, 40))  
                    print("\t\tHisatory 2:  "..dumpTable(inTAG.SEG[x].data, "", 41, 42))  
                    print("\t\tHisatory 3:  "..dumpTable(inTAG.SEG[x].data, "", 43, 44))   
                    print()
                    print("\t\tyet unknown: "..inTAG.SEG[x].data[45])         
                    print()
                    print("\t\tKGH-UID HEX:  "..dumpTable(inTAG.SEG[x].data, "", 46, 48))
                    print("\t\tBlock 4:  "..dumpTable(inTAG.SEG[x].data, "", 49, 54))
                    print("checksum 4: Tag-ID .. KGH-UID .. Block 4 => LegicCrc8 = "..inTAG.SEG[x].data[55].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(inTAG.SEG[x].data, "", 46, 54)), inTAG.SEG[x].data[55])..")")
                    print()
                    print("\t\tBlock 5:  "..dumpTable(inTAG.SEG[x].data, "", 56, 61))
                    print("checksum 5: Tag-ID .. Block 5 => LegicCrc8 = "..inTAG.SEG[x].data[62].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(inTAG.SEG[x].data, "", 56, 61)), inTAG.SEG[x].data[62])..")")
                    print()
                    print("\t\tBlock 6:  "..dumpTable(inTAG.SEG[x].data, "", 63, 72))
                    print("checksum 6: Tag-ID .. Block 6 => LegicCrc8 = "..inTAG.SEG[x].data[73].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(inTAG.SEG[x].data, "", 63, 72)), inTAG.SEG[x].data[73])..")")
                    print()
                    print("\t\tBlock 7:  "..dumpTable(inTAG.SEG[x].data, "", 74, 88))
                    print("checksum 7: Tag-ID .. Block 7 => LegicCrc8 = "..inTAG.SEG[x].data[89].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(inTAG.SEG[x].data, "", 74, 88)), inTAG.SEG[x].data[89])..")")
                    print()
                    print("\t\tBlock 8:  "..dumpTable(inTAG.SEG[x].data, "", 90, 94))
                 end
              end,
    ["e3p"] = function(x) 
                local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                -- if segment index was user defined
                if (type(x)=="string" and string.len(x)>0) then 
                  x=tonumber(x,10)
                  print(string.format("User-Selected Index %02d", x))
                -- or try to find match
                else x=autoSelectSegment(inTAG, "3rdparty") end
                  
                if (istable(inTAG) and istable(inTAG.SEG[x]) and inTAG.SEG[x].len == 100) then
                  --if (check43rdPartyCash1(uid, inTAG.SEG[x].data)) then
                    -- change Balance
                    if (confirm("\nedit Balance?")) then
                      local new_cash=input("enter new Balance without comma or currency", "100")
                      inTAG.SEG[x].data=edit3rdCash(new_cash, uid, inTAG.SEG[x].data)
                    end
                    -- change User-ID (used for online-account-mapping)
                    if (confirm("\nedit UserID-Mapping?")) then
                      local new_mapid=input("enter new UserID (6-digit value)", "012345")
                      inTAG.SEG[x].data=edit3rdUid(new_mapid, uid, inTAG.SEG[x].data)
                    end
                    if (confirm("\nedit Stamp?")) then
                      local new_stamp=input("enter new Stamp", getSegmentStamp(inTAG.SEG[x]))
                      inTAG.SEG[x].data=editStamp(new_stamp, uid, inTAG.SEG[x].data)
                      new_stamp=getSegmentStamp(inTAG.SEG[x], 'true')
                      print("stamp_bytes: "..#new_stamp)
                      -- replace stamp in 'block 1' also
                      io.write("editing stamp in Block 1 also ")
                      for i=20, (20+#new_stamp-1) do
                        inTAG.SEG[x].data[i]=new_stamp[i-19]
                        io.write(".");
                      end
                      print(" done")
                      -- fix known checksums
                      inTAG.SEG[x].data=fix3rdPartyCash1(uid, inTAG.SEG[x].data)
                    end
                    
                    -- print out new settings
                    dump3rdPartyCash1(inTAG, x)
                    --end
                end
              end,
    ["gs"] = function(x)
                if(type(x)=="string" and string.len(x)>=2) then x=tonumber(x, 10)
                else x=selectSegment(inTAG) end
                local stamp=getSegmentStamp(inTAG.SEG[x])
                print("Stamp : "..stamp)
                stamp=str2bytes(stamp)
                print("lenght: "..#stamp)
              end,
    ["c6"] = function(x) local crc16=string.format("%4.04x", utils.Crc16(x)) 
                  print(string.sub(crc16, 0,2).." "..string.sub(crc16, 3,4))
              end,
     ["cc"] = function(x)  if (istable(inTAG)) then checkAllSegCrc(inTAG) end end,
    ["cb"] = function(x) 
                if (istable(inTAG)) then
                  print("purge BackupArea")
                  inTAG=clearBackupArea(inTAG) 
                end 
             end, 
   ["f3p"] = function(x) 
               if(type(x)=="string" and string.len(x)>=2) then x=tonumber(x, 10)
               else x=selectSegment(inTAG) end
               if (istable(inTAG.SEG[x])) then 
                  local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                  inTAG.SEG[x].data=fix3rdPartyCash1(uid, inTAG.SEG[x].data)
               end 
              end,
     ["ck"] = function(x)  if (istable(inTAG)) then checkAllKghCrc(inTAG) end end,
  }
  print("modify-modus! enter 'h' for help or 'q' to quit")
  repeat 
    ic=input("Legic command? ('h' for help - 'q' for quit)", "h")
    -- command actions
    if (type(actions[string.lower(string.sub(ic,0,3))])=='function') then
      actions[string.lower(string.sub(ic,0,3))](string.sub(ic,5))
    elseif (type(actions[string.lower(string.sub(ic,0,2))])=='function') then
      actions[string.lower(string.sub(ic,0,2))](string.sub(ic,4))
    elseif (type(actions[string.lower(string.sub(ic,0,1))])=='function') then
      actions[string.lower(string.sub(ic,0,1))](string.sub(ic,3))
    else actions.h('') end
  until (string.sub(ic,0,1)=="q")
end

function clearBackupArea(tag)
  for i=1, #tag.Bck do
    tag.Bck[i]='00'
  end
  return tag
end

function getSegmentStamp(seg, bytes)
  local stamp=""
  local stamp_len=7
  --- the 'real' stamp on MIM is not really easy to tell for me since the 'data-block' covers stamp0..stampn+data0..datan
  -- there a no stamps longer than 7 bytes & they are write-protected by default , and I have not seen user-credntials 
  -- with stamps smaller 3 bytes (except: Master-Token)
  -- WRP -> Read/Write Protection 
  -- WRC -> Read/Write Condition
  -- RD depends on WRC - if WRC > 0 and RD=1: only reader with matching #WRC of Stamp-bytes in thier Database have Read-Access to the Tag
  if (seg.WRP<7) then stamp_len=(seg.WRP) end
  for i=1, (stamp_len) do
    stamp=stamp..seg.data[i-1]
  end
  if (bytes) then 
    stamp=str2bytes(stamp)
    return stamp
  else return stamp end
end

function str2bytes(s)
  local res={}
  if (string.len(s)%2~=0) then return print("stamp should be a even hexstring e.g.: deadbeef or 0badc0de") end
  for i=1, string.len(s), 2 do
    table.insert(res, string.sub(s,i,(i+1)))
  end
  return res
end

function editStamp(new_stamp, uid, data)
  local stamp=str2bytes(new_stamp)
  for i=0, #stamp-1 do
    data[i]=stamp[i+1]
  end
  -- now fill in stamp
  for i=0, (string.len(new_stamp)/2)-1 do
      data[i]=stamp[i+1]
  end
  return fix3rdPartyCash1(uid, data)
end

function autoSelectSegment(tag, s)
  local uid=tag.MCD..tag.MSN0..tag.MSN1..tag.MSN2
  local x=#tag.SEG+1
  local res = false
  io.write("autoSelect ")
  --- search for desired segment-type
  -- 3rd Party Segment
  if (s=="3rdparty") then
    repeat 
      io.write(". ")
      x=x-1
      res=check43rdPartyCash1(uid, tag.SEG[x].data)
    until ( res or x==0 )
   end  
  -- Legic-Cash Segment
  if (s=="legiccash") then
    repeat 
      io.write(". ")
      x=x-1
      res=check4LegicCash(tag.SEG[x].data)
    until ( res or x==0 )
   end
   ---
   -- segment found
   if (res) then
     io.write("\nautoselected Index: "..string.format("%02d", x).."\n")
     return x
   end
   ---
   -- nothing found   
   io.write("no Segment found\n") 
   return -1 
end

--- main function
function main(args)
	if (#args == 0 ) then modifyMode() end
  --- variables
  local inTAG, backupTAG, outTAG, outfile, interactive, crc, ofs, cfs, dfs
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
    if (cfs) then 
      -- xor willl be done in function writeFile
      -- with the value of byte[5]
      bytes[5]=crc 
    end
    -- write to outfile
    if (bytes) then 
      writeFile(bytes, outfile)
      --- read real tag into virtual tag 
      -- inTAG=readFromPM3() end
      --- or simply use the bytes that where wriiten
      inTAG=bytesToTag(bytes, inTAG)
      -- show new content
      if (dfs) then  
        print("-----------------------------------------")
        print(dumpTag(inTAG)) 
      end
    end
  end
  
end

-- Creates a complete/deep copy of the data
function deepCopy(object)
    local lookup_table = {}
    local function _copy(object)
        if type(object) ~= "table" then
            return object
        elseif lookup_table[object] then
            return lookup_table[object]
        end
        local new_table = {}
        lookup_table[object] = new_table
        for index, value in pairs(object) do
            new_table[_copy(index)] = _copy(value)
        end
        return setmetatable(new_table, getmetatable(object))
    end
    return _copy(object)
end

--- start
main(args)