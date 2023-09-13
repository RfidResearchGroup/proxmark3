--[[
if it don't works with you tag-layout - be so kind and let me know ;-)

Tested on Tags with those Layouts:

(example)   Legic-Prime Layout with 'Kaba Group Header'
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


(example)   Legic-Cash on MIM256/1024 tag' (37 bytes)
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

(example)   Legic-Prime Layout 'gantner unsegmented user-credential'
      +----+----+----+----+----+----+----+----+
  0x00|MCD |MSN0|MSN1|MSN2|MCC | 60 | ea | 08 |
      +----+----+----+----+----+----+----+----+
  0x08|Stp0|Stp1|Stp2|Stp3|Stp4|Dat0|Dat1|uCRC| <- addr 0x08..0x0f is WRP
      +----+----+----+----+----+----+----+----+
  0x10|emb0| <- this is only within wrp if addr 0x07==09
      +----+
MCD   = Manufacturer ID
MSN   = Manufacturer SerialNumber
60 ea = DCF Low + DCF high
08    = raw byte which holds the bits for OLE,WRP,WRC,RD
Stp   = Stamp (could be more as 4 - up to 7)
Dat   = Online-Mapping Data
uCRC  = crc8 over addr 0x00..0x03+0x07..0x0E


(example)   Legic-Prime Layout 'gantner unsegmented Master-Token (IAM) with a stamp_len of 4'
      +----+----+----+----+----+----+----+----+
  0x00|MCD |MSN0|MSN1|MSN2|MCC | 20 | f8 | 08 |
      +----+----+----+----+----+----+----+----+
  0x08|Stp0|Stp1|Stp2|Stp3| 00 | 00 | 00 |CRC1|
      +----+----+----+----+----+----+----+----+
  0x10| 00 | 00 | 00 | 00 | 00 |CRC2|
      +----+----+----+----+----+----+
MCD   = Manufacturer ID
MSN   = Manufacturer SerialNumber
60 ea = DCF Low + DCF high
08    = raw byte which holds the bits for OLE,WRP,WRC,RD
Stp   = Stamp (could be more as 4 - up to 7)
Dat   = Online-Mapping Data
CRC1  = crc8 over addr 0x00..0x03+0x07..0x0E (special 'gantner crc8')
CRC2  = MCD + MSB0..2+ addr 0x06 + addr 0x05 + addr 0x07 + Stamp (regular Master-Token-CRC)
--]]

--[[
Known issues; needs to be fixed:
* last byte in last segment is handled incorrectly when it is the last bytes on the card itself (MIM256: => byte 256)
--]]


---
-- requirements
local utils       = require('utils')
local getopt      = require('getopt')
local ansicolors  = require('ansicolors')

---
-- global variables / defines
local bxor    = bit32.bxor
local bbit    = bit32.extract
local input   = utils.input
local confirm = utils.confirm

---
-- init ansicolor-values & ansicolors switch
local colored_output = true
local acoff  = ""
local acgreen= ""
local accyan = ""
local acred  = ""
local acyellow = ""
local acblue = ""
local acmagenta = ""

local acy = ansicolors.yellow
local acc = ansicolors.cyan
local acr = ansicolors.reset

--- Helper ---
---
-- default colors (change to whatever you want)
function load_colors(onoff)
  if (onoff) then
    -- colors
    acgreen = ansicolors.green
    accyan  = ansicolors.cyan
    acred   = ansicolors.red
    acyellow= ansicolors.yellow
    acblue  = ansicolors.blue
    acmagenta= ansicolors.magenta
    acoff   = ansicolors.reset

    acy = ansicolors.yellow
    acc = ansicolors.cyan
    acr = ansicolors.reset
  else
    -- 'no color'
    acgreen = ""
    accyan  = ""
    acred   = ""
    acyellow= ""
    acblue  = ""
    acmagenta= ""
    acoff   = ""

    acy = ""
    acc = ""
    acr = ""
  end
end


example = "script run hf_legic"
author  = "Mosci, uhei"
version = "1.0.5"
desc =
[[

This script helps you to read, create and modify Legic Prime Tags ( MIM22, MIM256, MIM1024 )
The virtual tag (and therefore the file to be saved) is always a MIM1024 tag.
it's kinda interactive with following commands in three categories:

    Data I/O                    Segment Manipulation                   Token-Data
  -----------------             --------------------                -----------------
  ]]..acy..[[rt]]..acr..[[ -> read Tag                ]]..acy..[[as]]..acr..[[ -> add Segment                   ]]..acy..[[mt]]..acr..[[ -> make Token
  ]]..acy..[[wt]]..acr..[[ -> write Tag               ]]..acy..[[es]]..acr..[[ -> edit Segment Header           ]]..acy..[[et]]..acr..[[ -> edit Token data
                                ]]..acy..[[ed]]..acr..[[ => edit Segment Data             ]]..acy..[[tk]]..acr..[[ => toggle KGH-Flag
      File I/O                  ]]..acy..[[rs]]..acr..[[ => remove Segment
  -----------------             ]]..acy..[[cc]]..acr..[[ -> check Segment-CRC
  ]]..acy..[[lf]]..acr..[[ -> load bin File           ]]..acy..[[ck]]..acr..[[ -> check KGH
  ]]..acy..[[sf]]..acr..[[ -> save eml/bin File       ]]..acy..[[ds]]..acr..[[ -> dump Segments
  ]]..acy..[[xf]]..acr..[[ -> xor to File


 (partially) known Segments              Virtual Tags                     Script Output
 ---------------------------    -------------------------------     ------------------------
 ]]..acy..[[dlc]]..acr..[[ -> dump Legic-Cash         ]]..acy..[[ct]]..acr..[[ -> copy mainTag to backupTag     ]]..acy..[[tac]]..acr..[[ -> toggle ansicolors
 ]]..acy..[[elc]]..acr..[[ -> edit Legic-Cash         ]]..acy..[[tc]]..acr..[[ -> copy backupTag to mainTag
 ]]..acy..[[d3p]]..acr..[[ -> dump 3rd-Party-Cash     ]]..acy..[[tt]]..acr..[[ -> switch mainTag & backupTag
 ]]..acy..[[e3p]]..acr..[[ -> edit 3rd-Party-Cash     ]]..acy..[[di]]..acr..[[ -> dump mainTag
                                ]]..acy..[[do]]..acr..[[ => dump backupTag

 rt: 'read tag'          - reads a tag placed near to the PM3
 wt: 'write tag'         - writes the content of the 'virtual inTag' to a tag placed near to th PM3
                          without the need of changing anything - MCD,MSN,MCC will be read from the tag
                          before and applied to the output.

 lf: 'load file'         - load a (xored) binary file (*.bin) from the local Filesystem into the 'virtual inTag'
 sf: 'save file'         - saves the 'virtual inTag' to the local Filesystem as eml and bin (xored with Tag-MCC)
 xf: 'xor file'          - saves the 'virtual inTag' to the local Filesystem (xored with chosen MCC - use '00' for plain values)

 ct: 'copy tag'          - copy the 'virtual Tag' to a second 'virtual TAG' - not useful yet, but inernally needed
 tc: 'copy tag'          - copy the 'second virtual Tag' to 'virtual TAG' - not useful yet, but inernally needed
 tt: 'toggle tag'        - copy mainTag to BackupTag and backupTag to mainTag

 di: 'dump mainTag'      - shows the current content of the 'virtual Tag'
 do: 'dump backupTag'    - shows the current content of the 'virtual outTag'
 ds: 'dump Segments'     - will show the content of a selected Segment
 as: 'add Segment'       - will add a 'empty' Segment to the inTag
 es: 'edit Segment'      - edit the Segment-Header of a selected Segment (len, WRP, WRC, RD, valid)
                          all other Segment-Header-Values are either calculated or not needed to edit (yet)
 ed: 'edit data'         - edit the Data of a Segment (ADF-Aera / Stamp & Payload specific Data)
 et: 'edit Token'        - edit Data of a Token (CDF-Area / SAM, SAM64, SAM63, IAM, GAM specific Data)
 mt: 'make Token'        - create a Token 'from scratch' (guided)
 rs: 'remove segment'    - removes a Segment (except Segment 00, but this can be set to valid=0 for Master-Token)
 cc: 'check Segment-CRC' - checks & calculates (if check failed) the Segment-CRC of all Segments
 ck: 'check KGH-CRC'     - checks the and calculates a 'Kaba Group Header' if one was detected
                          'Kaba Group Header CRC calculation'
 tk: 'toggle KGH'        - toggle the (script-internal) flag for kgh-calculation for a segment
 xc: 'etra c'            - show string that was used to calculate the kgh-crc of a segment

dlc: 'dump Legic-Cash'   - show balance and checksums of a Legic-Cash Segment
elc: 'edit Legic-Cash'   - edit values of a Legic-Cash Segment

d3p: 'dump 3rd Party'    - show balance, history and checksums of a (yet) unknown 3rd-Party Cash Segment
e3p: 'edit 3rd Party'    - edit Data in 3rd-Party Cash Segment

tac: 'toggle ansicolors' - switch on and off the colored text-output of this script
                          default can be changed by setting the variable 'colored_output' to false
]]
currentTag="inTAG"

---
-- curency-codes for Legic-Cash-Segments (ISO 4217)
local currency = {
  ["03D2"]="EUR",
  ["0348"]="USD",
  ["033A"]="GBP",
  ["02F4"]="CHF"
}

---
-- This is only meant to be used when errors occur
function oops(err)
    print(acred.."ERROR: "..acoff ,err)
    return nil, err
end

---
-- Usage help
function help()
    -- the proxmark3 client can't handle such long strings
    -- by breaking up at specific points it still looks good.
    print(string.sub(desc, 0, 1961))
    print(string.sub(desc, 1962, 3925))
    print(string.sub(desc, 3926, #desc))
    print("Version: "..version)
    print("Example usage: "..example)
end

---
-- table check helper
function istable(t)
  return type(t) == 'table'
end

---
-- To have two char string for a byte
local function padString(str)
  if (#str == 1) then
    return '0'..str
  end
  return str
end

---
-- creates a 'deep copy' of a table (a=b only references)
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
-- split csv-string into table
local function split(str, sep)
    local sep = sep or ','
    local fields={}
    local matchfunc = string.gmatch(str, "([^"..sep.."]+)")
    if not matchfunc then return {str} end
    for str in matchfunc do
        table.insert(fields, str)
    end
    return fields
end

---
-- check availability of file
function file_check(file_name)
  if not file_name then return false, "" end

  local arr = split(file_name, ".")
  local path = core.search_file(arr[1], "."..arr[2])
  if (path == nil) then return false end

  local file_found = io.open(path, "r")
  if file_found == nil then
      return false, ""
  else
      file_found:close()
      return true, path
  end
end

---
-- put a string into a bytes-table
function str2bytes(s)
    if (string.len(s)%2 ~= 0) then
        return print("stamp should be a even hexstring e.g.: deadbeef or 0badc0de")
    end
  local res={}
  for i=1, string.len(s), 2 do
    table.insert(res, string.sub(s,i,(i+1)))
  end
  return res
end

---
-- put certain bytes into a new table
function bytesToTable(bytes, bstart, bend)
    local t={}
    for i=0, (bend-bstart) do
        t[i]=padString(bytes[bstart+i])
    end
    return t
end

---
-- read file into table
function getInputBytes(infile)
    local line
    local bytes = {}

    local arr = split(infile, ".")
    local path = core.search_file(arr[1], "."..arr[2])
    if (path == nil) then oops("failed to read from file ".. infile); return false; end

    local fhi,err = io.open(path,"rb")
    if err then oops("failed to read from file ".. path); return false; end

    file_data = fhi:read("*a");
    for i = 1, #file_data do
        bytes[i] = string.format("%x",file_data:byte(i))
    end
    fhi:close()
    if (bytes[7]=='00') then return false end
    print(#bytes .. " bytes from "..path.." loaded")
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
    if istable(tag) == false then return oops("tag is no table in: bytesToTag ("..type(tag)..")") end

    tag.MCD =padString(bytes[1]);
    tag.MSN0=padString(bytes[2]);
    tag.MSN1=padString(bytes[3]);
    tag.MSN2=padString(bytes[4]);
    tag.MCC =padString(bytes[5]);
    tag.DCFl=padString(bytes[6]);
    tag.DCFh=padString(bytes[7]);
    tag.raw =padString(bytes[8]);
    tag.SSC =padString(bytes[9]);
    tag.Type=getTokenType(tag.DCFl);
    tag.OLE=bbit("0x"..tag.DCFl,7,1)
    tag.WRP=("%d"):format(bbit("0x"..bytes[8],0,4))
    tag.WRC=("%d"):format(bbit("0x"..bytes[8],4,3))
    tag.RD=("%d"):format(bbit("0x"..bytes[8],7,1))
    if (tag.Type=="SAM" and tag.raw=='9f') then
    tag.Stamp_len=(tonumber(0xfc,10)-tonumber(bbit("0x"..tag.DCFh,0,8),10))
    elseif (tag.Type=="SAM" and (tag.raw=='08' or tag.raw=='09')) then
      tag.Stamp_len = tonumber(tag.raw,10)
    end
    tag.data=bytesToTable(bytes, 10, 13)
    tag.Bck=bytesToTable(bytes, 14, 20)
    tag.MTC=bytesToTable(bytes, 21, 22)

    print(acgreen.."Tag-Type: ".. tag.Type..acoff)
    if (tag.Type=="SAM" and #bytes>23) then
      tag=segmentsToTag(bytes, tag)
      print(acgreen..(#tag.SEG+1).." Segment(s) found"..acoff)
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
    print(accyan..#bytes.." bytes for Tag processed"..acoff)
    return tag

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
-- read Tag-Table in bytes-table
function tagToBytes(tag)
    if istable(tag) == false then return oops("tag is no table in tagToBytes ("..type(tag)..")") end

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
    return bytes
  end


---
--- PM3 I/O ---
-- write virtual Tag to real Tag
function writeToTag(tag)
    local bytes
    local taglen = 22
    local writeDCF = false
    if(utils.confirm(acred.."\nPlace the (empty) Tag onto the PM3\nand confirm writing to this Tag: "..acoff) == false) then
        return
    end
    if(utils.confirm(acred.."\nShould the decremental field (DCF) be written?: "..acoff) == true) then
        writeDCF = true
    end

    -- get used bytes / tag-len
    if (istable(tag.SEG)) then
        if (istable(tag.Bck)) then
            for i=0, #tag.SEG do
                taglen = taglen + tag.SEG[i] . len
            end
        end
        local uid_old = tag.MCD..tag.MSN0..tag.MSN1..tag.MSN2

        -- read new tag into memory so we can xor the new data with the new MCC
        outTAG = readFromPM3()
        outbytes = tagToBytes(outTAG)
        -- copy 'inputbuffer' to 'outputbuffer'
        tag.MCD  = outbytes[1]
        tag.MSN0 = outbytes[2]
        tag.MSN1 = outbytes[3]
        tag.MSN2 = outbytes[4]
        tag.MCC  = outbytes[5]
        -- recheck all segments-crc/kghcrc (only on a credential)
        if (istable(tag.Bck)) then
            checkAllSegCrc(tag)
            checkAllKghCrc(tag)
            local uid_new = tag.MCD..tag.MSN0..tag.MSN1..tag.MSN2
            for i=0, #tag.SEG do
                if (check43rdPartyCash1(uid_old, tag.SEG[i].data)) then
                    io.write(accyan.."\nfixing known checksums"..acoff.." ... ")
                    if (fix3rdPartyCash1(uid_new, tag.SEG[i].data)) then
                        io.write(acgreen.." done\n"..acoff)
                    else
                        oops("\nsomething went wrong at the repair of the 3rd-party-cash-segment")
                    end
                end
            end
        end
        bytes = tagToBytes(tag)
        -- master-token-crc
        if (tag.Type ~= "SAM") then
            bytes[22] = calcMtCrc(bytes)
        end
        if (bytes) then
            bytes = xorBytes(bytes,tag.MCC)
        end
    end


    -- write data to file
    if (taglen > 0) then
        WriteBytes = input(acyellow.."enter number of bytes to write?"..acoff, taglen)
        -- write pm3-buffer to Tag
        for i=1, WriteBytes do
            if (i > 7) then
                cmd = ("hf legic wrbl -o %d -d %s "):format(i-1, padString(bytes[i]))
                print(acgreen..cmd..acoff)
                core.console(cmd)
                core.clearCommandBuffer()
            elseif (i == 7) then
                if (writeDCF) then
                    -- write DCF in reverse order (requires 'mosci-patch')
                    cmd = ('hf legic wrbl -o 5 -d %s%s'):format(padString(bytes[i-1]), padString(bytes[i]))
                    print(acgreen..cmd..acoff)
                    core.console(cmd)
                    core.clearCommandBuffer()
                else
                    print(acgreen.."skip byte 0x05-0x06 - DCF"..acoff)
                end
            elseif (i == 6) then
                print(acgreen.."skip byte 0x05 - will be written next step"..acoff)
            else
                print(acgreen.."skip byte 0x00-0x04 - unwritable area"..acoff)
            end
            utils.Sleep(0.2)
        end
    end
end

--- File I/O ---
---
-- read file into virtual-tag
local function readFile(filename)
    print(accyan)
    local bytes = {}
    local tag = {}

    local res, path = file_check(filename)
    if not res then
        return oops("input file: "..acyellow..filename..acoff.." not found")
    end

    bytes = getInputBytes(path)
    if bytes == false then return oops('couldnt get input bytes') end

    -- make plain bytes
    bytes = xorBytes(bytes,bytes[5])
    print("create virtual tag from ".. #bytes .. " bytes")
    -- create Tag for plain bytes
    tag = createTagTable()
    -- load plain bytes to tag-table
    print(acoff)
    tag = bytesToTag(bytes, tag)

    return tag
end

local function save_BIN(data, filename)
    local outfile
    local counter = 1
    local ext = ".bin"
    local fn = filename..ext

    -- Make sure we don't overwrite a file
    local res, path = file_check(fn)
    while res == false do
        fn = filename..ext:gsub(ext, "-"..tostring(counter)..ext)
        counter = counter + 1
        res, path = file_check(fn)
    end

    outfile = io.open(path, 'wb')

    local i = 1
    while data[i] do
        local byte = string.char(tonumber(data[i], 16))
        outfile:write(byte)
        i = i + 1
    end
    outfile:close()
    return fn, #data
end
---
-- write bytes to file
function writeFile(bytes, filename)
    local emlext = ".eml"
    local res, path
    if (filename ~= 'MyLegicClone') then
        res, path = file_check(filename..emlext)
        if res then
            local answer = confirm("\nthe output-file "..path.." already exists!\nthis will delete the previous content!\ncontinue?")
            if not answer then return print("user abort") end
        end
    end
    local line
    local bcnt = 0
    local fho, err = io.open(path, "w")
    if err then
        return oops("OOps ... failed to open output-file ".. path)
    end

    bytes = xorBytes(bytes, bytes[5])

    for i = 1, #bytes do
        if (bcnt == 0) then
            line = padString(bytes[i])
        elseif (bcnt <= 7) then
            line = line.." "..padString(bytes[i])
        end
        if (bcnt == 7) then
            -- write line to new file
            fho:write(line.."\n")
            -- reset counter & line
            bcnt = -1
            line = ""
        end
        bcnt = bcnt + 1
    end
    fho:close()

    print("\nwrote "..acyellow..(#bytes * 3)..acoff.." bytes to " ..acyellow..filename..emlext..acoff)

    -- save binary
    local fn_bin, fn_bin_num = save_BIN(bytes, filename)
    if fn_bin and fn_bin_num then
        print("\nwrote "..acyellow..fn_bin_num..acoff.." bytes to BINARY file "..acyellow..fn_bin..acoff)
    end

    return true
end

function getRandomTempName()
  local upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  local lowerCase = "abcdefghijklmnopqrstuvwxyz"

  local characterSet = upperCase .. lowerCase

  local keyLength = 8
  local output = ""

  for   i = 1, keyLength do
    local rand = math.random(#characterSet)
    output = output .. string.sub(characterSet, rand, rand)
  end

  output = "hf-legic-temp-" .. output

  return output
end

---
-- read from pm3 into virtual-tag
function readFromPM3()
  local tag, bytes, infile
    --infile="legic.temp"
    infile=getRandomTempName()
    core.console("hf legic dump -f "..infile)
    tag=readFile(infile..".bin")

    res, path = file_check(infile..".bin")
    if not res then return nil end
    os.remove(path)

    res, path = file_check(infile..".eml")
    os.remove(path)

    res, path = file_check(infile..".json")
    os.remove(path)
    return tag
end

--- Map related ---
---
-- make tagMap
local function makeTagMap()
    local tagMap = {}
    if (#tagMap == 0) then
        tagMap['name'] = input(accyan.."enter Name for this Map: "..acoff , "newTagMap")
        tagMap['mappings'] = {}
        tagMap['crc8'] = {}
        -- insert fixed Tag-CRC
        table.insert(tagMap.crc8, {name = 'TAG-CRC', pos = 5, seq = {1, 4}})
        tagMap['crc16'] = {}
    end
    print(accyan.."new tagMap created"..acoff)
    return tagMap
end

---
-- save mapping to file
local function saveTagMap(map, filename)

    local res, path

    if #filename > 0 then
       res, path = file_check(filename)
        if res then
            local answer = confirm("\nthe output-file "..acyellow..path..acoff.." alredy exists!\nthis will delete the previous content!\ncontinue?")
            if not answer then return print("user abort") end
        end
    end

    local line
    local fho,err = io.open(path, "w")
    if err then oops("OOps ... failed to open output-file "..acyellow..path..acoff) end

    -- write line to new file
    for k, v in pairs(map) do
        if (istable(v)) then
            for k2, v2 in pairs(v) do
                if (k == 'mappings') then
                    fho:write(k..","..k2..","..v2['name']..","..v2['start']..","..v2['end']..","..((v2['highlight']) and "1" or "0").."\n")
                elseif (k == "crc8") then
                    local tmp = ""
                    tmp = k..","..k2..","..v2['name']..","..v2['pos']..","
                    tmp=tmp..tbl2seqstr(v2['seq'])
                    fho:write(tmp.."\n")
                end
            end
        else
            fho:write(k..","..v.."\n")
        end
    end
    fho:close()
    return true
end

---
-- toggle higligh
local function toggleHighlight(tbl)
    if (tbl['highlight']) then
        tbl['highlight'] = false
    else
        tbl['highlight'] = true
    end
    return tbl
end

---
-- return table od seqence-string
local function seqstr2tbl(seqstr)
    local s = split(seqstr)
    local res = {}
    if (#s >= 1) then
        for sk, sv in pairs(s) do
            s2 = split(sv, '-')
            if(#s2 == 2) then
                table.insert(res, s2[1])
                table.insert(res, s2[2])
            end
        end
    end
    return res
end

---
-- return sequence-string from table
local function tbl2seqstr(seqtbl)
    local res = ""
    if (istable(seqtbl)) then
        for sk, sv in pairs(seqtbl) do
            res = res..sv..((sk%2==0) and "," or "-")
        end
        if (string.sub(res, string.len(res))== ",") then
            res = string.sub(res, 1, string.len(res)-1)
        end
    end
    return res
end

---
-- read map-file into map
function loadTagMap(filename)
  local map={mappings={}, crc8={}, crc16={}}
  local m=0
  local c=0
  local line, fields
  local temp={}
  local offset=0

  local res, path = file_check(filename)
  if not res then
      return oops("input file: "..acyellow..filename..acoff.." not found")
  else

    local fhi,err = io.open(path)
    while true do
        line = fhi:read()
        if line == nil then
        break
      else
        fields = split(line)
      end
        if (#fields == 2) then
        if (fields[1] == 'offset') then
          offset = tonumber(fields[2],10)
        end
        -- map-name
        map[fields[1]]=fields[2]
      elseif (fields[1]=='mappings') then
        m=m+1
        temp={}
        -- mapping
        temp['name']=fields[3]
        temp['start']=tonumber(fields[4], 10)
        temp['end']=tonumber(fields[5], 10)
        if(temp['start']>22) then
          temp['start']=temp['start']+offset
          temp['end']=temp['end']+offset
        end
        if (tonumber(fields[6], 10)==1) then temp['highlight']= true
        else temp['highlight']= false end
        table.insert(map['mappings'], m, temp)
      elseif (fields[1]=='crc8') then
        c=c+1
        temp={}
        -- crc8
        temp['name']=fields[3]
        temp['pos']=tonumber(fields[4], 10)+offset
        local s=string.sub(line, string.len(fields[1]..","..fields[2]..","..fields[3]..",")+1, string.len(line))
        temp['seq']=seqstr2tbl(s)
        for k, v in pairs(temp['seq']) do
          if(tonumber(v, 10)>22) then v=tonumber(v, 10)+offset end
          temp['seq'][k]=tonumber(v, 10)
        end
        table.insert(map.crc8, temp)
      end
    end
    fhi:close()
  end
  return map
end

---
-- dump tagMap (mappings only)
function dumpTagMap(tag, tagMap)
  if(#tagMap.mappings>0) then
    bytes=tagToBytes(tag)
    local temp
    local lastend=0
    -- start display mappings
    for k, v in pairs(tagMap.mappings) do
      if ((lastend+1)<v['start']) then
        print("...")
      end
      if (isPosCrc8(tagMap, v['start'])>0) then
        if ( checkMapCrc8(tagMap, bytes, isPosCrc8(tagMap, v['start']) ) ) then
          io.write("("..("%04d"):format(v['start']).."-"..("%04d"):format(v['end'])..") "..acgreen..v['name']..acoff)
        else
          io.write("("..("%04d"):format(v['start']).."-"..("%04d"):format(v['end'])..") "..acred..v['name']..acoff)
        end
      else
        io.write("("..("%04d"):format(v['start']).."-"..("%04d"):format(v['end'])..") "..((v['highlight']) and acmagenta or acyellow)..v['name']..acoff)
      end

      temp = ""
      while (#v['name'] + temp:len()) < 20 do temp = temp.." " end

      for i=v['start'], v['end'] do
        temp=temp..bytes[i].." "
      end

      print(temp)
      lastend=v['end']
    end
  end
end

---
--
function isPosCrc8(tagMap, pos)
  local res=0
  if (#tagMap.crc8>0) then
    for k, v in pairs(tagMap.crc8) do
      if(v['pos']==pos) then res=k end
    end
  end
  return res
end

---
-- check mapped crc
function checkMapCrc8(tagMap, bytes, n)
  local res=false
  if (#tagMap.crc8>0) then
    if(istable(tagMap.crc8[n])) then
      temp=""
      for k2, v2 in pairs(tagMap.crc8[n]) do
        if (istable(v2)) then
            temp=temp..tbl2seqstr(v2)
        end
      end
      local tempres=""
      local tempres=getSequences(bytes, temp)
      tempres=("%02x"):format(utils.Crc8Legic(tempres))
      if (bytes[tagMap.crc8[n]['pos']]==tempres) then
        res=true
      end
    end
  end
  return res
end

---
-- edit existing Map
function editTagMap(tag, tagMap)
  local t = [[
]]..acc..[[Data]]..acr..[[

    ]]..acy..[[dm]]..acr..[[  - show         ]]..acy..[[dr]]..acr..[[  - dump raw

]]..acc..[[Mappings]]..acr..[[

    ]]..acy..[[im]]..acr..[[  - insert       ]]..acy..[[am]]..acr..[[  - add
    ]]..acy..[[rm]]..acr..[[  - remove       ]]..acy..[[mas]]..acr..[[ - map all segments

]]..acc..[[CRC8]]..acr..[[

    ]]..acy..[[ac8]]..acr..[[ - add          ]]..acy..[[sc8]]..acr..[[ - show
    ]]..acy..[[rc8]]..acr..[[ - remove

    ]]..acy..[[q]]..acr..[[   - exit         ]]..acy..[[h]]..acr..[[   - Help
  ]]

  --if(#tagMap.mappings==0) then oops("no mappings in tagMap"); return tagMap end
  print("tagMap edit-mode submenu")
  repeat
    x=input('tagMap submenu:', 'h')
      if      (x=='h') then print(t)
      elseif  (x=='dm') then tagMmap=dumpTagMap(tag, tagMap)
      elseif  (x=='dr') then tagMmap=dumpMap(tag, tagMap)
      elseif  (x=='rc8') then
        if (istable(tagMap.crc8)) then
          local x1 = selectTableEntry(tagMap.crc8, "select number of CRC8 to remove:")
          if (istable(tagMap.crc8[x1])) then
            table.remove(tagMap.crc8, x1)
          end
        end
      elseif  (x=='ac8') then
        local p=tonumber(input("enter byte-addr of crc8", '0'),10)
        if (p>0) then
          local i1=input("enter comma-seperated byte-sequences (e.g.: '1-4,23-26')", '1-4,23-26')
          local s1=split(i1, ',')
          if (#s1>0) then
            local temp={seq={}}
            for k, v in pairs(s1) do
              v1=split(v, '-')
              if(#v1==2) then
                table.insert(temp.seq, v1[1])
                table.insert(temp.seq, v1[2])
              end
            end
            temp['pos']=p
            temp['name']=input("enter a name for the CRC8", "CRC "..(#tagMap.crc8+1))
            table.insert(tagMap.crc8, temp)
          end
        end
      elseif  (string.sub(x, 1, 3)=='sc8') then
        local bytes=tagToBytes(tag)
        local res, pos
        -- trigger manually by sc8 <'4digit' checkadd> <'seqeuence-string'>
        -- e.g.: sc8 0027 1-4,23-36
        if (string.len(x)>=9) then
          pos=tonumber(string.sub(x, 5, 8), 10)
          x=string.sub(x, 9, string.len(x))
          print("x: "..x.."  - pos:"..pos)
        else
          x=selectTableEntry(tagMap.crc8, "select CRC:")
          if(istable(tagMap.crc8[x])) then
            pos=tagMap.crc8[x]['pos']
            x=tbl2seqstr(tagMap.crc8[x]['seq'])
          end
        end
        if (type(x)=='string') then
          res=("%02x"):format(utils.Crc8Legic(getSequences(bytes, x)))
          print(accyan.."Sequence:\t"..acoff..x)
          print(accyan.."Bytes:\t\t"..acoff..getSequences(bytes, x))
          print(accyan.."calculated: "..acoff..res..accyan.." bytes["..pos.."]: "..acoff..bytes[pos].." ("..compareCrc(utils.Crc8Legic(getSequences(bytes, x)), bytes[pos])..")")
        end
      elseif (x=="tm") then
          x=selectTableEntry(tagMap.mappings, "select number of Mapping:")
          tagMap.mappings[x]=toggleHighlight(tagMap.mappings[x])
      elseif  (x=='am') then tagMap=addMapping(tag, tagMap)
      elseif  (x=='im') then tagMap=addMapping(tag, tagMap, selectTableEntry(tagMap.mappings, "select List-Position for insert:"))
      elseif  (x=='rm') then tagMap=deleteMapping(tag, tagMap)
      elseif  (x=='mas') then tagMap=mapTag(tagMap); tagMap=mapAllSegments(tag, tagMap)
      elseif  (type(actions[string.sub(x, 3)])=='function') then actions[string.sub(x, 3)]()
      end
  until x=='q'
  print("exit sub-Menu")
  return tagMap
end

---
-- dump raw mapped and unmapped
function dumpMap(tag, tagMap)
  local dstart=1
  local dend, cnt
  local bytes = tagToBytes(tag)
  local stats = getSegmentStats(bytes)
  dend=stats[#stats]['end']
  print(accyan.."Tag uses "..dend.." bytes:"..acoff)
  for i=dstart, dend do
    if (check4MappedByte(i, tagMap) and not check4MapCrc8(i, tagMap) and not check4Highlight(i, tagMap)) then io.write(""..acyellow)
    elseif (check4MapCrc8(i, tagMap)) then
      if ( checkMapCrc8(tagMap, bytes, isPosCrc8(tagMap, i) ) ) then
        io.write(""..acgreen)
      else
        io.write(""..acred)
      end
    else
      io.write(""..acoff)
    end
    -- highlighted mapping
    if (check4Highlight(i, tagMap)) then io.write(""..acmagenta) end

    io.write(bytes[i])
    if (i%8==0) then io.write("\n")
      else io.write(" ") end
  end

  io.write("\n"..acoff)
end

---
-- show bytes used for crc-calculation
function getSequences(bytes, seqstr)
  if (type(seqstr) ~= "string") then seqstr = input("enter comma-seperated sequences (e.g.: '1-4,23-26')", '1-4,23-26') end
  local seqs = split(seqstr, ',')
  local res = ""
  if(#seqs>0) then
    for k, v in pairs(seqs) do
      local seq = split(v,'-')
      if (#seq >= 2) then
        for i = seq[1], seq[2] do
          res = res..bytes[i].." "
        end
      end
      if(string.len(res)>0) then res = res.."  " end
    end
  else
    oops("no sequence found in '"..seqstr.."'")
  end
  return res
end

---
-- check if byte-addr is a know crc
function check4MapCrc8(addr, tagMap)
  local res=false
  for i=1, #tagMap.crc8 do
    if (addr == tagMap.crc8[i]['pos']) then
      res=true
    end
  end
  return res
end

---
-- check if byte-addr is a know crc
function check4MapCrc16(addr, tagMap)
  local res=false
  for i=1, #tagMap.crc16 do
    if (addr == tagMap.crc16[i]['pos']) then
      res=true
    end
  end
  return res
end

---
-- check if byte is mapped or not
function check4MappedByte(addr, tagMap)
  local res=false
  for _, v in pairs(tagMap.mappings) do
    if (addr >= v['start'] and addr <= v['end'] ) then
      res= true
    end
  end
  return res
end

---
-- check if byte is highlighted or not
function check4Highlight(addr, tagMap)
  local res = false
  for _, v in pairs(tagMap.mappings) do
    if (addr >= v['start'] and addr <= v['end'] ) then
      res = v['highlight']
    end
  end
  return res
end

---
-- add interactive mapping
function addMapping(tag, tagMap, x)
  if (type(x) ~= "number") then x = #tagMap.mappings + 1 end
  local bytes = tagToBytes(tag)
  local myMapping = {}
  myMapping['name']  = input(accyan.."enter Maping-Name:"..acoff, string.format("mapping %d", #tagMap.mappings+1))
  myMapping['start'] = tonumber(input(accyan.."enter start-addr:"..acoff, '1'), 10)
  myMapping['end']   = tonumber(input(accyan.."enter end-addr:"..acoff, #bytes), 10)
  myMapping['highlight'] = confirm("set highlighted")
  table.insert(tagMap.mappings, x, myMapping)
  return tagMap
end

---
-- delete mapping
function deleteMapping(tag, tagMap)
  if(#tagMap.mappings>0) then
    local d = selectTableEntry(tagMap.mappings, "select number of Mapping to remove:")
    if (type(d)=='number') then
      table.remove(tagMap.mappings, d)
    else oops("deleteMapping: got type = "..type(d).." - expected type = 'number'")
    end
  end
  return tagMap
end

---
-- select a mapping from a tagmap
function selectTableEntry(table, action)
  if (type(action) ~= "string") then action = "select number of item:" end
  for k, v in pairs(table) do
    print(accyan..k..acoff.."\t-> "..accyan..v['name']..acoff)
  end
  local res = tonumber(input(action , 0), 10)
  if (istable(table[res])) then
    return  res
  else
    return false
  end
end

---
-- map all segments
function mapAllSegments(tag, tagMap)
  local bytes=tagToBytes(tag)
  local WRP,WRC,WRPC
  segs=getSegmentStats(bytes)
  if (istable(segs)) then
    for k, v in pairs(segs) do
      -- wrp (write proteted) = byte 2
      WRP = tonumber(bytes[v['start']+2],16)
      -- wrc (write control) - bit 4-6 of byte 3
      WRC = tonumber(bbit("0x"..bytes[v['start']+3],4,3),16)
      --tagMap=mapTokenData(tagMap, 'Segment '..("%02d"):format(v['index']).." HDR", v['start'], v['start']+3)
      tagMap=mapTokenData(tagMap, 'Segment '..("%02d"):format(v['index']).." CRC", v['start']+4, v['start']+4, true)
      table.insert(tagMap.crc8, {name = 'Segment '..("%02d"):format(v['index']).." CRC", pos=v['start']+4, seq={1,4,v['start'],v['start']+3}} )
      if(WRC>WRP) then
        WRPC=WRC
        tagMap=mapTokenData(tagMap, 'Segment '..("%02d"):format(v['index']).." WRC", v['start']+5, v['start']+5+WRC-1, true)
      elseif (WRP>WRC and WRC>0) then
        WRPC=WRP
        tagMap=mapTokenData(tagMap, 'Segment '..("%02d"):format(v['index']).." WRC", v['start']+5, v['start']+5+WRC-1, true)
        tagMap=mapTokenData(tagMap, 'Segment '..("%02d"):format(v['index']).." WRP", v['start']+WRC+5, v['start']+5+WRP-1, true)
      else
        WRPC=WRP
        tagMap=mapTokenData(tagMap, 'Segment '..("%02d"):format(v['index']).." WRP", v['start']+5, v['start']+5+WRP-1, true)
      end
      tagMap=mapTokenData(tagMap, 'Segment '..("%02d"):format(v['index']).." data", v['start']+5+WRPC, v['end'], false)

    end
    print(#segs.." Segments mapped")
  else
    oops("autoMapSegments failed: no Segments found")
  end
  return tagMap
end

---
-- map all token data
function mapTokenData(tagMap, mname, mstart, mend, mhigh)
  --if ( not mhigh ) then mhigh=false end
  local myMapping = {}
  myMapping['name'] = mname
  myMapping['start'] = mstart
  myMapping['end'] = mend
  myMapping['highlight'] = mhigh
  table.insert(tagMap.mappings, myMapping)
  return tagMap
end

---
-- map a map
function mapTag(tagMap)
  tagMap=makeTagMap()
  tagMap=mapTokenData(tagMap, 'Tag-ID', 1, 4, true)
  tagMap=mapTokenData(tagMap, 'Tag-CRC', 5, 5, false)
  tagMap=mapTokenData(tagMap, 'DCF', 6, 7, true)
  tagMap=mapTokenData(tagMap, 'THDR-Raw/Stamp-Len', 8, 8, true)
  tagMap=mapTokenData(tagMap, 'SSC', 9, 9, true)
  tagMap=mapTokenData(tagMap, 'Header', 10, 13, false)
  tagMap=mapTokenData(tagMap, 'Backup', 14, 19, true)
  tagMap=mapTokenData(tagMap, 'Bck-CRC', 20, 20, false)
  tagMap=mapTokenData(tagMap, 'TokenTime', 21, 22, false)
  return tagMap
end

--- Dump Data ---
---
-- dump virtual Tag-Data
function dumpTag(tag)
  local i, i2
  local res
  local dp=0
  local raw=""
  -- sytstem area
  res =acyellow.."\nCDF: System Area"..acoff
  res= res.."\n"..dumpCDF(tag)
  -- segments (user-token area)
  if(tag.Type=="SAM" and tag.raw=='9f') then
    res = res..acyellow.."\n\nADF: User Area"..acoff
    for i=0, #tag.SEG do
      res=res.."\n"..dumpSegment(tag, i).."\n"
    end
  end
  return res
end

---
-- dump tag-system area
function dumpCDF(tag)
  local res=""
  local i=0
  local raw=""
  local bytes
  if (istable(tag)) then
    res = res..accyan.."MCD: "..acoff..tag.MCD..accyan.." MSN: "..acoff..tag.MSN0.." "..tag.MSN1.." "..tag.MSN2..accyan.." MCC: "..acoff..tag.MCC.."\n"
    res = res.."DCF: "..tag.DCFl.." "..tag.DCFh..", Token_Type="..tag.Type.." (OLE="..tag.OLE.."), Stamp_len="..tag.Stamp_len.."\n"
    res = res.."WRP="..tag.WRP..", WRC="..tag.WRC..", RD="..tag.RD..", raw="..tag.raw..((tag.raw=='9f') and (", SSC="..tag.SSC.."\n") or "\n")

    -- credential (end-user tag)
    if (tag.Type=="SAM" and tag.raw=='9f') then
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
    elseif (tag.Type~="SAM") then
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


    -- 'Gantner User-Credential' specific
    elseif (tag.Type=="SAM" and (tag.raw=='08' or tag.raw=='09')) then
      print(acgreen.."Gantner Detected"..acoff)
    end

    return res
  else print(acred.."no valid Tag in dumpCDF"..acoff) end
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
  if ( (istable(tag.SEG[i])) and tag.Type=="SAM" and tag.raw=="9f") then
    if (istable(tag.SEG[i].raw)) then
      for k,v in pairs(tag.SEG[i].raw) do
        raw=raw..v.." "
      end
    end

    -- segment header
    res = res..accyan.."Segment "..("%02d"):format(tag.SEG[i].index)..acoff..": "
    res = res .."raw header: "..string.sub(raw,0,-2)..", flag="..tag.SEG[i].flag..", (valid="..("%x"):format(tag.SEG[i].valid)..", last="..("%x"):format(tag.SEG[i].last).."), "
    res = res .."len="..("%04d"):format(tag.SEG[i].len)..", WRP="..("%02x"):format(tag.SEG[i].WRP)..", WRC="..("%02x"):format(tag.SEG[i].WRC)..", "
    res = res .."RD="..("%02x"):format(tag.SEG[i].RD)..", CRC="..tag.SEG[i].crc.." "
    res = res .."("..(checkSegmentCrc(tag, i) and acgreen.."valid" or acred.."error") ..acoff..")"
    raw=""


    -- WRC protected
    if ((tag.SEG[i].WRC>0)) then
      res = res .."\nWRC protected area:\n"
      for i2=dp, dp+tag.SEG[i].WRC-1 do
        res = res..tag.SEG[i].data[i2].." "
        dp=dp+1
      end
    end

    -- WRP mprotected
    if (tag.SEG[i].WRP>tag.SEG[i].WRC) then
      res = res .."\nRemaining write protected area:\n"
      for i2=dp, dp+(tag.SEG[i].WRP-tag.SEG[i].WRC)-1 do
        res = res..tag.SEG[i].data[i2].." "
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
       res = res..tag.SEG[i].data[dp].." (KGH: "..(checkKghCrc(tag, i) and acgreen.."valid" or acred.."error") ..acoff..")"
     else  res = res..tag.SEG[i].data[dp] end
    end
    dp=0
    return res
  else
    return print(acred.."Segment not found"..acoff)
  end
end

---
-- return bytes 'sstrat' to 'send' from a table
function dumpTable(tab, header, tstart, tend)
  res=""
  for i=tstart, tend do
    res=res..tab[i].." "
  end
    if (#header == 0) then
        return res
    else
        return (header.." #"..(tend-tstart+1).."\n"..res)
    end
end

---
-- dump 3rd Party Cash
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
-- dump Legic-Cash data
function dumpLegicCash(tag, x)

    if istable(tag.SEG[x]) == false then return end

     io.write("in Segment "..tag.SEG[x].index.." :\n")
     print("--------------------------------\n\tLegic-Cash Values\n--------------------------------")
     local limit, curr, balance, rid, tcv
     -- currency of balance & limit
     curr=string.upper(tag.SEG[x].data[8]..tag.SEG[x].data[9])
     if currency[curr] ~= nil then
       curr = currency[curr]
     end
     -- maximum balance
     limit=string.format("%4.2f", tonumber(tag.SEG[x].data[10]..tag.SEG[x].data[11]..tag.SEG[x].data[12], 16)/100)
     -- current balance
     balance=string.format("%4.2f", tonumber(tag.SEG[x].data[15]..tag.SEG[x].data[16]..tag.SEG[x].data[17], 16)/100)
     -- reader-id who wrote last transaction
     rid=tonumber(tag.SEG[x].data[18]..tag.SEG[x].data[19]..tag.SEG[x].data[20], 16)
     -- transaction counter value
     tcv=tonumber(tag.SEG[x].data[29], 16)
     print("Currency:\t\t "..curr)
     print("Limit:\t\t\t "..limit)
     print("Balance:\t\t "..balance)
     print("Transaction Counter:\t "..tcv)
     print("Reader-ID:\t\t "..rid.."\n--------------------------------\n")
   end

---
--  raw 3rd-party
function print3rdPartyCash1(tag, x)

    if istable(tag.SEG[x]) == false then return end

    local uid=tag.MCD..tag.MSN0..tag.MSN1..tag.MSN2
     print("\n\t\tStamp  :  "..dumpTable(tag.SEG[x].data, "", 0 , 2))
     print("\t\tBlock 0:  "..dumpTable(tag.SEG[x].data, "", 3 , 18))
     print()
     print("\t\tBlock 1:  "..dumpTable(tag.SEG[x].data, "", 19, 30))
     print("checksum 1: Tag-ID .. Block 1 => LegicCrc8 = "..tag.SEG[x].data[31].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[x].data, "", 19, 30)), tag.SEG[x].data[31])..")")
     print()
     print("\t\tBlock 2:  "..dumpTable(tag.SEG[x].data, "", 32, 33))
     print("checksum 2: Block 2 => LegicCrc8 = "..tag.SEG[x].data[34].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[x].data, "", 32, 33)), tag.SEG[x].data[34])..")")
     print()
     print("\t\tBlock 3:  "..dumpTable(tag.SEG[x].data, "", 35, 36))
     print("checksum 3: Block 3 => LegicCrc8 = "..tag.SEG[x].data[37].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[x].data, "", 35, 36)), tag.SEG[x].data[37])..")")
     print()
     print("\t\tyet unknown: "..tag.SEG[x].data[38])
     print()
     print("\t\tHisatory 1:  "..dumpTable(tag.SEG[x].data, "", 39, 40))
     print("\t\tHisatory 2:  "..dumpTable(tag.SEG[x].data, "", 41, 42))
     print("\t\tHisatory 3:  "..dumpTable(tag.SEG[x].data, "", 43, 44))
     print()
     print("\t\tyet unknown: "..tag.SEG[x].data[45])
     print()
     print("\t\tKGH-UID HEX:  "..dumpTable(tag.SEG[x].data, "", 46, 48))
     print("\t\tBlock 4:  "..dumpTable(tag.SEG[x].data, "", 49, 54))
     print("checksum 4: Tag-ID .. KGH-UID .. Block 4 => LegicCrc8 = "..tag.SEG[x].data[55].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[x].data, "", 46, 54)), tag.SEG[x].data[55])..")")
     print()
     print("\t\tBlock 5:  "..dumpTable(tag.SEG[x].data, "", 56, 61))
     print("checksum 5: Tag-ID .. Block 5 => LegicCrc8 = "..tag.SEG[x].data[62].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[x].data, "", 56, 61)), tag.SEG[x].data[62])..")")
     print()
     print("\t\tBlock 6:  "..dumpTable(tag.SEG[x].data, "", 63, 72))
     print("checksum 6: Tag-ID .. Block 6 => LegicCrc8 = "..tag.SEG[x].data[73].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[x].data, "", 63, 72)), tag.SEG[x].data[73])..")")
     print()
     print("\t\tBlock 7:  "..dumpTable(tag.SEG[x].data, "", 74, 88))
     print("checksum 7: Tag-ID .. Block 7 => LegicCrc8 = "..tag.SEG[x].data[89].." ("..compareCrc(utils.Crc8Legic(uid..dumpTable(tag.SEG[x].data, "", 74, 88)), tag.SEG[x].data[89])..")")
     print()
     print("\t\tBlock 8:  "..dumpTable(tag.SEG[x].data, "", 90, 94))
  end

--- Token related --
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
    ttype = ttype..k..") "..v.."  "
  end
  mtq = tonumber(input("select number for Token-Type\n"..ttype, '1'), 10)
  if (type(mtq) ~= "number") then return print("selection invalid!")
  elseif (mtq > #mt.Type) then return print("selection invalid!")
  else print("Token-Type '"..mt.Type[mtq].."' selected") end
  local raw = calcHeaderRaw(mt.WRP[mtq], mt.WRC[mtq], mt.RD[mtq])
  local mtCRC = "00"

  bytes = {"01", "02", "03", "04", "cb", string.sub(mt.DCF[mtq], 0, 2), string.sub(mt.DCF[mtq], 3), raw,
         "00", "00", "00", "00", "00", "00", "00", "00",
         "00", "00", "00", "00", "00", "00"}
  if (mtq == 1) then
    for i = 0, #mt.Segment do
      table.insert(bytes, mt.Segment[i])
    end
    bytes[9] = "ff"
  end
  -- fill bytes
  for i = #bytes, 1023 do table.insert(bytes, "00") end

  -- if Master-Token -> calc Master-Token-CRC
  if (mtq>1) then bytes[22] = calcMtCrc(bytes) end

  local tempTag = createTagTable()
  -- remove segment if MasterToken
  if (mtq>1) then tempTag.SEG[0] = nil end

  return bytesToTag(bytes, tempTag)
end

---
-- edit token-data
function editTag(tag)
  -- for simulation it makes sense to edit everything
  local edit_sim = "MCD MSN0 MSN1 MSN2 MCC DCFl DCFh WRP WRC RD"
  -- on real tags it makes only sense to edit DCF, WRP, WRC, RD
  local edit_real = "DCFl DCFh WRP WRC RD"
  if (confirm(acyellow.."do you want to edit non-writeable values (e.g. for simulation)?"..acoff)) then
    edit_tag = edit_sim
  else edit_tag = edit_real end

  if(istable(tag)) then
    for k,v in pairs(tag) do
      if(type(v) ~= "table" and type(v) ~= "boolean" and string.find(edit_tag, k)) then
        tag[k] = input("value for: "..accyan..k..acoff, v)
      end
    end

    if (tag.Type == "SAM") then ttype = "Header"; else ttype = "Stamp"; end
      if (confirm(acyellow.."do you want to edit "..ttype.." Data?"..acoff)) then
      -- master-token specific
      if(istable(tag.Bck) == false) then
        -- stamp-data length=(0xfc-DCFh)
        -- on MT: SSC holds the Starting Stamp Character (Stamp0)
        tag.SSC=input(ttype.."0: ", tag.SSC)
        -- rest of stamp-bytes are in tag.data 0..n
        for i=0, (tonumber(0xfc ,10)-("%d"):format('0x'..tag.DCFh))-2 do
        tag.data[i] = input(ttype.. i+1 ..": ", tag.data[i])
        end
      else
        --- on credentials byte7 should always be 9f and byte8 ff
        -- on Master-Token not (even on SAM63/64 not)
        -- tag.SSC=input(ttype.."0: ", tag.SSC)
        for i=0, #tag.data do
           tag.data[i] = input(ttype.. i ..": ", tag.data[i])
        end
      end
    end

    bytes = tagToBytes(tag)

    --- check data-consistency (calculate tag.raw)
    bytes[8] = calcHeaderRaw(tag.WRP, tag.WRC, tag.RD)

    --- Master-Token specific
    -- should be triggered if a SAM was converted to a non-SAM (user-Token to Master-Token)
    -- or a Master-Token has being edited (also SAM64 & SAM63 - which are in fact Master-Token)
    if(tag.Type ~= "SAM" or bytes[6]..bytes[7] ~= "60ea") then
      -- calc new Master-Token crc
      bytes[22] = calcMtCrc(bytes)
    else
      -- ensure tag.SSC set to 'ff' on credential-token (SAM)
      bytes[9] = 'ff'
      -- if a Master-Token was converted to a Credential-Token
      -- lets unset the Time-Area to 00 00 (will contain Stamp-Data on MT)
      bytes[21] = '00'
      bytes[22] = '00'
    end

    tag = bytesToTag(bytes, tag)
  end
end

---
-- calculates header-byte (addr 0x07)
function calcHeaderRaw(wrp, wrc, rd)
  wrp = ("%02x"):format(tonumber(wrp, 10))
  rd = tonumber(rd, 16)
  local res = ("%02x"):format(tonumber(wrp, 16)+tonumber(wrc.."0", 16)+((rd>0) and tonumber("8"..(rd-1), 16) or 0))
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
-- clear beackup-area of a virtual tag
function clearBackupArea(tag)
  for i=1, #tag.Bck do
    tag.Bck[i]='00'
  end
  return tag
end

--- Segment related --
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
-- get index, start-aadr, length and content
function getSegmentStats(bytes)
  local sStats = {}
  local sValid, sLast, sLen, sStart, x
  sStart=23
  x=0
  repeat
    local s={}
      -- valid = bit 6 of byte 1
      sValid = bbit("0x"..bytes[sStart+1],6,1)
      -- last = bit 7 of byte 1
      sLast = bbit("0x"..bytes[sStart+1],7,1)
      -- len = (byte 0)+(bit0-3 of byte 1)
    sLen = tonumber(bbit("0x"..bytes[sStart+1],0,4)..bytes[sStart],16)
    --print("index: "..("%02d"):format(x).." Len: "..sLen.." start:"..sStart.." end: "..(sStart+sLen-1))
    s['index']=x
    s['start']=sStart
    s['end']=sStart+sLen-1
    s['len']=sLen
    if ( (sStart+sLen-1)>sStart ) then
      table.insert(sStats, s)
    end
    sStart=sStart+sLen
    x=x+1
  until (sLast==1 or sValid==0 or x==126)
  if (#sStats>0 ) then return sStats
  else return false; end
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
  raw[2]=("%02x"):format(bbit("0x"..("%03x"):format(seg.len),8,4)+bbit("0x"..("%02x"):format((seg.valid*64)+(seg.last*128)),0,8))
  -- WRP
  raw[3]=("%02x"):format(bbit("0x"..("%02x"):format(seg.WRP),0,8))
  -- WRC + RD
  raw[4]=("%02x"):format(tonumber((seg.WRC*16)+(seg.RD*128),10))
  -- flag
  seg.flag=string.sub(raw[2],0,1)
  --print(raw[1].." "..raw[2].." "..raw[3].." "..raw[4])
  if(#seg.data>(seg.len-5)) then
    print("current payload: ".. #seg.data .." - desired payload: ".. seg.len-5)
    print(acyellow.."Data-Length has being reduced:"..acgreen.." auto-removing "..acyellow.. #seg.data-(seg.len-5) ..acgreen .." bytes from Payload!"..acoff);
    for i=(seg.len-5), #seg.data-1 do
      table.remove(seg.data)
    end
  elseif (#seg.data<(seg.len-5)) then
    print("current payload: ".. #seg.data .." - desired payload: ".. seg.len-5)
    print(acyellow.."Data-Length has being extended:"..acgreen.." auto-adding "..acyellow..(seg.len-5)-#seg.data ..acgreen .." bytes to Payload!"..acoff);
    for i=#seg.data, (seg.len-5-1) do
      table.insert(seg.data, '00')
    end
  end
  return seg
end

---
-- edit segment helper
function editSegment(tag, index)
  local k,v
  local edit_possible="valid len RD WRP WRC Stamp Payload"
  if (istable(tag.SEG[index])) then
    for k,v in pairs(tag.SEG[index]) do
      if(string.find(edit_possible,k)) then
        tag.SEG[index][k]=tonumber(input(accyan..k..acoff..": ", v),10)
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
function editSegmentData(data, uid)
    io.write("\n")
    if istable(data) == false then print("no Segment-Data found") end

    local lc = check4LegicCash(data, uid)

    for i=0, #data-1 do
        data[i]=input(accyan.."Data"..i..acoff..": ", data[i])
    end
    if (lc) then
        data = fixLegicCash(data, uid)
    end
    return data
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
-- get only the stamp-bytes of a segment
function getSegmentStamp(seg, bytes)
  local stamp=""
  local stamp_len=7
  --- the 'real' stamp on MIM is not really easy to tell for me since the 'data-block' covers stamp0..stampn+data0..datan
  -- there a no stamps longer than 7 bytes & they are write-protected by default , and I have not seen user-credntials
  -- with stamps smaller 3 bytes (except: Master-Token)
  -- WRP -> Read/Write Protection
  -- WRC -> Read/Write Condition
  -- RD depends on WRC - if WRC > 0 and RD=1: only reader with matching #WRC of Stamp-bytes in their Database have Read-Access to the Tag
  if (seg.WRP<7) then stamp_len=(seg.WRP) end
  for i=1, (stamp_len) do
    stamp=stamp..seg.data[i-1]
  end
  if (bytes) then
    stamp=str2bytes(stamp)
    return stamp
  else return stamp end
end

---
-- edit stamp of a segment
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

---
-- autoselect special/known segments
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
      res=check4LegicCash(tag.SEG[x].data, uid)
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
   io.write(acyellow.."no Segment found\n"..acoff)
   return -1
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
-- edit uid 3rd party cash
function edit3rdUid(mapid, uid, data)
  mapid=("%06x"):format(tonumber(mapid, 10))
  data[46]=string.sub(mapid, 1 ,2)
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
-- edit 3rd-party cash
function edit3rdPartyCash1(tag, x)
   local uid=tag.MCD..tag.MSN0..tag.MSN1..tag.MSN2
  if (confirm("\nedit Balance?")) then
    local new_cash=input("enter new Balance≤\nwithout comma and without currency-sign! (0-65535)", "100")
    tag.SEG[x].data=edit3rdCash(new_cash, uid, tag.SEG[x].data)
  end
  -- change User-ID (used for online-account-mapping)
  if (confirm("\nedit UserID-Mapping?")) then
    local new_mapid=input("enter new UserID (6-digit value)", "012345")
    tag.SEG[x].data=edit3rdUid(new_mapid, uid, tag.SEG[x].data)
  end
  if (confirm("\nedit Stamp?")) then
    local new_stamp=input("enter new Stamp", getSegmentStamp(tag.SEG[x]))
    tag.SEG[x].data=editStamp(new_stamp, uid, tag.SEG[x].data)
    new_stamp=getSegmentStamp(tag.SEG[x], 'true')
    print("stamp_bytes: "..#new_stamp)
    -- replace stamp in 'block 1' also
    io.write("editing stamp in Block 1 also ")
    for i=20, (20+#new_stamp-1) do
      tag.SEG[x].data[i]=new_stamp[i-19]
      io.write(".");
    end
    print(" done")
    -- fix known checksums
    tag.SEG[x].data=fix3rdPartyCash1(uid, tag.SEG[x].data)
  end
  return tag
end

---
-- edit Legic Cash
function editLegicCash(data, uid)
  local limit, curr, balance, rid, tcv
  -- currency of balance & limit
  curr=currency[data[8]..data[9]]
  -- maximum balance
  limit=string.format("%4.2f", tonumber(data[10]..data[11]..data[12], 16)/100)
  -- current balance
  balance=string.format("%4.2f", tonumber(data[15]..data[16]..data[17], 16)/100)
  -- reader-id who wrote last transaction
  rid=tonumber(data[18]..data[19]..data[20], 16)
  -- transaction counter value
  tcv=tonumber(data[29], 16)

  -- edit currency
  if (confirm(accyan.."change Currency?"..acoff)) then
    for k, v in pairs(currency) do io.write(k .. " = " .. v .. "\n") end
    curr=input(accyan.."enter the 4-digit Hex for the new Currency:"..acoff, data[8]..data[9])
    data[8]=string.sub(curr, 1, 2)
    data[9]=string.sub(curr, 3, 4)
  end

  -- edit limit
  if (confirm(accyan.."change Limit?"..acoff)) then
    limit=string.format("%06x", input(accyan.."enter the Decimal for the new Limit:"..acoff, limit))
    data[10]=string.sub(limit, 1, 2)
    data[11]=string.sub(limit, 3, 4)
    data[12]=string.sub(limit, 5, 6)
  end

  -- edit balance
  if (confirm(accyan.."change Balance?"..acoff)) then
    balance=string.format("%06x", input(accyan.."enter the Decimal for the new Balance:"..acoff, balance))
    print("Balance: "..balance)
    data[15]=string.sub(balance, 1, 2)
    data[16]=string.sub(balance, 3, 4)
    data[17]=string.sub(balance, 5, 6)
  end

  -- edit transaction-counter
  if (confirm(accyan.."change Transaction-Counter?"..acoff)) then
    tcv=string.format("%02x", input(accyan.."enter the 4-digit Hex for the new Currency:"..acoff, data[29]))
    data[29]=tcv
  end

  -- edit reader.id
  if (confirm(accyan.."change Last-Reader-ID?"..acoff)) then
    rid=string.format("%06x", input(accyan.."enter the Decimal for the new Balance:"..acoff, rid))
    print("Balance: "..balance)
    data[18]=string.sub(rid, 1, 2)
    data[19]=string.sub(rid, 3, 4)
    data[20]=string.sub(rid, 5, 6)
  end

  return fixLegicCash(data, uid)
end

---
-- chack for signature of a 'Legic-Cash-Segment'
function check4LegicCash(data, uid)
  if(#data==32) then
    local stamp_len=(#data-25)
    local stamp=""
    for i=0, stamp_len-1 do
      stamp=stamp..data[i].." "
    end
    if (data[7]=="01") then
      if (("%04x"):format(utils.Crc16Legic(dumpTable(data, "", 0, 12), uid)) == data[13]..data[14]) then
        if (("%04x"):format(utils.Crc16Legic(dumpTable(data, "", 15, 20), uid)) == data[21]..data[22]) then
          if (("%04x"):format(utils.Crc16Legic(dumpTable(data, "", 23, 29), uid)) == data[30]..data[31]) then
            io.write(accyan.."Legic-Cash Segment detected "..acoff)
            return true
          end
        end
      end
    end
  end
  return false
end

---
-- chack for signature of a '3rd Party Cash-Segment' - not all bytes know until yet !!
function check43rdPartyCash1(uid, data)
  if(#data==95) then
    -- too explicit checking will avoid fixing ;-)
    if (string.find(compareCrc(utils.Crc8Legic(uid..dumpTable(data, "", 19, 30)), data[31]),"valid")) then
      --if (compareCrc(utils.Crc8Legic(uid..data[32]..data[33]), data[34])=="valid") then
        --if (compareCrc(utils.Crc8Legic(uid..data[35]..data[36]), data[37])=="valid") then
         --if (compareCrc(utils.Crc8Legic(uid..dumpTable(data, "", 56, 61)), data[62])=="valid") then
            --if (compareCrc(utils.Crc8Legic(uid..dumpTable(data, "", 74, 88)), data[89])=="valid") then
              io.write(accyan.."3rd Party Cash-Segment detected "..acoff)
              return true
              --end
          --end
          --end
      --end
    end
  end
  return false
end

--- CRC related ---
---
-- build segmentCrc credentials
function segmentCrcCredentials(tag, segid)
  if (istable(tag.SEG[0])) then
    local cred = tag.MCD..tag.MSN0..tag.MSN1..tag.MSN2
    cred = cred ..tag.SEG[segid].raw[1]..tag.SEG[segid].raw[2]..tag.SEG[segid].raw[3]..tag.SEG[segid].raw[4]
    return cred
    else return print(acyellow.."Master-Token / unsegmented Tag!"..acoff) end
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
-- compare two bytes
function compareCrc(calc, guess)
  calc=("%02x"):format(calc)
  if (calc==guess) then return acgreen.."valid"..acoff
  else return acred.."error "..acoff..calc.."!="..guess end
end

---
-- compare 4 bytes
function compareCrc16(calc, guess)
  calc=("%04x"):format(calc)
  if (calc==guess) then return acgreen.."valid"..acoff
  else return acred.."error "..acoff..calc.."!="..guess end
end

---
-- repair / fix crc's of a 'Legic-Cash-Segment'
function fixLegicCash(data, uid)
  if(#data==32 and data[7]=="01") then
    local crc1, crc2, crc3
    -- set shadow-balance equal to balance
    data[23]=data[15]
    data[24]=data[16]
    data[25]=data[17]
    -- set shadow-last-reader to last-reader
    data[26]=data[18]
    data[27]=data[19]
    data[28]=data[20]
    -- calculate all crc's
    crc1=("%04x"):format(utils.Crc16Legic(dumpTable(data, "", 0, 12), uid))
    crc2=("%04x"):format(utils.Crc16Legic(dumpTable(data, "", 15, 20), uid))
    crc3=("%04x"):format(utils.Crc16Legic(dumpTable(data, "", 23, 29), uid))
    -- set crc's
    data[13]=string.sub(crc1, 1, 2)
    data[14]=string.sub(crc1, 3, 4)
    data[21]=string.sub(crc2, 1, 2)
    data[22]=string.sub(crc2, 3, 4)
    data[30]=string.sub(crc3, 1, 2)
    data[31]=string.sub(crc3, 3, 4)
    return data
  end
end

---
-- repair / fix (yet known) crc's of a '3rd Party Cash-Segment' - not all bytes know until yet !!
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
-- calculate segmentCRC for a given segment
function calcSegmentCrc(tag, segid)
  if (istable(tag.SEG[0])) then
  -- check if a 'Kaber Group Header' exists
    local data=segmentCrcCredentials(tag, segid)
    return ("%02x"):format(utils.Crc8Legic(data))
  end
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
-- check all segment-crc
function checkAllSegCrc(tag)
  if (istable(tag.SEG[0])) then
    for i=0, #tag.SEG do
      crc=calcSegmentCrc(tag, i)
      tag.SEG[i].crc=crc
    end
    else return print(acyellow.."Master-Token / unsegmented Tag"..acoff) end
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
-- validate segmentCRC for a given segment
function checkSegmentCrc(tag, segid)
    local data=segmentCrcCredentials(tag, segid)
    if (("%02x"):format(utils.Crc8Legic(data))==tag.SEG[segid].crc) then
      return true
    end
    return false
end

---
-- validate kghCRC to segment in tag-table
function checkKghCrc(tag, segid)
  if (type(tag.SEG[segid])=='table') then
    if (tag.data[3]=="11" and tag.raw=="9f" and tag.SSC=="ff") then
      local data=kghCrcCredentials(tag, segid)
      if (("%02x"):format(utils.Crc8Legic(data))==tag.SEG[segid].data[tag.SEG[segid].len-5-1]) then return true; end
      else return false; end
  else oops(acred.."'Kaba Group header' detected but no Segment-Data found"..ansocolors.reset) end
end

---
-- helptext for modify-mode
function modifyHelp()
  local t=[[

         Data I/O                    Segment Manipulation                Token-Data
     -----------------               --------------------           ---------------------
     ]]..acy..[[rt]]..acr..[[ => read Tag                  ]]..acy..[[as]]..acr..[[ => add Segment              ]]..acy..[[mt]]..acr..[[ => make Token
     ]]..acy..[[wt]]..acr..[[ => write Tag                 ]]..acy..[[es]]..acr..[[ => edit Segment Header      ]]..acy..[[et]]..acr..[[ => edit Token data
                                     ]]..acy..[[ed]]..acr..[[ => edit Segment Data        ]]..acy..[[tk]]..acr..[[ => toggle KGH-Flag
         File I/O                    ]]..acy..[[rs]]..acr..[[ => remove Segment
     -----------------               ]]..acy..[[cc]]..acr..[[ => check Segment-CRC
     ]]..acy..[[lf]]..acr..[[ => load bin File             ]]..acy..[[ck]]..acr..[[ => check KGH
     ]]..acy..[[sf]]..acr..[[ => save eml/bin File         ]]..acy..[[ds]]..acr..[[ => dump Segments
     ]]..acy..[[xf]]..acr..[[ => xor to File


         Virtual Tags                       tagMap                   (partial) known Segments
 --------------------------------    ---------------------          ---------------------------
 ]]..acy..[[ct]]..acr..[[ => copy mainTag to backupTag     ]]..acy..[[mm]]..acr..[[ => make (new) Map           ]]..acy..[[dlc]]..acr..[[ => dump Legic-Cash
 ]]..acy..[[tc]]..acr..[[ => copy backupTag to mainTag     ]]..acy..[[em]]..acr..[[ => edit Map submenu         ]]..acy..[[elc]]..acr..[[ => edit Legic-Cash
 ]]..acy..[[tt]]..acr..[[ => switch mainTag & backupTag    ]]..acy..[[lm]]..acr..[[ => load map from file       ]]..acy..[[d3p]]..acr..[[ => dump 3rd-Party-Cash
 ]]..acy..[[di]]..acr..[[ => dump mainTag                  ]]..acy..[[sm]]..acr..[[ => save map to file         ]]..acy..[[e3p]]..acr..[[ => edit 3rd-Party-Cash
 ]]..acy..[[do]]..acr..[[ => dump backupTag

                            ]]..acy..[[h]]..acr..[[ => this help                ]]..acy..[[q]]..acr..[[ => quit
  ]]
  return t
end

---
-- modify Tag (interactive)
function modifyMode()
  local i, backupTAG,  outTAG, inTAG, outfile, infile, sel, segment, bytes, outbytes, tagMap

  actions = {
    ---
    -- helptext
     ["h"] = function(x)
              print("  Version: "..acgreen..version..acr);
              print(modifyHelp())
              print("\n".."tags im Memory: "..(istable(inTAG) and ((currentTag=='inTAG') and acgreen.."*mainTAG"..acoff or "mainTAG") or "").."  "..(istable(backupTAG) and ((currentTag=='backupTAG') and acgreen.."*backupTAG"..acoff or "backupTAG") or ""))
              print("")
            end,
    ---
    -- read real Tag with PM3 into virtual 'mainTAG'
    ["rt"] = function(x)
                inTAG=readFromPM3();
                --actions.di()
              end,
    ---
    -- write content of virtual 'mainTAG' to real Tag with PM3
    ["wt"] = function(x)
                writeToTag(inTAG)
              end,
    ---
    -- copy mainTAG to backupTAG
    ["ct"] = function(x)
                print(accyan.."copy mainTAG to backupTAG"..acoff)
                  backupTAG=deepCopy(inTAG)
            end,
    ---
    -- copy backupTAG to mainTAG
    ["tc"] = function(x)
                print(accyan.."copy backupTAG to mainTAG"..acoff)
                inTAG=deepCopy(backupTAG)
            end,
    ---
    -- toggle between mainTAG and backupTAG
    ["tt"] = function(x)
                -- copy main to temp
                outTAG=deepCopy(inTAG)
                -- copy backup to main
                inTAG=deepCopy(backupTAG)
                print(accyan.."toggle to "..accyan..((currentTag=='inTAG') and "backupTAG" or "mainTAG")..acoff)
                if(currentTag=="inTAG") then currentTag='backupTAG'
                else currentTag='inTAG' end
                -- copy temp (main) to backup
                backupTAG=deepCopy(outTAG)
            end,
    ---
    -- load file into mainTAG
    ["lf"] = function(x)
              if (x and not x=="" and type(x)=='string' and file_check(x)) then
                filename = x
              else
                filename = input("enter filename: ", "legic.temp")
              end
              inTAG=readFile(filename)
              -- check for existing tagMap
              local res, path = file_check(filename..".map")
              if res then
                if(confirm(accyan.."Mapping-File for "..acoff..path..accyan.." found - load it also?"..acoff)) then
                  tagMap=loadTagMap(filename..".map")
                end
              end
            end,
    ---
    -- save values of mainTAG to a file (xored with MCC of mainTAG)
    ["sf"] = function(x)
              if istable(inTAG) then
                outfile = input("enter filename:", "hf-legic-"..inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2)
                bytes = tagToBytes(inTAG)
                --bytes=xorBytes(bytes, inTAG.MCC)
                if (bytes) then
                  writeFile(bytes, outfile)
                end
               end
              end,
    ---
    -- save values of mainTAG to a file (xored with 'specific' MCC)
    ["xf"] = function(x)
              if istable(inTAG) then
                outfile = input("enter filename:", "hf-legic-"..inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2)
                crc = input("enter new crc: ('00' for a plain dump)", inTAG.MCC)
                print("obfuscate with: "..crc)
                bytes=tagToBytes(inTAG)
                bytes[5]=crc
                if (bytes) then
                  writeFile(bytes, outfile)
                end
              end
             end,
    ---
    -- dump mainTAG (and all Segments)
    ["di"] = function(x)
                if (istable(inTAG)) then
                  local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                  if(istable(inTAG.SEG[0])) then
                    for i=0, #inTAG.SEG do
                      if(check43rdPartyCash1(uid, inTAG.SEG[i].data)) then
                        io.write(accyan.."in Segment index: "..inTAG.SEG[i].index ..acoff.. "\n")
                      elseif(check4LegicCash(inTAG.SEG[i].data, uid)) then
                        io.write(accyan.."in Segment index: "..inTAG.SEG[i].index..acoff.."\n")
                        lc=true;
                        lci=inTAG.SEG[i].index;
                      end
                    end
                  end
                  print("\n"..dumpTag(inTAG).."\n")
                  if (lc) then actions["dlc"](lci) end
                  lc=false
                end
              end,
    ---
    -- dump backupTAG (and all Segments)
    ["do"] = function(x) if (istable(backupTAG)) then print("\n"..dumpTag(backupTAG).."\n") end end,
    ---
    -- create a empty tagMap
    ["mm"] = function(x)
                -- clear existing tagMap and init
                if (istable(inTAG)) then
                  tagMap=makeTagMap()
                end
              end,
    ---
    -- edit a tagMap
    ["em"] = function(x)
                if (istable(inTAG)==false) then
                  if (confirm("no mainTAG in memory!\nread from PM3?")) then
                    actions['rt']()
                  elseif (confirm("load from File?")) then
                    actions['lf']()
                    else return
                  end
                end
                if (istable(tagMap)==false) then actions['mm']() end
                -- edit
                tagMap=editTagMap(inTAG, tagMap)
              end,
    ---
    -- save a tagMap
    ["sm"] = function(x)
                if (istable(tagMap)) then
                  if (istable(tagMap) and #tagMap.mappings>0) then
                    print(accyan.."Map contains "..acoff..#tagMap..accyan.." mappings"..acoff)
                    saveTagMap(tagMap, input(accyan.."enter filename:"..acoff, "Legic.map"))
                  else
                    print(acyellow.."no mappings in tagMap!"..acoff)
                  end
                end
              end,
    ---
    -- load a tagMap
    ["lm"] = function(x)
                tagMap = loadTagMap(input(accyan.."enter filename:"..acoff, "Legic.map"))
              end,
    ---
    -- dump single segment
    ["ds"] = function(x)
                if (type(x)=="string" and string.len(x)>0) then
                    sel = tonumber(x,10)
                else
                    sel = selectSegment(inTAG)
                end
                if (sel) then print("\n"..(dumpSegment(inTAG, sel) or acred.."no Segments available") ..acoff.."\n") end
              end,
    ---
    -- edit segment header
    ["es"] = function(x)
              if (type(x)=="string" and string.len(x)>0) then sel=tonumber(x,10)
              else sel=selectSegment(inTAG) end
              if (sel) then
                if(istable(inTAG.SEG[0])) then
                  inTAG=editSegment(inTAG, sel)
                  inTAG.SEG[sel]=regenSegmentHeader(inTAG.SEG[sel])
                else
                    print(acyellow.."no Segments in Tag"..acoff)
                end
              end
            end,
    ---
    -- add segment
    ["as"] = function(x)
              if (istable(inTAG.SEG[0])) then
                inTAG=addSegment(inTAG)
                inTAG.SEG[#inTAG.SEG-1]=regenSegmentHeader(inTAG.SEG[#inTAG.SEG-1])
                inTAG.SEG[#inTAG.SEG]=regenSegmentHeader(inTAG.SEG[#inTAG.SEG])
                else print(accyan.."Master-Token / unsegmented Tag!"..acoff)
              end
            end,
    ---
    -- remove segment
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
    ---
    -- edit data-portion of single segment
    ["ed"] = function(x)
              if (type(x) == "string" and string.len(x)>0) then sel=tonumber(x,10)
              else sel = selectSegment(inTAG) end
              if (istable(inTAG.SEG[sel])) then
                local uid = inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                inTAG.SEG[sel].data = editSegmentData(inTAG.SEG[sel].data, uid)
              end
            end,
    ---
    -- edit Tag (MCD, MSN, MCC etc.)
    ["et"] = function(x)
                if (istable(inTAG)) then
                  editTag(inTAG)
                end
            end,
    ---
    -- make (dummy) Token
    ["mt"] = function(x) inTAG=makeToken(); actions.di() end,
    ---
    -- fix segment-crc on single segment
    ["ts"] = function(x)
               if (type(x)=="string" and string.len(x)>0) then sel=tonumber(x,10)
               else sel=selectSegment(inTAG) end
                regenSegmentHeader(inTAG.SEG[sel])
              end,
    ---
    -- toggle kgh-crc-flag on a single segment
    ["tk"] = function(x)
               if (istable(inTAG) and istable(inTAG.SEG[0])) then
                if (type(x)=="string" and string.len(x)>0) then
                    sel = tonumber(x,10)
                else
                    sel = selectSegment(inTAG)
                end
                if(inTAG.SEG[sel].kgh) then
                    inTAG.SEG[sel].kgh = false
                else
                    inTAG.SEG[sel].kgh = true
                end
               end
              end,
    ---
    -- calculate LegicCrc8
    ["k"] = function(x)
              if (type(x)=="string" and string.len(x)>0) then
                print(("%02x"):format(utils.Crc8Legic(x)))
              end
             end,
    ---
    -- noop
    ["xb"] = function(x)
          end,
    ---
    -- print string for LegicCrc8-calculation about single segment
    ["xc"] = function(x)
               if (istable(inTAG) and istable(inTAG.SEG[0])) then
                 if (type(x)=="string" and string.len(x)>0) then
                    sel = tonumber(x,10)
                 else
                    sel = selectSegment(inTAG)
                 end
                 print("k "..kghCrcCredentials(inTAG, sel))
               end
              end,
    ---
    -- fix legic-cash checksums
    ["flc"] = function(x)
                if (type(x)=="string" and string.len(x)>0) then
                    x = tonumber(x,10)
                else
                    x = selectSegment(inTAG)
                end
                local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                inTAG.SEG[x].data=fixLegicCash(inTAG.SEG[x].data, uid)
              end,
    ---
    -- edit legic-cash values fixLegicCash(data, uid)
    ["elc"] = function(x)
                x=autoSelectSegment(inTAG, "legiccash")
                local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                inTAG.SEG[x].data=editLegicCash(inTAG.SEG[x].data, uid)
              end,
    ---
    -- dump legic-cash human-readable
    ["dlc"] = function(x)
                -- if segment index was user defined
                if (type(x)=="string" and string.len(x)>0) then
                  x=tonumber(x,10)
                  print(string.format("User-Selected Index %02d", x))
                else
                -- or try to find match
                    x = autoSelectSegment(inTAG, "legiccash")
                end
                -- dump it
                dumpLegicCash(inTAG, x)
              end,
    ---
    -- dump 3rd-party-cash-segment
    ["d3p"] = function(x)
                local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                -- if segment index was user defined
                if (type(x)=="string" and string.len(x)>0) then
                  x=tonumber(x,10)
                  print(string.format("User-Selected Index %02d", x))
                else
                -- or try to find match
                    x = autoSelectSegment(inTAG, "3rdparty")
                end
                if (istable(inTAG) and istable(inTAG.SEG[x]) and inTAG.SEG[x].len == 100) then
                  uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                  if (check43rdPartyCash1(uid, inTAG.SEG[x].data)) then
                    dump3rdPartyCash1(inTAG, x)
                  end
                end
              end,
    ---
    -- dump 3rd-party-cash-segment (raw blocks and checksums over 'known areas')
    ["r3p"] = function(x)
                local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                -- if segment index was user defined
                if (type(x)=="string" and string.len(x)>0) then
                  x=tonumber(x,10)
                  print(string.format("User-Selected Index %02d", x))
                else
                -- or try to find match
                    x = autoSelectSegment(inTAG, "3rdparty")
                end
                print3rdPartyCash1(inTAG, x)
              end,
    ---
    -- edit 3rd-party-cash-segment values (Balance, Mapping-UID, Stamp)
    ["e3p"] = function(x)
                local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                -- if segment index was user defined
                if (type(x)=="string" and string.len(x)>0) then
                  x=tonumber(x,10)
                  print(string.format("User-Selected Index %02d", x))

                else
                -- or try to find match
                    x = autoSelectSegment(inTAG, "3rdparty")
                end
                if (istable(inTAG) and istable(inTAG.SEG[x]) and inTAG.SEG[x].len == 100) then
                  inTAG=edit3rdPartyCash1(inTAG, x)
                    dump3rdPartyCash1(inTAG, x)
                end
              end,
    ---
    -- force fixing 3rd-party-checksums
    ["f3p"] = function(x)
               if(type(x)=="string" and string.len(x)>=2) then
                    x = tonumber(x, 10)
                else
                    x = selectSegment(inTAG)
                end
               if (istable(inTAG.SEG[x])) then
                  local uid=inTAG.MCD..inTAG.MSN0..inTAG.MSN1..inTAG.MSN2
                  inTAG.SEG[x].data=fix3rdPartyCash1(uid, inTAG.SEG[x].data)
               end
              end,
    ---
    -- get stamp from single segment
    ["gs"] = function(x)
                if(type(x)=="string" and string.len(x)>=2) then
                    x = tonumber(x, 10)
                else
                    x = selectSegment(inTAG)
                end
                local stamp=getSegmentStamp(inTAG.SEG[x])
                print("Stamp : "..stamp)
                stamp=str2bytes(stamp)
                print("length: "..#stamp)
              end,
    ---
    -- calculate crc16
    ["c6"] = function(x) local crc16=string.format("%4.04x", utils.Crc16(x))
                  print(string.sub(crc16, 0,2).." "..string.sub(crc16, 3,4))
              end,
    ---
    -- check & fix segments-crc of all segments
    ["cc"] = function(x) if (istable(inTAG)) then checkAllSegCrc(inTAG) end end,
    ---
    -- set backup-area-bytes to '00'
    ["cb"] = function(x)
                if (istable(inTAG)) then
                  print(accyan.."purge BackupArea"..acoff)
                  inTAG=clearBackupArea(inTAG)
                end
             end,
    ---
    -- check and fix all segments inTAG.SEG[x].kgh toggled 'on'
    ["ck"] = function(x) if (istable(inTAG)) then checkAllKghCrc(inTAG) end end,
    ---
    -- check and fix all segments inTAG.SEG[x].kgh toggled 'on'
    ["tac"] = function(x)
                if (colored_output) then
                  colored_output=false
                else
                  colored_output=true
                end
                load_colors(colored_output)
              end,
  }
  repeat
    -- default message / prompt
    ic=input("Legic command? ('"..acy.."h"..acr.."' for help - '"..acy.."q"..acr.."' for quit)", acy.."h"..acr)
    -- command actions decisions (first match, longer commands before shorter)
    if (type(actions[string.lower(string.sub(ic,0,3))])=='function') then
      actions[string.lower(string.sub(ic,0,3))](string.sub(ic,5))
    elseif (type(actions[string.lower(string.sub(ic,0,2))])=='function') then
      actions[string.lower(string.sub(ic,0,2))](string.sub(ic,4))
    elseif (type(actions[string.lower(string.sub(ic,0,1))])=='function') then
      actions[string.lower(string.sub(ic,0,1))](string.sub(ic,3))
    else
      actions.h('')
    end
  until (string.sub(ic,0,1)=="q")
end

---
-- main function
function main(args)
  -- set init colors/switch (can be toggled with 'tac' => 'toggle ansicolors')
  load_colors(colored_output)
  if (#args == 0 ) then modifyMode() end
  --- variables
  local inTAG, backupTAG, outTAG, outfile, interactive, crc
  local ofs=false
  local cfs=false
  local dfs=false
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
    if o == "m" then
        interactive = true
        modifyMode()
    end
    -- xor (e.g. for clone or plain file)
    if o == "c" then
        cfs = true
        crc = a
    end
    -- output file
    if o == "o" then
        outfile = a
        ofs = true
    end
  end

  -- file conversion (output to file)
    if ofs == false then return end

    -- dump infile / tag-read
    if (dfs) then
      print("-----------------------------------------")
      print(dumpTag(inTAG))
    end

    bytes=tagToBytes(inTAG)
    if (cfs) then
      -- xor will be done in function writeFile
      -- with the value of byte[5]
      bytes[5]=crc
    end

    -- write to outfile
    if (bytes) then

      if (outfile) then
        writeFile(bytes, outfile)
      end
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

---
-- script start
main(args)
