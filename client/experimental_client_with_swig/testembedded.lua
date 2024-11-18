local pm3 = require("pm3")
p=pm3.pm3()

p:console("hw status")
p:console("hw version")
for line in p.grabbed_output:gmatch("[^\r\n]+") do
    if line:find("Unique ID") or line:find("uC:") then
        print(line)
    end
end

print("Device:", p.name)
p:console("Rem passthru remark! :coffee:", false, false)

local json = require("dkjson")
print("Fetching prefs:")
p:console("prefs show --json")
local prefs, err = json.decode(p.grabbed_output)
if not prefs then
    print("Error decoding JSON: ", err)
else
    print("Save path: ", prefs['file.default.savepath'])
    print("Dump path: ", prefs['file.default.dumppath'])
    print("Trace path:", prefs['file.default.tracepath'])
end
