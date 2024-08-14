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
p:console("Rem passthru remark! :coffee:", true)
