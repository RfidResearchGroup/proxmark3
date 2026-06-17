-- EMV terminal emulator demo (offline mock fixture)
-- Usage: script run emv_terminal_demo

local mock = "client/src/emv/test/fixtures/host_arqc_cvn18/mock_apdu.json"
local out = "/tmp/emv_terminal_demo_session.json"
local patch = "/tmp/emv_terminal_demo_patch.json"

print("emv terminal demo — mock ARQC host-sim path")

local result = emv_terminal_run({
    mock_apdu = mock,
    profile = "interac",
    output = out,
    host_sim = true,
})

print(string.format("rc=%s outcome=%s session=%s",
    tostring(result.rc), result.outcome, result.session_path))

if result.session_path and result.session_path ~= "" then
    local erc = emv_terminal_export_sim(result.session_path, patch)
    print("export-sim rc=" .. tostring(erc) .. " -> " .. patch)
end
