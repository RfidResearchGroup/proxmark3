-- Offline JavaCard integration checks. No APDUs are sent.

assert(type(core.gp_send) == 'function', 'core.gp_send is missing')
assert(type(core.gp_auth) == 'function', 'core.gp_auth is missing')
assert(type(core.gp_session) == 'function', 'core.gp_session is missing')

local active, scp = core.gp_session()
assert(active == false and scp == 0, 'unexpected initial GP session')

local response, message = core.gp_send(false)
assert(response == nil and message == 'expected a hexadecimal APDU string')
response, message = core.gp_send('00zz')
assert(response == nil and message == 'invalid hexadecimal APDU')
response, message = core.gp_send('00')
assert(response == nil and message == 'invalid hexadecimal APDU')

local ok
ok, message = core.gp_auth(false)
assert(ok == false and message == 'expected a hexadecimal key')
ok, message = core.gp_auth('00')
assert(ok == false and message == 'key must contain 16, 24, or 32 bytes')
ok, message = core.gp_auth('404142434445464748494A4B4C4D4E4F', 4)
assert(ok == false and message == 'invalid SCP version or security level')

active, scp = core.gp_session()
assert(active == false and scp == 0, 'invalid arguments changed the GP session')
print('JavaCard Lua integration tests ( ok )')
