#[[
+==========================================================+
| STANDALONE      | DESCRIPTION                            |
+==========================================================+
| (empty)         | No standalone mode                     |
+----------------------------------------------------------+
| LF_SKELETON     | standalone mode skeleton               |
|                 | - iceman                               |
+----------------------------------------------------------+
| LF_EM4100EMUL   | Simulate predefined em4100 tags only   |
|                 |                                        |
+----------------------------------------------------------+
| LF_EM4100RSWB   | Read/simulate/brute em4100 tags &      |
|                 | clone it to T555x tags                 |
+----------------------------------------------------------+
| LF_EM4100RSWW   | Read/simulate/validate em4100 tags &   |
|                 | clone it to T55xx tags, wipe T55xx tags|
+----------------------------------------------------------+
| LF_EM4100RWC    | Read/simulate em4100 tags & clone it   |
|                 | to T555x tags                          |
+----------------------------------------------------------+
| LF_HIDBRUTE     | HID corporate 1000 bruteforce          |
|                 | - Federico dotta & Maurizio Agazzini   |
+----------------------------------------------------------+
| LF_HIDFCBRUTE   | HID Facility Code bruteforce           |
| (RDV4 only)     |                                        |
+----------------------------------------------------------+
| LF_ICEHID       | LF HID collector to flashmem           |
| (RDV4 only)     |                                        |
+----------------------------------------------------------+
| LF_MULTIHID     | LF HID 26 Bit (H1031) multi simulator  |
|                 | - Shain Lakin                          |
+----------------------------------------------------------+
| LF_NEDAP_SIM    | LF Nedap ID simple simulator           |
|                 |                                        |
+----------------------------------------------------------+
| LF_NEXID        | LF Nexwatch collector to flashmem      |
| (RDV4 only)     |                                        |
+----------------------------------------------------------+
| LF_PROXBRUTE    | HID ProxII bruteforce                  |
|                 | - Brad Antoniewicz                     |
+----------------------------------------------------------+
| LF_PROX2BRUTE   | HID ProxII bruteforce v2               |
|                 |                                        |
+----------------------------------------------------------+
| LF_SAMYRUN      | HID26 read/clone/sim                   |
| (default)       | - Samy Kamkar                          |
+----------------------------------------------------------+
| LF_THAREXDE     | Simulate/read EM4x50 tags              |
| (RDV4 only)     | storing in flashmem                    |
+----------------------------------------------------------+
| HF_14ASNIFF     | 14a sniff to flashmem (rdv4) or ram    |
|                 |                                        |
+----------------------------------------------------------+
| HF_14BSNIFF     | 14b sniff to flashmem (rdv4) or ram    |
|                 |                                        |
+----------------------------------------------------------+
| HF_15SNIFF      | 15693 sniff to flashmem (rdv4) or ram  |
|                 |                                        |
+----------------------------------------------------------+
| HF_15SIM        | 15693 tag simulator                    |
|                 |                                        |
+----------------------------------------------------------+
| HF_AVEFUL       | Mifare ultralight read/simulation      |
|                 | - Ave Ozkal                            |
+----------------------------------------------------------+
| HF_BOG          | 14a sniff with ULC/ULEV1/NTAG auth     |
| (RDV4 only)     | storing in flashmem - Bogito           |
+----------------------------------------------------------+
| HF_CARDHOPPER   | Relay 14a protocols over long distances|
| (RDV4 only)     | (w/ IP backbone) - Sam Haskins         |
+----------------------------------------------------------+
| HF_COLIN        | Mifare ultra fast sniff/sim/clone      |
| (RDV4 only)     | - Colin Brigato                        |
+----------------------------------------------------------+
| HF_CRAFTBYTE    | UID stealer - Emulates scanned 14a UID |
|                 | - Anze Jensterle                       |
+----------------------------------------------------------+
| HF_ICECLASS     | Simulate HID iCLASS legacy ags         |
| (RDV4 only)     | storing in flashmem                    |
+----------------------------------------------------------+
| HF_LEGIC        | Read/simulate Legic Prime tags         |
|                 | storing in flashmem                    |
+----------------------------------------------------------+
| HF_LEGICSIM     | Simulate Legic Prime tags              |
| (RDV4 only)     | stored on flashmem                     |
+----------------------------------------------------------+
| HF_MATTYRUN     | Mifare sniff/clone                     |
|                 | - Matías A. Ré Medina                  |
+----------------------------------------------------------+
| HF_MFCSIM       | Simulate Mifare Classic 1k card        |
| (RDV4 only)     | storing in flashmem - Ray Lee          |
+----------------------------------------------------------+
| HF_MSDSAL       | Read and emulate MSD Visa cards        |
|                 | - Salvador Mendoza                     |
+----------------------------------------------------------+
| HF_REBLAY       | 14A Relay over BT                      |
| (RDV4 only)     |  - Salvador Mendoza                    |
+----------------------------------------------------------+
| HF_ST25_TEAROFF | Store/restore ST25TB tags with         |
|                 | tear-off for counters - SecLabz        |
+----------------------------------------------------------+
| HF_TCPRST       | IKEA Rothult read/sim/dump/emul        |
|                 | - Nick Draffen                         |
+----------------------------------------------------------+
| HF_TMUDFORD     | Read and emulate 15 tags               |
|                 | - Tim Mudford                          |
+----------------------------------------------------------+
| HF_UNISNIFF     | Sniff 14a/14b/15 (optionally to flash) |
|                 | - hazardousvoltage                     |
+----------------------------------------------------------+
| HF_YOUNG        | Mifare sniff/simulation                |
|                 | - Craig Young                          |
+----------------------------------------------------------+
| DANKARMULTI     | Load multiple standalone modes.        |
|                 | - Daniel Karling                       |
+----------------------------------------------------------+
| HF_EMVPNG       | Read and emulate EMV Visa cards        |
|                 | - Davi Mikael (Penegui)                |
+----------------------------------------------------------+
]]

# Default standalone if no standalone specified
set(DEFAULT_STANDALONE LF_SAMYRUN)
# (you can set explicitly STANDALONE= to disable standalone modes)
if (NOT DEFINED STANDALONE)
    set(STANDALONE ${DEFAULT_STANDALONE})
endif ()
set(STANDALONE_REQ_DEFS)

# List of all standalone modes, and which ones require bluetooth, smartcard or flash.
# (for now, we only support one standalone mode at a time)
set(STANDALONE_MODES
    LF_SKELETON LF_EM4100EMUL LF_EM4100RSWB LF_EM4100RSWW LF_EM4100RWC
    LF_HIDBRUTE LF_HIDFCBRUTE LF_ICEHID LF_MULTIHID LF_NEDAP_SIM LF_NEXID
    LF_PROXBRUTE LF_PROX2BRUTE LF_SAMYRUN LF_THAREXDE
    HF_14ASNIFF HF_14BSNIFF HF_15SNIFF HF_15SIM
    HF_AVEFUL HF_BOG HF_CARDHOPPER HF_COLIN HF_CRAFTBYTE HF_ICECLASS
    HF_LEGIC HF_LEGIC_RDV4 HF_LEGICSIM HF_MATTYRUN HF_MFCSIM HF_MSDSAL HF_REBLAY
    HF_ST25_TEAROFF HF_TCPRST HF_TMUDFORD HF_UNISNIFF HF_YOUNG HF_EMVPNG DANKARMULTI)
# List of modes that require bluetooth
set(STANDALONE_MODES_REQ_BT HF_CARDHOPPER HF_REBLAY)
# List of modes that require smartcard
set(STANDALONE_MODES_REQ_SMARTCARD)
# List of modes that require flash
set(STANDALONE_MODES_REQ_FLASH
    LF_HIDFCBRUTE LF_ICEHID LF_NEXID LF_THAREXDE HF_BOG HF_COLIN
    HF_ICECLASS HF_LEGIC_RDV4 HF_LEGICSIM HF_MFCSIM)

message(STATUS "STANDALONE = ${STANDALONE}")
message(STATUS "STANDALONE_MODES = ${STANDALONE_MODES}")

# Check if the specified standalone mode is valid, and set the corresponding definitions.
#  'MATCHES' is used to check if the specified standalone mode is in the list of valid modes.
if (DEFINED STANDALONE)
    if ("${STANDALONE_MODES}" MATCHES "${STANDALONE}")
        string(TOUPPER ${STANDALONE} STANDALONE_UPPER)
        set(STANDALONE_PLATFORM_DEFS ${STANDALONE_PLATFORM_DEFS} "-DWITH_STANDALONE_${STANDALONE_UPPER}")
        # Required for SmartCard, set '-DWITH_SMARTCARD'
        if ("${STANDALONE_MODES_REQ_SMARTCARD}" MATCHES "${STANDALONE}")
            set(STANDALONE_REQ_DEFS ${STANDALONE_REQ_DEFS} -DWITH_SMARTCARD)
        endif ()
        # Required for Flash, set '-DWITH_FLASH'
        if ("${STANDALONE_MODES_REQ_FLASH}" MATCHES "${STANDALONE}")
            set(STANDALONE_REQ_DEFS ${STANDALONE_REQ_DEFS} -DWITH_FLASH)
        endif ()
        # Required for Bluetooth, set '-DWITH_FPC_USART_HOST'
        # (we use USART host for bluetooth communication in standalone modes)
        if ("${STANDALONE_MODES_REQ_BT}" MATCHES "${STANDALONE}")
            set(STANDALONE_REQ_DEFS ${STANDALONE_REQ_DEFS} -DWITH_FPC_USART_HOST)
        endif ()
    else ()
        message(FATAL_ERROR "Invalid STANDALONE: ${STANDALONE}. ${KNOWN_DEFINITIONS}")
    endif ()
endif ()

# Export the definitions for standalone mode to be used in the main CMakeLists.txt
# --- Usually referenced externally:
# STANDALONE_REQ_DEFS            -> Definitions required by the selected standalone mode (e.g., -DWITH_FLASH)
# STANDALONE_PLATFORM_DEFS       -> Definitions for the selected standalone mode (e.g., -DWITH_STANDALONE_LF_SAMYRUN)
# --- It is not usually used externally:
# STANDALONE_MODES               -> List of all valid standalone modes (for error checking)
# STANDALONE_MODES_REQ_BT        -> List of standalone modes that require bluetooth (for error checking)
# STANDALONE_MODES_REQ_SMARTCARD -> List of standalone modes that require smartcard (for error checking)
# STANDALONE_MODES_REQ_FLASH     -> List of standalone modes that require flash (for error checking)
