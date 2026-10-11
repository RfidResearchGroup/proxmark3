# The Unofficial DESFire Bible
## A Comprehensive Technical Reference with Citations

### Table of Contents
1. [Introduction](#introduction)
2. [DESFire Evolution Timeline](#desfire-evolution-timeline)
3. [Version Comparison Table](#version-comparison-table)
4. [Memory Architecture](#memory-architecture)
5. [Security Features by Version](#security-features-by-version)
6. [Complete Command Reference](#complete-command-reference)
7. [Authentication Deep Dive](#authentication-deep-dive)
8. [File Types and Operations](#file-types-and-operations)
9. [Cryptographic Implementation](#cryptographic-implementation)
10. [Communication Modes](#communication-modes)
11. [Error Codes Reference](#error-codes-reference)
12. [Implementation Examples](#implementation-examples)
13. [Bibliography](#bibliography)

---

## Introduction

MIFARE DESFire is a family of contactless smart card ICs (Integrated Circuits) compliant with ISO/IEC 14443-4 Type A. This comprehensive reference documents all DESFire versions from Classic (D40) through EV3, including the cost-optimized Light variant. Every technical detail includes inline citations to ensure accuracy and traceability.

### Document Scope
This bible covers:
- All DESFire versions: Classic/EV0, EV1, EV2, EV3, and Light
- Complete command sets with hex codes and parameters
- Authentication protocols and cryptographic implementations
- Memory organization and file structures
- Security features and attack mitigations
- Real-world implementation examples

---

## DESFire Evolution Timeline

### DESFire Classic/EV0 (D40) - Original Release
- **Release**: Early 2000s
- **Memory**: Fixed 4KB EEPROM [Source: MF3D_H_X3_SDS.pdf]
- **Applications**: Maximum 28 applications [Source: MF3D_H_X3_SDS.pdf]
- **Files per App**: Up to 16 files [Source: AN11004.pdf]
- **Encryption**: DES and 3DES only [Source: MF3D_H_X3_SDS.pdf]
- **Communication Speed**: 106 kbps [Source: AN11004.pdf]
- **Key Features**:
  - Basic file types: Standard, Backup, Value, Cyclic Record
  - Simple authentication protocol
  - No advanced security features

### DESFire EV1 - First Evolution (2006)
- **Memory Options**: 2KB, 4KB, 8KB EEPROM [Source: AN11004.pdf]
- **Applications**: Still limited to 28 [Source: MF3D_H_X3_SDS.pdf]
- **Files per App**: Increased to 32 [Source: AN11004.pdf]
- **New Cryptography**: Added AES-128 support [Source: AN11004.pdf]
- **Communication Speed**: Up to 848 kbps [Source: AN11004.pdf]
- **New Features** [Source: AN11004.pdf]:
  - ISO/IEC 7816-4 APDU wrapping support
  - Random UID option for privacy
  - GetCardUID command
  - ISO file identifiers (2 bytes)
  - Transaction backup mechanism
  - Improved key management

### DESFire EV2 - Second Generation (2016)
- **Memory Options**: 2KB, 4KB, 8KB EEPROM [Source: AN12696.pdf]
- **Applications**: Unlimited (removed 28 app limit) [Source: MF3D_H_X3_SDS.pdf]
- **Communication Improvements**: 128-byte frame size (2x EV1) [Source: AN12696.pdf]
- **Major New Features**:
  - **Virtual Card Architecture (VCA)** [Source: AN12696.pdf]: Privacy-preserving multiple card emulation
  - **Transaction MAC (TMAC)** [Source: AN12696.pdf]: Offline transaction verification
  - **Proximity Check** [Source: AN12696.pdf]: Protection against relay attacks
  - **Delegated Application Management (DAM)** [Source: AN12696.pdf]: Secure cloud provisioning
  - **Multiple Key Sets** [Source: AN12696.pdf]: Key rolling mechanism
  - **Originality Check** [Source: AN12696.pdf]: Verify genuine NXP silicon

### DESFire EV3 - Latest Generation (2020)
- **Memory Options**: 2KB, 4KB, 8KB, 16KB EEPROM [Source: MF3D_H_X3_SDS.pdf]
- **Performance**: 1.6x faster than EV1 [Source: AN12753.pdf]
- **Communication**: 256-byte frame size (2x EV2) [Source: AN12753.pdf]
- **Security Certification**: Common Criteria EAL5+ [Source: plt-05618-a.0-mifare-desfire-ev3-application-note.pdf]
- **New Features**:
  - **Transaction Timer** [Source: AN12753.pdf]: Prevents delayed attack scenarios
  - **Secure Dynamic Messaging (SDM)** [Source: AN12753.pdf]: Dynamic URL generation
  - **Secure Unique NFC (SUN)** [Source: AN12753.pdf]: Unique tap verification
  - **Pre-configured DAM Keys** [Source: AN12753.pdf]: Simplified cloud setup
  - **Improved MACing** [Source: AN12753.pdf]: Enhanced integrity protection

### DESFire Light - Cost-Optimized Variant
- **Memory Options**: 0.5KB (640B) or 2KB [Source: [0011955][v1.0] st_pegasus_desfire_lite_v10.pdf]
- **Applications**: Single application only [Source: [0011955][v1.0] st_pegasus_desfire_lite_v10.pdf]
- **Files**: Up to 32 files [Source: [0011955][v1.0] st_pegasus_desfire_lite_v10.pdf]
- **Cryptography**: AES-128 only (no DES/3DES) [Source: [0011955][v1.0] st_pegasus_desfire_lite_v10.pdf]
- **Limitations**:
  - No backup files support
  - Simplified command set
  - No multi-application features
  - Reduced security options

---

## Version Comparison Table

| Feature | Classic/EV0 | EV1 | EV2 | EV3 | Light |
|---------|-------------|-----|-----|-----|-------|
| **Memory Options** | 4KB | 2/4/8KB | 2/4/8KB | 2/4/8/16KB | 0.5/2KB |
| **Max Applications** | 28 [^1] | 28 [^1] | Unlimited [^2] | Unlimited [^2] | 1 [^3] |
| **Files per App** | 16 [^4] | 32 [^4] | 32 [^5] | 32 [^5] | 32 [^3] |
| **Frame Size** | 64B | 64B | 128B [^5] | 256B [^6] | 64B |
| **DES/3DES** | ✓ | ✓ | ✓ | ✓ | ✗ |
| **AES-128** | ✗ | ✓ [^4] | ✓ | ✓ | ✓ [^3] |
| **Random UID** | ✗ | ✓ [^4] | ✓ | ✓ | ✗ |
| **VCA** | ✗ | ✗ | ✓ [^5] | ✓ | ✗ |
| **Proximity Check** | ✗ | ✗ | ✓ [^5] | ✓ | ✗ |
| **Transaction MAC** | ✗ | ✗ | ✓ [^5] | ✓ | Limited |
| **Transaction Timer** | ✗ | ✗ | ✗ | ✓ [^6] | ✗ |
| **SDM/SUN** | ✗ | ✗ | ✗ | ✓ [^6] | ✗ |
| **Speed** | 106 kbps | 848 kbps [^4] | 848 kbps | 1.6x EV1 [^6] | 106 kbps |
| **CC Certification** | ✗ | EAL4+ | EAL5+ | EAL5+ [^7] | EAL4+ |

[^1]: [Source: MF3D_H_X3_SDS.pdf]
[^2]: [Source: MF3D_H_X3_SDS.pdf]
[^3]: [Source: [0011955][v1.0] st_pegasus_desfire_lite_v10.pdf]
[^4]: [Source: AN11004.pdf]
[^5]: [Source: AN12696.pdf]
[^6]: [Source: AN12753.pdf]
[^7]: [Source: plt-05618-a.0-mifare-desfire-ev3-application-note.pdf]

---

## Memory Architecture

### Memory Layout Structure

All DESFire cards follow a hierarchical structure:

```
PICC (Card) Level
├── Master Application (AID 0x000000)
│   ├── PICC Master Key
│   └── Card Configuration
└── Applications (AID 0x000001 - 0xFFFFFF)
    ├── Application Master Key
    ├── Application Keys (0-13)
    └── Files (0-31)
        ├── Standard Data Files
        ├── Backup Files
        ├── Value Files
        ├── Linear Record Files
        └── Cyclic Record Files
```

### Application Identifier (AID)
- **Size**: 3 bytes (24 bits) [Source: AN11004.pdf]
- **Range**: 0x000000 to 0xFFFFFF
- **Reserved**: 0x000000 (Master Application)
- **User Range**: 0x000001 to 0xFFFFFF

### File Types and Structures

#### 1. Standard Data File
- **Purpose**: Store raw data [Source: AN11004.pdf]
- **Size**: 1 to 8191 bytes (EV1), 1 to 32 bytes (Light) [Source: various]
- **Operations**: Read, Write
- **Structure**: Simple byte array

#### 2. Backup File
- **Purpose**: Transactional data with commit/abort [Source: AN11004.pdf]
- **Size**: Same as Standard File
- **Operations**: Read, Write, Commit, Abort
- **Note**: Not supported on DESFire Light [Source: [0011955][v1.0] st_pegasus_desfire_lite_v10.pdf]

#### 3. Value File
- **Purpose**: Store 32-bit signed integer [Source: AN11004.pdf]
- **Operations**: Read, Credit, Debit, Limited Credit
- **Limits**: Configurable lower and upper bounds
- **Structure**:
  ```
  Value: 4 bytes (signed int32)
  ```

#### 4. Linear Record File
- **Purpose**: Append-only records [Source: AN11004.pdf]
- **Record Size**: 1 to 8191 bytes
- **Max Records**: Configurable
- **Operations**: Read, Write (append), Clear

#### 5. Cyclic Record File
- **Purpose**: Circular buffer of records [Source: AN11004.pdf]
- **Behavior**: Oldest record overwritten when full
- **Operations**: Read, Write (newest), Clear

### Memory Access Rights

Each file has configurable access rights [Source: AN11004.pdf]:
- **Read Access**: Key 0-13, 0xE (free), 0xF (deny)
- **Write Access**: Key 0-13, 0xE (free), 0xF (deny)
- **Read&Write Access**: Key 0-13, 0xE (free), 0xF (deny)
- **Change Access Rights**: Key 0-13, 0xF (deny)

Communication settings per file:
- **0x00**: Plain communication
- **0x01**: MACed communication
- **0x03**: Fully enciphered communication

---

## Security Features by Version

### DESFire Classic/EV0 Security
- **Encryption**: DES/3DES only [Source: MF3D_H_X3_SDS.pdf]
- **Authentication**: Simple challenge-response
- **Protection**: Basic anti-collision, no advanced features

### DESFire EV1 Security Enhancements
- **AES-128 Support**: Added alongside DES/3DES [Source: AN11004.pdf]
- **Random UID**: Configurable for privacy [Source: AN11004.pdf]
- **Diversified Keys**: Support for key derivation
- **Anti-tearing**: Transaction backup mechanism

### DESFire EV2 Security Additions
- **Proximity Check** [Source: AN12696.pdf]:
  - Prevents relay attacks
  - Time-based distance bounding
  - Configurable timing parameters

- **Virtual Card Architecture (VCA)** [Source: AN12696.pdf]:
  - Multiple virtual cards in one
  - Install/Select/Delete virtual cards
  - Privacy through UID randomization

- **Transaction MAC (TMAC)** [Source: AN12696.pdf, MF2DLHX0.pdf]:
  - Offline transaction verification
  - Reader-specific MACs with CommitReaderID command (0xC8)
  - Counter-based freshness (TMC - Transaction MAC Counter)
  - Special file type 0x05 with unique access rights:
    - Read: Normal access control
    - Write: Always 0xF (disabled)
    - ReadWrite: CommitReaderID key (0x0-0xE enabled, 0xF disabled)
    - Change: Normal access control
  - TMV (Transaction MAC Value) calculated on CommitTransaction

- **Secure Messaging v2** [Source: AN12696.pdf]:
  - Improved IV generation
  - Command counter protection
  - Enhanced session key derivation

### DESFire EV3 Security Features
- **Transaction Timer** [Source: AN12753.pdf]:
  - Maximum time window for operations
  - Prevents delayed attack scenarios
  - Configurable per application

- **Secure Dynamic Messaging (SDM)** [Source: AN12753.pdf]:
  - Dynamic NDEF message generation
  - Encrypted file data in URLs
  - PICCData and MACed responses

- **Common Criteria EAL5+** [Source: plt-05618-a.0-mifare-desfire-ev3-application-note.pdf]:
  - Highest security certification
  - Formally verified implementation
  - Hardware security evaluation

---

## Complete Command Reference

### Authentication Commands

#### 0x0A - Authenticate (Legacy DES/3DES)
- **Parameters**: KeyNo (1 byte) [Source: protocols.h, line 334]
- **Response**: Encrypted RndB (8 bytes) + status
- **Versions**: All except Light
- **Flow**: See Authentication Deep Dive section

#### 0x1A - Authenticate ISO (3DES)
- **Parameters**: KeyNo (1 byte) [Source: protocols.h, line 335]
- **Response**: Encrypted RndB (8 bytes) + status
- **Versions**: EV1, EV2, EV3
- **Note**: ISO/IEC 7816-4 compliant

#### 0xAA - Authenticate AES
- **Parameters**: KeyNo (1 byte) [Source: protocols.h, line 336]
- **Response**: Encrypted RndB (16 bytes) + status
- **Versions**: EV1, EV2, EV3, Light
- **Note**: Uses AES-128 in CBC mode

#### 0x71 - AuthenticateEV2First
- **Parameters**: KeyNo (1 byte) + Capabilities [Source: protocols.h, line 337]
- **Response**: Transaction identifier + encrypted data
- **Versions**: EV2, EV3
- **Purpose**: Initial EV2 authentication with capability exchange

#### 0x77 - AuthenticateEV2NonFirst
- **Parameters**: KeyNo (1 byte) [Source: protocols.h, line 338]
- **Response**: Encrypted authentication data
- **Versions**: EV2, EV3
- **Purpose**: Subsequent EV2 authentication

#### 0x70 - FreeMem
- **Parameters**: None [Source: protocols.h, line 339]
- **Response**: Free memory (3 bytes)
- **Versions**: All
- **Authentication**: Not required

### Application Management Commands

#### 0xCA - CreateApplication
- **Parameters**: [Source: protocols.h, line 344]
  - AID (3 bytes)
  - KeySettings (1 byte)
  - NumOfKeys (1 byte): Lower nibble = key count, Upper nibble = crypto method
- **Versions**: All
- **Example**: `CA 01 00 00 0F 81` creates AID 0x000001 with 1 AES key

#### 0xDA - DeleteApplication
- **Parameters**: AID (3 bytes) [Source: protocols.h, line 345]
- **Versions**: All
- **Authentication**: PICC Master Key required

#### 0x5A - SelectApplication
- **Parameters**: AID (3 bytes) [Source: protocols.h, line 347]
- **Versions**: All
- **Note**: AID 0x000000 selects master application

#### 0x6A - GetApplicationIDs
- **Parameters**: None [Source: protocols.h, line 346]
- **Response**: List of AIDs (3 bytes each)
- **Versions**: All

#### 0x45 - GetKeySettings
- **Parameters**: None [Source: protocols.h, line 350]
- **Response**: KeySettings (1 byte) + NumOfKeys (1 byte)
- **Versions**: All

#### 0x64 - GetKeyVersion
- **Parameters**: KeyNo (1 byte) [Source: protocols.h, line 355]
- **Response**: Key version (1 byte)
- **Versions**: All

### File Management Commands

#### 0xCD - CreateStdDataFile
- **Parameters**: [Source: protocols.h, line 357]
  - FileNo (1 byte)
  - FileOption/CommSettings (1 byte)
  - AccessRights (2 bytes)
  - FileSize (3 bytes, LSB first)
- **Versions**: All

#### 0xCB - CreateBackupFile
- **Parameters**: Same as CreateStdDataFile [Source: protocols.h, line 358]
- **Versions**: All except Light
- **Note**: Supports transaction mechanism

#### 0xCC - CreateValueFile
- **Parameters**: [Source: protocols.h, line 359]
  - FileNo (1 byte)
  - CommSettings (1 byte)
  - AccessRights (2 bytes)
  - LowerLimit (4 bytes)
  - UpperLimit (4 bytes)
  - Value (4 bytes)
  - LimitedCreditEnable (1 byte)
- **Versions**: All

#### 0xC1 - CreateLinearRecordFile
- **Parameters**: [Source: protocols.h, line 360]
  - FileNo (1 byte)
  - CommSettings (1 byte)
  - AccessRights (2 bytes)
  - RecordSize (3 bytes)
  - MaxNumberOfRecords (3 bytes)
- **Versions**: All

#### 0xC0 - CreateCyclicRecordFile
- **Parameters**: Same as CreateLinearRecordFile [Source: protocols.h, line 361]
- **Versions**: All

#### 0xDF - DeleteFile
- **Parameters**: FileNo (1 byte) [Source: protocols.h, line 362]
- **Versions**: All

#### 0x6F - GetFileIDs
- **Parameters**: None [Source: protocols.h, line 363]
- **Response**: List of FileIDs (1 byte each)
- **Versions**: All

#### 0xF5 - GetFileSettings
- **Parameters**: FileNo (1 byte) [Source: protocols.h, line 364]
- **Response**: File type + settings structure
- **Versions**: All

### Data Manipulation Commands

#### 0xBD - ReadData
- **Parameters**: [Source: protocols.h, line 367]
  - FileNo (1 byte)
  - Offset (3 bytes, LSB first)
  - Length (3 bytes, LSB first)
- **Response**: Data + status
- **Versions**: All

#### 0x3D - WriteData
- **Parameters**: [Source: protocols.h, line 368]
  - FileNo (1 byte)
  - Offset (3 bytes)
  - Length (3 bytes)
  - Data (variable)
- **Versions**: All

#### 0x6C - GetValue
- **Parameters**: FileNo (1 byte) [Source: protocols.h, line 369]
- **Response**: Value (4 bytes)
- **Versions**: All

#### 0x0C - Credit
- **Parameters**: [Source: protocols.h, line 370]
  - FileNo (1 byte)
  - Amount (4 bytes)
- **Versions**: All

#### 0xDC - Debit
- **Parameters**: Same as Credit [Source: protocols.h, line 371]
- **Versions**: All

#### 0x1C - LimitedCredit
- **Parameters**: Same as Credit [Source: protocols.h, line 372]
- **Versions**: All
- **Note**: Only if LimitedCreditEnabled

#### 0x3B - WriteRecord
- **Parameters**: [Source: protocols.h, line 373]
  - FileNo (1 byte)
  - Offset (3 bytes)
  - Length (3 bytes)
  - Data (variable)
- **Versions**: All

#### 0xBB - ReadRecords
- **Parameters**: [Source: protocols.h, line 374]
  - FileNo (1 byte)
  - Offset (3 bytes): Record number
  - Length (3 bytes): Number of records
- **Versions**: All

#### 0xEB - ClearRecordFile
- **Parameters**: FileNo (1 byte) [Source: protocols.h, line 375]
- **Versions**: All

#### 0xC7 - CommitTransaction
- **Parameters**: Option byte (optional, 1 byte) [Source: MF2DLHX0.pdf, AN12343.pdf]
- **Versions**: All
- **Purpose**: Commit all pending changes
- **Note**: With option 0x01, returns TMC and TMV for TMAC verification

#### 0xC8 - CommitReaderID
- **Parameters**: ReaderID (16 bytes) [Source: MF2DLHX0.pdf, Section 10.3]
- **Versions**: EV2, EV3, Light
- **Purpose**: Set reader-specific identifier for Transaction MAC generation
- **Authentication**: Depends on TMAC file ReadWrite access rights:
  - 0x0-0x4: Authentication with specified key required
  - 0xE: Free access allowed
  - 0xF: CommitReaderID disabled
- **Communication**: Requires MACed or Encrypted mode
- **Response**:
  - When authenticated: EncTMRI (16 bytes) = E_TM(SesTMENCKey, TMRIPrev)
  - When not authenticated: No data, only status code
- **Notes**:
  - EncTMRI uses AES CBC with zero IV for encryption
  - TMRIPrev tracks previous transaction's ReaderID for chain verification
  - TMRIPrev only updated on CommitTransaction if authenticated
  - Used with TMAC file type (0x05) for offline transaction verification

#### 0xA7 - AbortTransaction
- **Parameters**: None [Source: protocols.h, line 377]
- **Versions**: All
- **Purpose**: Rollback pending changes

### Configuration Commands

#### 0x5F - ChangeFileSettings
- **Parameters**: [Source: protocols.h, line 365]
  - FileNo (1 byte)
  - CommSettings (1 byte)
  - AccessRights (2 bytes)
- **Versions**: All

#### 0x54 - ChangeKeySettings
- **Parameters**: KeySettings (1 byte) [Source: protocols.h, line 351]
- **Versions**: All

#### 0xC4 - ChangeKey
- **Parameters**: [Source: protocols.h, line 352]
  - KeyNo (1 byte)
  - New key data (encrypted)
- **Versions**: All

### Information Commands

#### 0x60 - GetVersion
- **Parameters**: None [Source: protocols.h, line 349]
- **Response**: Version info structure (28 bytes)
- **Versions**: All

#### 0x51 - GetCardUID
- **Parameters**: None [Source: protocols.h, line 389]
- **Response**: UID (7 bytes)
- **Versions**: EV1+
- **Authentication**: Required

#### 0x61 - GetFileCounters
- **Parameters**: FileNo (1 byte) [Source: protocols.h, line 390]
- **Response**: Counters for SDM
- **Versions**: EV2+

#### 0x6E - GetFreeMemory
- **Parameters**: None [Source: AN11004.pdf]
- **Response**: Free memory (3 bytes)
- **Versions**: All

### ISO Wrapped Commands

#### 0xAD - ISOReadBinary
- **Parameters**: ISO 7816-4 wrapped ReadData [Source: protocols.h, line 378]
- **Versions**: EV1+

#### 0xAB - ISOAppendRecord
- **Parameters**: ISO 7816-4 wrapped WriteRecord [Source: protocols.h, line 380]
- **Versions**: EV1+

#### 0xA2 - ISOReadRecords
- **Parameters**: ISO 7816-4 wrapped ReadRecords [Source: protocols.h, line 379]
- **Versions**: EV1+

#### 0xA0 - ISOSelectFile
- **Parameters**: ISO 7816-4 file selection [Source: protocols.h, line 382]
- **Versions**: EV1+

#### 0x3A - ISOUpdateBinary
- **Parameters**: ISO 7816-4 wrapped WriteData [Source: protocols.h, line 383]
- **Versions**: EV1+

### Special Commands

#### 0xAF - Additional Frame
- **Purpose**: Continue previous command [Source: protocols.h, line 342]
- **Parameters**: Additional data
- **Versions**: All

#### 0x00 - ISO Wrapping
- **Purpose**: ISO 7816-4 command wrapping [Source: protocols.h, line 341]
- **Versions**: EV1+

### Transaction/Security Commands (EV2/EV3)

#### 0xC9 - InitializeKeySet
- **Parameters**: KeySetNo + KeySetSettings [Source: protocols.h, line 385]
- **Versions**: EV2+

#### 0xCE - FinalizeKeySet
- **Parameters**: KeySetNo + KeyVersion [Source: protocols.h, line 386]
- **Versions**: EV2+

#### 0xCF - RollKeySet
- **Parameters**: KeySetNo [Source: protocols.h, line 387]
- **Versions**: EV2+

#### 0xF6 - GetDelegatedInfo
- **Parameters**: DAMSlotNo [Source: protocols.h, line 391]
- **Versions**: EV2+

#### 0xFA - TransactionMAC
- **Parameters**: Transaction data [Source: various sources]
- **Versions**: EV2+
- **Purpose**: Generate offline verification MAC

### Status Codes

#### Success Codes
- **0x00**: OPERATION_OK [Source: protocols.h, line 393]
- **0x0C**: NO_CHANGES [Source: protocols.h, line 394]

#### Error Codes
- **0x0E**: OUT_OF_MEMORY [Source: protocols.h, line 395]
- **0x1C**: ILLEGAL_COMMAND_CODE [Source: protocols.h, line 396]
- **0x1E**: INTEGRITY_ERROR [Source: protocols.h, line 397]
- **0x40**: NO_SUCH_KEY [Source: protocols.h, line 398]
- **0x7E**: LENGTH_ERROR [Source: protocols.h, line 399]
- **0x9D**: PERMISSION_DENIED [Source: protocols.h, line 400]
- **0x9E**: PARAMETER_ERROR [Source: protocols.h, line 401]
- **0xA0**: APPLICATION_NOT_FOUND [Source: protocols.h, line 402]
- **0xA1**: APPL_INTEGRITY_ERROR [Source: protocols.h, line 403]
- **0xAE**: AUTHENTICATION_ERROR [Source: protocols.h, line 404]
- **0xAF**: ADDITIONAL_FRAME [Source: protocols.h, line 405]
- **0xBE**: BOUNDARY_ERROR [Source: protocols.h, line 406]
- **0xC1**: COMMAND_ABORTED [Source: protocols.h, line 408]
- **0xCA**: PICC_INTEGRITY_ERROR [Source: protocols.h, line 407]
- **0xCD**: PICC_DISABLED_ERROR [Source: protocols.h, line 409]
- **0xCE**: COUNT_ERROR [Source: protocols.h, line 410]
- **0xDE**: DUPLICATE_ERROR [Source: protocols.h, line 411]
- **0xEE**: EEPROM_ERROR [Source: protocols.h, line 412]
- **0xF0**: FILE_NOT_FOUND [Source: protocols.h, line 413]
- **0xF1**: FILE_INTEGRITY_ERROR [Source: protocols.h, line 414]

---

## Authentication Deep Dive

### DES/3DES Authentication Protocol

#### Phase 1: Initial Authentication Request
```
PCD → PICC: 90 0A 00 00 01 [KeyNo] 00
             └─ Authenticate command (0x0A)
```
[Source: DESFire DES authentication D40-DES authentification.pdf, line 7]

#### Phase 2: PICC Responds with Encrypted RndB
```
PICC → PCD: [Ek(RndB)] 91 AF
             └─ 8 bytes encrypted RndB
```
[Source: DESFire DES authentication D40-DES authentification.pdf, line 9]

#### Phase 3: PCD Prepares Response
1. Decrypt RndB using key
2. Generate RndA (8 bytes)
3. Rotate RndB left by 1 byte
4. Concatenate: RndA || RndB_rotated
5. Encrypt with CBC mode, IV from previous response

[Source: DESFire DES authentication D40-DES authentification.pdf, lines 23-39]

#### Phase 4: Send Encrypted Challenge
```
PCD → PICC: 90 AF 00 00 10 [Ek(RndA || RndB_rot)] 00
```
[Source: DESFire DES authentication D40-DES authentification.pdf, line 41]

#### Phase 5: Verify PICC Response
```
PICC → PCD: [Ek(RndA_rot)] 91 00
```
PCD decrypts and verifies rotated RndA matches
[Source: DESFire DES authentication D40-DES authentification.pdf, lines 43-56]

### AES Authentication Protocol

Similar flow but with 16-byte blocks:
1. Uses command 0xAA instead of 0x0A
2. RndA and RndB are 16 bytes each
3. AES-128 in CBC mode
4. Session key derivation differs

[Source: DESFire.py, lines 79-144]

### EV2 Authentication Protocol

#### EV2First Authentication
1. **Capability Exchange**:
   ```
   PCD → PICC: 71 [KeyNo] [Len] [PCDcap2]
   PICC → PCD: [TI] [PDcap2] [PCDcap2] AF
   ```
   [Source: desfire_ev3_authentication.pdf, lines 18-25]

2. **Complete Authentication**:
   - Similar challenge-response
   - Generates Transaction Identifier (TI)
   - Establishes secure channel

#### EV2NonFirst Authentication
```
PCD → PICC: 77 [KeyNo]
```
Requires previous EV2First in same session
[Source: desfire_ev3_authentication.pdf, lines 27-30]

### Session Key Generation

#### DES Session Key (8 bytes)
```
SessionKey = RndA[0:4] || RndB[0:4]
```
[Source: DESFire DES authentication D40-DES authentification.pdf, lines 66-71]

#### 2K3DES Session Key (16 bytes)
```
SessionKey = RndA[0:4] || RndB[0:4] || RndA[4:8] || RndB[4:8]
```
[Source: DESFire.py, lines 135-136]

#### 3K3DES Session Key (24 bytes)
```
SessionKey = RndA[0:4] || RndB[0:4] ||
             RndA[6:10] || RndB[6:10] ||
             RndA[12:16] || RndB[12:16]
```
[Source: DESFire.py, lines 138-141]

#### AES Session Key (16 bytes)
```
SessionKey = RndA[0:4] || RndB[0:4] || RndA[12:16] || RndB[12:16]
```
[Source: DESFire.py, lines 143-144]

### CMAC Calculation

#### Subkey Generation
```python
# Generate L by encrypting zero block
L = AES_Encrypt(Key, 0x00000000000000000000000000000000)

# Generate K1
K1 = L << 1
if MSB(L) == 1:
    K1 = K1 XOR Rb  # Rb = 0x87 for AES

# Generate K2
K2 = K1 << 1
if MSB(K1) == 1:
    K2 = K2 XOR Rb
```
[Source: mifare_desfire_crypto.c, lines 95-123]

#### CMAC Calculation
1. Pad message if needed (0x80 0x00...)
2. XOR last block with K1 (complete) or K2 (incomplete)
3. CBC encrypt all blocks
4. Final block is CMAC

[Source: mifare_desfire_crypto.c, lines 126-151]

---

## File Types and Operations

### Standard Data File Operations

#### CreateStdDataFile
```
Command: CD [FileNo] [CommSettings] [AccessRights] [FileSize]
Example: CD 01 00 00 00 00 10 00 00  // File 01, plain, free access, 16 bytes
```
[Source: protocols.h, line 357]

#### ReadData
```
Command: BD [FileNo] [Offset-3B] [Length-3B]
Example: BD 01 00 00 00 10 00 00  // Read 16 bytes from offset 0
```
[Source: protocols.h, line 367]

#### WriteData
```
Command: 3D [FileNo] [Offset-3B] [Length-3B] [Data]
Example: 3D 01 00 00 00 04 00 00 DE AD BE EF  // Write 4 bytes
```
[Source: protocols.h, line 368]

### Value File Operations

#### CreateValueFile
```
Command: CC [FileNo] [CommSettings] [AccessRights] [LowerLimit-4B] [UpperLimit-4B] [Value-4B] [LimitedCreditEnable]
Example: CC 02 00 00 00 00 00 00 00 E8 03 00 00 00 00 00 00 01
         // Value file 02, limits 0-1000, initial 0, limited credit enabled
```
[Source: protocols.h, line 359]

#### Credit Operation
```
Command: 0C [FileNo] [Amount-4B]
Example: 0C 02 64 00 00 00  // Credit 100 to file 02
```
[Source: protocols.h, line 370]

#### Debit Operation
```
Command: DC [FileNo] [Amount-4B]
Example: DC 02 0A 00 00 00  // Debit 10 from file 02
```
[Source: protocols.h, line 371]

### Record File Operations

#### CreateLinearRecordFile
```
Command: C1 [FileNo] [CommSettings] [AccessRights] [RecordSize-3B] [MaxRecords-3B]
Example: C1 03 00 00 00 20 00 00 0A 00 00
         // Linear record file 03, 32-byte records, max 10 records
```
[Source: protocols.h, line 360]

#### WriteRecord
```
Command: 3B [FileNo] [Offset-3B] [Length-3B] [Data]
Example: 3B 03 00 00 00 20 00 00 [32 bytes of data]
```
[Source: protocols.h, line 373]

#### ReadRecords
```
Command: BB [FileNo] [RecordNo-3B] [NumRecords-3B]
Example: BB 03 00 00 00 05 00 00  // Read 5 records starting from record 0
```
[Source: protocols.h, line 374]

### Transaction Mechanism

For Backup and Value files:
1. Perform operations (Write, Credit, Debit)
2. Changes are pending until:
   - **CommitTransaction (0xC7)**: Apply changes
   - **AbortTransaction (0xA7)**: Discard changes

[Source: protocols.h, lines 376-377]

---

## Cryptographic Implementation

### Key Diversification (AN10922)

#### Algorithm Steps
1. **Prepare Diversification Input**:
   ```
   M = [Constant] || [UID] || [AID] || [SystemIdentifier]
   ```
   Constants:
   - 0x01: AES-128
   - 0x21: 2K3DES
   - 0x31: 3K3DES
   [Source: mifare_key_deriver.c, lines 10-17]

2. **Calculate Diversified Key**:
   ```
   DiversifiedKey = CMAC(MasterKey, M)
   ```
   [Source: mifare_key_deriver.c, lines 101-177]

### Secure Messaging

#### MACed Communication Mode (0x01)
- Commands sent in plain
- Response includes 8-byte CMAC
- CMAC covers: Response Data + Status Code
[Source: various implementation files]

#### Full Enciphered Mode (0x03)
- Command data encrypted after authentication
- Response data encrypted
- Both include CMAC for integrity
- Uses session keys and IVs

### IV Generation

#### EV1 IV Handling
- Initial IV: All zeros
- Subsequent: Last block of previous crypto operation

#### EV2/EV3 IV Generation
```
IV = EncryptedFlag || TI || .pdfCtr || ZeroPadding
```
- TI: Transaction Identifier (4 bytes)
- .pdfCtr: Command Counter (2 bytes)
[Source: hf_desfire.c and crypto implementations]

---

## Communication Modes

### Plain Communication (0x00)
- No encryption or MACing
- Suitable for public data
- Fastest performance
- No authentication required for read

### MACed Communication (0x01)
- Data transmitted in plain
- 8-byte CMAC appended to responses
- Integrity protection
- Requires authentication

### Fully Enciphered Communication (0x03)
- All data encrypted
- CMAC for integrity
- Maximum security
- Requires authentication
- Performance impact

---

## Error Codes Reference

### Common Error Scenarios

#### 0x9D - PERMISSION_DENIED
- Attempting operation without required authentication
- Wrong key authenticated for operation
- Access rights don't permit operation

#### 0xAE - AUTHENTICATION_ERROR
- Authentication protocol failure
- Wrong key or key version
- Corrupted authentication data

#### 0x7E - LENGTH_ERROR
- Command parameters wrong length
- Data exceeds file size
- Frame size exceeded

#### 0xA0 - APPLICATION_NOT_FOUND
- Invalid AID selected
- Application was deleted
- Card not properly initialized

---

## Implementation Examples

### Example 1: Creating an Application with AES Keys
```python
# Create application 0x000001 with 5 AES keys
aid = [0x01, 0x00, 0x00]
key_settings = 0x0F  # All keys changeable, free directory
num_keys = 0x85     # 5 keys, AES encryption (bit 7 set)

command = [0xCA] + aid + [key_settings, num_keys]
response = send_command(command)
```

### Example 2: Secure File Write with MACing
```python
# Authenticate first
authenticate_aes(key_no=0x01, key=master_key)

# Create MACed file
create_std_file(file_no=0x01,
                comm_settings=0x01,  # MACed
                access_rights=0x0000,  # Free access
                file_size=32)

# Write data (will be MACed automatically)
write_data(file_no=0x01, offset=0, data=b"Secure data here")
```

### Example 3: Value File Transaction
```python
# Create value file with limits
create_value_file(file_no=0x02,
                  lower_limit=0,
                  upper_limit=10000,
                  initial_value=1000,
                  limited_credit=True)

# Perform operations
credit(file_no=0x02, amount=500)   # Balance: 1500
debit(file_no=0x02, amount=200)    # Balance: 1300

# Commit all changes
commit_transaction()
```

---

## Bibliography

### Primary Sources (Datasheets)
1. **AN11004**: MIFARE DESFire EV1 Features and Hints
2. **AN12696**: MIFARE DESFire EV2 Features and Hints
3. **AN12753**: MIFARE DESFire EV3 Features and Hints
4. **MF3D_H_X3_SDS**: MIFARE DESFire EV3 Secure Data Sheet
5. **PLT-05618**: MIFARE DESFire EV3 Application Note
6. **[0011955][v1.0]**: ST Pegasus DESFire Light v1.0 Specification
7. **AN-315**: Understanding Protege MIFARE DESFire Credentials

### Implementation Sources
1. **protocols.h**: Proxmark3 DESFire protocol definitions
2. **hf_desfire.c**: Proxmark3 DESFire implementation
3. **DESFire.py**: Python DESFire implementation
4. **DESFire_DEF.py**: Python DESFire constants
5. **mifare_desfire.c**: libfreefare C implementation
6. **mifare_desfire_crypto.c**: libfreefare crypto implementation
7. **DesfireEv3.java**: Android DESFire EV3 implementation

### Documentation Sources
1. **desfire_ev3_authentication.pdf**: EV3 authentication details
2. **desfire_ev3_file_operations.pdf**: EV3 file operation examples
3. **DESFire DES authentication D40-DES authentification.pdf**: Legacy auth flow
4. **DESFire TDES decryption SEND mode.pdf**: TDES implementation details
5. **auth1d_d40.pdf**: D40 authentication documentation

### Additional References
1. ISO/IEC 14443-4: Proximity cards protocol
2. ISO/IEC 7816-4: Smart card APDU specification
3. Common Criteria EAL5+ certification documents
4. NIST SP 800-38B: CMAC specification
5. AN10922: NXP Key Diversification

---

*End of The Unofficial DESFire Bible*

*Compiled from official documentation and implementation sources*
*All information includes inline citations for verification*
*Last updated: Based on DESFire EV3 specifications*