# FMCOS CPU Smart Card Commands
<a id="Top"></a>

FMCOS (Fudan Microelectronics CPU OS) is an ISO14443-A CPU card operating system used in
Chinese transit and e-wallet cards (PBOC compliant). Common hardware: FM1208-09, FM1216.

All commands in this family are reachable via `hf fmcos <subcommand>`.

---

# Table of Contents

- [Card Information](#card-information)
  - [info](#info)
  - [select](#select)
- [File Management](#file-management)
  - [erase](#erase)
  - [createdir](#createdir)
  - [createfile](#createfile)
  - [createkeyfile](#createkeyfile)
- [Data Access](#data-access)
  - [readbinary](#readbinary)
  - [readrecord](#readrecord)
  - [writebinary](#writebinary)
  - [writerecord](#writerecord)
  - [append](#append)
  - [key (write key)](#key-write-key)
- [Authentication](#authentication)
  - [authexternal](#authexternal)
  - [authinternal](#authinternal)
- [PIN Management](#pin-management)
  - [pinverify](#pinverify)
  - [pinchange](#pinchange)
  - [pinreset](#pinreset)
  - [pinunblock](#pinunblock)
- [Financial Operations](#financial-operations)
  - [balance](#balance)
  - [credit](#credit)
  - [purchase](#purchase)
  - [overdraft](#overdraft)
  - [history](#history)
- [Card Lifecycle](#card-lifecycle)
  - [block](#block)
  - [unblock](#unblock)
- [File Access Reference](#file-access-reference)
- [Key Types Reference](#key-types-reference)
- [File Protection Modes](#file-protection-modes)
- [Access Rights Byte](#access-rights-byte)
- [Complete Wallet Session Walkthrough](#complete-wallet-session-walkthrough)
- [TID Tag Provisioning](#tid-tag-provisioning)
  - [tidsetcard](#tidsetcard)
  - [tidsetuid](#tidsetuid)
  - [tidsetauth](#tidsetauth)
  - [tiderase](#tiderase)
  - [tidprovision](#tidprovision)
  - [tidcreatedf](#tidcreatedf)
  - [tidcreatebin](#tidcreatebin)
  - [tidcreaterec](#tidcreaterec)
- [TID Vendor Card Templates](#tid-vendor-card-templates)

---

## Card Information

### info

Detect a FMCOS card and dump its file-system layout: MF, DFs, and EFs with their file
identifiers, types, sizes, and access attributes.

```
hf fmcos info
```

### select

SELECT a file or application directory by 2-byte file ID (hex) or by DF name (ASCII string).
After selection subsequent commands operate within that context.

```
hf fmcos select --id 3f00
hf fmcos select --id 3f01
hf fmcos select --name 77616C6C657454657374
```

| Flag | Description |
|------|-------------|
| `--id <hex>` | 2-byte file ID (e.g. `3f00` for MF, `3f01` for an ADF) |
| `--name <hex>` | DF name bytes as hex (up to 16 bytes, e.g. `77616C6C657454657374` = `walletTest`) |
| `-k` / `--keep` | Keep the RF field on after the command |

---

## File Management

### erase

ERASE DF -- delete all EFs and sub-DFs from the currently selected DF, but keep the DF
itself and its keyfile.  Requires the MF or relevant DF to be selected first.

```
hf fmcos select --id 3f00
hf fmcos erase
```

### createdir

CREATE DF (directory / application directory).

```
hf fmcos createdir --id 3f01 --space 1500 --cperm f0 --eperm f0 --appid 95 --name 77616C6C657454657374
```

| Flag | Description |
|------|-------------|
| `--id <hex>` | 2-byte file ID for the new DF |
| `--space <hex>` | Total byte space to reserve (hex, e.g. `1500` = 5376 bytes) |
| `--cperm <hex>` | Create-permission byte - who may create files inside this DF |
| `--eperm <hex>` | Erase-permission byte - who may erase this DF |
| `--appid <hex>` | 1-byte application file ID (DF type + short identifier) |
| `--name <hex>` | Optional DF name bytes as hex (up to 16 bytes, enables select-by-name) |

**`--cperm` (create permission):**

Controls the minimum security state required to create new EFs or sub-DFs inside this DF.
Uses the same XY nibble encoding as `--rperm` / `--wperm` in `createfile` (see the permission byte table there).

After `erase` clears the DF, the create-permission check is suspended and any file may be created freely.
The restriction is reinstated the next time the DF is re-entered once a KEY file has been established inside it.

**`--eperm` (erase permission):**

Controls the minimum security state required to run `erase` on this DF.
Uses the same XY nibble encoding.
Erasing a DF destroys all EFs and sub-DFs inside it; the DF record, its permissions, and its allocated space
are preserved.
Set to `ef` to prohibit erasing entirely: since E (14) < F (15), the range E..F is impossible and the condition
can never be satisfied.

**`--appid` (application file ID):**

A 1-byte value stored in the DF control block that encodes both the DF type and a short numeric identifier.

| Bits 7-5 | Meaning |
|----------|---------|
| `000` | Dedicated Directory File (DDF) - a plain directory, no application context |
| `100` | Application Dedicated File (ADF) - holds a PBOC / EMV application |

Bits 4-0 are the short file identifier (0-31) used by the card to link this DF to its keyfile.
This value must equal the `--dfsid` argument when creating the keyfile for this DF with `createkeyfile`.

Example: `--appid 95` = binary `10010101` - bits 7-5 are `100` (ADF), bits 4-0 are `10101` = 21 = `0x15`,
so the FCI returned on SELECT FILE references short identifier `0x15` and the matching keyfile uses `--dfsid 95`.
Standard PBOC wallet DFs conventionally use `0x95`.

### createfile

CREATE EF (elementary file) in the currently selected DF.

```
# Unprotected binary file
hf fmcos createfile --id 0002 --type bin --size 50 --rperm f0 --wperm f0 --access ff

# Variable-length record file with MAC-only line protection
hf fmcos createfile --id 0006 --type var --size 50 --rperm f0 --wperm f0 --access 7f --prot mac

# Loop (cyclic) file with MAC+encryption
hf fmcos createfile --id 000a --type loop --size 210 --rperm f0 --wperm f0 --access 7f --prot enc

# Wallet/passbook balance file (EDEP) linked to loop file 0x0018
hf fmcos createfile --id 0002 --type wallet --size 0208 --rperm f0 --wperm 00 --access 18
```

| Flag | Description |
|------|-------------|
| `--id <hex>` | 2-byte file ID |
| `--type <type>` | `bin` (0x28), `fix` (0x2A), `var` (0x2C), `loop` (0x2E), `wallet` (0x2F) |
| `--size <hex>` | File size in bytes (hex, e.g. `0208` = 520) |
| `--rperm <hex>` | Read permission byte; for wallet type this is the usage-rights byte controlling financial operations |
| `--wperm <hex>` | Write permission byte; for wallet type always sent as `0x00` (balance is managed by financial APDUs only) |
| `--access <hex>` | Line-protection control byte for normal EFs; for wallet type this is the low byte of the linked loop EF's file ID |
| `--prot <mode>` | Line-protection mode: `none` (default), `mac` (append MAC), `enc` (encrypt + MAC) |

**Permission byte encoding (`--rperm` and `--wperm`):**

FMCOS maintains a 4-bit security state register (0-F) per directory, reset to 0 on power-up or DF selection, and advanced by a
successful PIN verify or external authenticate. Each permission byte is a single hex byte `XY`:

| High nibble X | Low nibble Y | Condition for the operation to be allowed |
|:---:|:---:|---|
| `0` | `Y` | MF security state >= Y (uses **MF** register, not current DF) |
| `X` (1-F) | `Y` | Current DF security state >= Y **and** <= X |
| `X` | `Y` where X = Y | Current DF security state must equal X exactly |
| `X` | `Y` where X < Y | **Never** allowed (impossible condition) |

Common values:

| Value | Meaning |
|-------|---------|
| `f0` | Open - always allowed (any state 0-F satisfies the range) |
| `f1` | Requires DF state >= 1 (at least one successful PIN/ext-auth in this DF) |
| `ff` | Requires DF state = F (15) - highest external-authenticate level only |
| `53` | Requires DF state in [3, 5] |
| `ef` | **Never** allowed (E < F - impossible) |

**`--access` byte:**

The meaning differs by file type.

*Normal EFs (bin, fix, var, loop)* - BYTE7 is a line-protection control byte:

| Bit 7 | Bits 6-4 | Bits 3-2 | Bits 1-0 |
|:---:|:---:|:---:|:---:|
| Read enforcement | Reserved (always `111`) | Read key ID | Write key ID |

- **Bit 7 = 1**: plain (unprotected) reads are accepted - use with `--prot none`
- **Bit 7 = 0**: reads *must* carry line protection - use with `--prot mac` or `--prot enc`
- **Bits 3-2** select which line-protection key in the keyfile is used for read operations
- **Bits 1-0** select which key is used for write operations

Key ID encoding (same for both read and write selectors):

| Bits | Key ID |
|:---:|:---:|
| `11` | 00 |
| `10` | 01 |
| `01` | 02 |
| `00` | 03 |

Common `--access` values for normal EFs:

| `--access` | Binary | Bit 7 | Read key | Write key | Typical use |
|:---:|:---:|:---:|:---:|:---:|---|
| `ff` | `1111 1111` | 1 | ID 00 | ID 00 | Unprotected file (`--prot none`) |
| `7f` | `0111 1111` | 0 | ID 00 | ID 00 | Line-protected file (`--prot mac` or `--prot enc`) |
| `7e` | `0111 1110` | 0 | ID 00 | ID 01 | Protected, separate keys for read and write |

*Wallet EF (type `wallet`)* - `--access` is the low byte of the linked loop EF's file ID (the transaction-log file).
For example, `--access 18` links the wallet to loop file `0x0018`.

**`--prot` (line-protection mode):**

A protection mask is ORed into the file type byte (BYTE1 of the CREATE FILE data) at file creation time.
Thereafter, every read or write to that file must follow the declared protection level.

| Mode | Mask | File type byte effect | Behavior |
|------|:---:|:---:|---|
| `none` | `0x00` | unchanged (e.g. `0x28` for bin) | Plain reads and writes; no cryptographic overhead |
| `mac` | `0x80` | bit 7 set (e.g. `0x28` -> `0xA8`) | Each WRITE must append a 4-byte MAC; READ response includes a 4-byte MAC |
| `enc` | `0xC0` | bits 7-6 set (e.g. `0x28` -> `0xE8`) | WRITE data is DES/3DES-encrypted **and** followed by a 4-byte MAC; READ response is encrypted with a MAC |

The MAC is computed over the full APDU (CLA, INS, P1, P2, Lc, data payload) using a random 4-byte nonce
from GET CHALLENGE as the CBC IV, with the keyfile's line-protection key (type `36`).  The CLA byte must
have its low nibble set to `4` (`0x04` plain, `0x84` for ISO-secure) when line protection is active.

> **Not applicable** to wallet (`0x2F`) - financial file access is controlled entirely by the PBOC transaction APDUs, not line protection.

**File type encodings:**

| Name | Code | Description |
|------|------|-------------|
| `bin` | 0x28 | Binary transparent file |
| `fix` | 0x2A | Fixed-length record file |
| `var` | 0x2C | Variable-length record file |
| `loop` | 0x2E | Cyclic (loop) file -- used for transaction logs |
| `wallet` | 0x2F | E-purse wallet / passbook balance file |

### createkeyfile

CREATE KEYFILE in the currently selected DF.  A DF must have a keyfile before any keys
can be written to it.

```
hf fmcos createkeyfile --id 0000 --space 200 --dfsid 95 --perm f0
```

| Flag | Description |
|------|-------------|
| `--id <hex>` | 2-byte file ID for the keyfile (commonly `0000`) |
| `--space <hex>` | Space to reserve for key storage (bytes, hex, e.g. `200` = 512) |
| `--dfsid <hex>` | Parent DF SID (must match the DF's `--appid` value) |
| `--perm <hex>` | Key addition permission byte - security condition required to add a new key to this keyfile via WRITE KEY |

**Permission byte encoding (`--perm`):**

The permission byte is a single hex byte `XY` that defines the required security state before a WRITE KEY (add) operation
is permitted.  FMCOS maintains a 4-bit security state register (0-F) per directory; the register is set to 0 on reset or
when selecting a DF, and advances when a PIN verify or external-authenticate succeeds.

| High nibble X | Low nibble Y | Condition for WRITE KEY (add) to be allowed |
|:---:|:---:|---|
| `0` | `Y` | MF security state >= Y (uses **MF** register, not the current DF) |
| `X` (1-F) | `Y` | Current DF security state >= Y **and** <= X |
| `X` | `Y` where X = Y | Current DF security state must equal X exactly |
| `X` | `Y` where X < Y | **Never** allowed (impossible condition - effectively locks the key file) |

Common values:

| `--perm` | Meaning |
|----------|---------|
| `f0` | Open - no authentication required; any state (0-F) satisfies >= 0 and <= F |
| `f1` | Requires DF state >= 1 (at least one successful PIN/ext-auth in this DF) |
| `ff` | Requires DF state = F (15) - typically the highest external-authenticate level |
| `11` | Requires DF state = 1 exactly |
| `53` | Requires DF state in [3, 5] |
| `ef` | **Never** allowed (E < F -> impossible) - effectively write-locks the keyfile |

> **Note:** The `--perm` byte only governs *adding* new keys to the keyfile.  Each individual key record also carries
> its own separate use-permission and change-permission bytes that are set when writing the key with `hf fmcos write key`.

---

## Data Access

### readbinary

READ BINARY from the currently selected transparent (bin) EF.

```
# Plain read
hf fmcos readbinary --p1 00 --p2 00 --len 10

# With MAC line-protection (verifies response MAC)
hf fmcos readbinary --p1 00 --p2 00 --len 10 --prot mac --key 36363636363636363636363636363636

# With MAC+encryption (decrypts response)
hf fmcos readbinary --p1 00 --p2 00 --len 10 --prot enc --key 36363636363636363636363636363636
```

| Flag | Description |
|------|-------------|
| `--p1 <hex>` | P1 byte (high byte of file offset) |
| `--p2 <hex>` | P2 byte (low byte of file offset) |
| `--len <hex>` | Number of bytes to read (Le) |
| `--prot <mode>` | `none`, `mac`, or `enc` |
| `--key <hex>` | Line-protection key (8 or 16 bytes, required when `--prot` is mac/enc) |

### readrecord

READ RECORD from the currently selected record or cyclic EF.

```
# Read record 1 from var file 0x06 (plain)
hf fmcos readrecord --rec 01 --fid 06 --len 10

# Read with MAC verification
hf fmcos readrecord --rec 01 --fid 07 --len 10 --prot mac --key 36363636363636363636363636363636

# Read with decryption
hf fmcos readrecord --rec 01 --fid 08 --len 10 --prot enc --key 36363636363636363636363636363636
```

| Flag | Description |
|------|-------------|
| `--rec <hex>` | Record number (P1); `00` = current record |
| `--fid <hex>` | File ID in P2 (upper 5 bits); `00` = current file |
| `--len <hex>` | Number of bytes to read |
| `--prot <mode>` | `none`, `mac`, or `enc` |
| `--key <hex>` | Line-protection key when prot is mac/enc |

### writebinary

UPDATE BINARY -- write data to the currently selected transparent EF.

```
# Plain write
hf fmcos writebinary --p1 00 --p2 00 --data 11121314151617181910

# Write with MAC
hf fmcos writebinary --p1 00 --p2 00 --data 21222324252627282920 \
  --prot mac --key 36363636363636363636363636363636

# Write with MAC+encryption (data is encrypted before sending)
hf fmcos writebinary --p1 00 --p2 00 --data 31323334353637383930 \
  --prot enc --key 36363636363636363636363636363636
```

| Flag | Description |
|------|-------------|
| `--p1 <hex>` | P1 byte (high offset byte) |
| `--p2 <hex>` | P2 byte (low offset byte) |
| `--data <hex>` | Data bytes to write |
| `--prot <mode>` | `none`, `mac`, or `enc` |
| `--key <hex>` | Line-protection key |

### writerecord

UPDATE RECORD -- write a record into the currently selected EF.

```
# Plain record write (P1=record number, P2=file-id<<3|04)
hf fmcos writerecord --rec 01 --fid 06 --data 5152535455565758595a

# With MAC
hf fmcos writerecord --rec 01 --fid 07 --data 6162636465666768696a \
  --prot mac --key 36363636363636363636363636363636

# With MAC+encryption
hf fmcos writerecord --rec 01 --fid 08 --data 7172737475767778797a \
  --prot enc --key 36363636363636363636363636363636
```

| Flag | Description |
|------|-------------|
| `--rec <hex>` | Record number (P1) |
| `--fid <hex>` | File ID for P2 encoding |
| `--data <hex>` | Record data bytes |
| `--prot <mode>` | `none`, `mac`, or `enc` |
| `--key <hex>` | Line-protection key |

### append

APPEND RECORD -- append a new record to a cyclic (loop) EF.

```
# Plain append
hf fmcos append --fid 0a --data 9192939495969798999a

# With MAC
hf fmcos append --fid 0b --data a1a2a3a4a5a6a7a8a9a0 \
  --prot mac --key 36363636363636363636363636363636

# With MAC+encryption
hf fmcos append --fid 0c --data b1b2b3b4b5b6b7b8b9b0 \
  --prot enc --key 36363636363636363636363636363636
```

| Flag | Description |
|------|-------------|
| `--fid <hex>` | File ID of the loop EF |
| `--data <hex>` | Record data bytes |
| `--prot <mode>` | `none`, `mac`, or `enc` |
| `--key <hex>` | Line-protection key |

### key (write key)

WRITE KEY -- write a key entry into the currently selected keyfile.  Use `--op 01` to add
a new key, `--op 02` to update an existing one.

**Group A keys** (DES/3DES data keys with version + algorithm fields):

```
# Add InternalKey (0x34) at slot 0, always-free usage
hf fmcos key --op 01 --id 00 --type internal \
  --usage f0 --change 02 --version 00 --algo 01 \
  --key 2b8a438742c851566f02d881b09d58c0

# Add CreditKey (0x3F) at slot 1
hf fmcos key --op 01 --id 01 --type credit \
  --usage f0 --change 02 --version 00 --algo 01 \
  --key a9e6e145f5df09500a58eef8575d49db

# Add PurchaseKey (0x3E) at slot 1
hf fmcos key --op 01 --id 01 --type purchase \
  --usage f0 --change 02 --version 00 --algo 01 \
  --key eb18ce6986c820970e876219052ce0cf
```

**Group B keys** (PIN and external-auth keys with error counter):

```
# Add PIN key (0x3A) at slot 0 -- pin value is 2-6 raw bytes
hf fmcos key --op 01 --id 00 --type pin \
  --usage f0 --followup 01 --errcount 33 \
  --key 123456

# Add ExternalAuth key (0x39) at slot 0
hf fmcos key --op 01 --id 00 --type extauth \
  --usage f0 --change 02 --followup 44 --errcount 33 \
  --key f49dc1ba1b4deb5264718bc559106c0d
```

**Group C keys** (line-protection, unlock-PIN, change-PIN):

```
# Add line-protection key (0x36) at slot 0
hf fmcos key --op 01 --id 00 --type lineprotect \
  --usage f0 --change 02 --errcount ff \
  --key 8a021972bfec9d152ca9eb82d7d12c09

# Add unlock-PIN key (0x37)
hf fmcos key --op 01 --id 00 --type unlockpin \
  --usage f0 --change 02 --errcount 33 \
  --key d8f60fa2d791f3a658d27c0545824300

# Add change-PIN key (0x38)
hf fmcos key --op 01 --id 00 --type changepin \
  --usage f0 --change 02 --errcount 33 \
  --key fb487a6d1b7cbf1bf84c666b8338376e
```

**Key types:**

| Name | Code | Group | Description |
|------|------|-------|-------------|
| `desenc` | 0x30 | A | DES encrypt key |
| `desdec` | 0x31 | A | DES decrypt key |
| `desmac` | 0x32 | A | DES MAC key |
| `internal` | 0x34 | A | Internal-auth / TAC key |
| `overdraft` | 0x3C | A | Overdraft-limit key |
| `debit` | 0x3D | A | Debit (online transfer) key |
| `purchase` | 0x3E | A | Purchase / debit key |
| `credit` | 0x3F | A | Credit key |
| `extauth` | 0x39 | B | External-authentication key |
| `pin` | 0x3A | B | PIN code key |
| `lineprotect` | 0x36 | C | Line-protection key |
| `unlockpin` | 0x37 | C | Unlock-PIN key |
| `changepin` | 0x38 | C | Change-PIN key |

---

## Authentication

### authexternal

EXTERNAL AUTHENTICATE -- authenticate the reader to the card.  The card issues a challenge,
the reader encrypts it with the external-auth key, and sends the response back.

```
hf fmcos authexternal --id 00 --key f49dc1ba1b4deb5264718bc559106c0d
```

| Flag | Description |
|------|-------------|
| `--id <hex>` | Key slot ID |
| `--key <hex>` | External-auth key (8 or 16 bytes) |

### authinternal

INTERNAL AUTHENTICATE -- authenticate the card to the reader.  The reader sends an 8-byte
challenge (`--data`); the card responds with a DES-encrypted value that the reader verifies
offline.

```
hf fmcos authinternal --p1 00 --p2 00 --data 0102030405060708
```

| Flag | Description |
|------|-------------|
| `--p1 <hex>` | P1 byte (typically `00`) |
| `--p2 <hex>` | P2 byte (typically `00`) |
| `--data <hex>` | 8-byte challenge sent to the card |

---

## PIN Management

### pinverify

VERIFY PIN -- present the PIN code to the card to unlock PIN-gated operations.
PIN is 2-6 raw bytes.

```
hf fmcos pinverify --id 00 --pin 123456
```

| Flag | Description |
|------|-------------|
| `--id <hex>` | PIN key slot ID |
| `--pin <hex>` | PIN bytes (2-6 bytes) |

### pinchange

CHANGE PIN -- change the PIN using the current (old) PIN for authorization.

```
hf fmcos pinchange --id 00 --old 123456 --new 13371337
```

| Flag | Description |
|------|-------------|
| `--id <hex>` | PIN key slot ID |
| `--old <hex>` | Current PIN (2-6 bytes) |
| `--new <hex>` | New PIN (2-6 bytes) |

### pinreset

RESET PIN -- set a new PIN using the change-PIN key MAC for authorization (no old PIN needed).
The command computes a MAC over the new PIN using the change-PIN key and sends it to the card.

```
hf fmcos pinreset --id 00 --pin 13371337 \
  --key fb487a6d1b7cbf1bf84c666b8338376e
```

| Flag | Description |
|------|-------------|
| `--id <hex>` | PIN key slot ID |
| `--pin <hex>` | New PIN (2-6 bytes) |
| `--key <hex>` | Change-PIN key (16 bytes); MAC = DES-MAC(new_pin, XOR_halves(key)) |

### pinunblock

UNBLOCK PIN -- clear the PIN blocked state and set a new PIN.
The new PIN is encrypted with the unlock-PIN key and a GET CHALLENGE IV.

```
hf fmcos pinunblock --id 00 --pin 123456 \
  --key d8f60fa2d791f3a658d27c054582430e
```

| Flag | Description |
|------|-------------|
| `--id <hex>` | PIN key slot ID |
| `--pin <hex>` | New PIN (2-6 bytes) |
| `--key <hex>` | Unlock-PIN key (16 bytes) |

---

## Financial Operations

FMCOS implements a two-phase PBOC e-wallet protocol.  Phase 1 initializes the transaction
and returns card-computed data (old balance, serial number, random seed, MAC1).  Phase 2
commits the transaction with a terminal-computed MAC2 and receives a Transaction
Authentication Code (TAC) from the card which the terminal verifies.

**Keys involved:**

| Key | Role |
|-----|------|
| Credit key (16 B) | Derive the session process key for credit operations |
| Purchase key (16 B) | Derive the session process key for purchase/debit |
| Overdraft key (16 B) | Derive the session process key for overdraft-limit updates |
| Internal key / DTK (16 B) | Verify TAC: all financial commands use `tac_key = XOR(ikey[0:8], ikey[8:16])` -> DES-CBC-MAC |

**Terminal ID:** 6 bytes identifying the terminal.  Use any fixed value for testing (e.g. `666666666666`).

### balance

GET BALANCE -- read the current balance from the wallet or passbook balance file.

```
hf fmcos balance --type wallet
hf fmcos balance --type passbook
```

| Flag | Description |
|------|-------------|
| `--type <type>` | `wallet` (0x02) or `passbook` (0x01) |
| `-k` / `--keep` | Keep field on |

**APDU:** `80 5C 00 <type> 04`  
**Response:** 4-byte big-endian balance.

Example output:

```
[=] Balance (wallet): 1000 (0x000003E8)
```

### credit

ADD CREDIT -- two-phase credit (load) transaction (PBOC INITIALIZE FOR LOAD + CREDIT FOR LOAD).

**Phase 1 -- INITIALIZE FOR LOAD** (`INS 50`, P1=00):

Initiates the credit transaction and authenticates the card to the terminal.
The terminal sends the credit key slot ID, the load amount (4 bytes), and the terminal ID (6 bytes).
The card responds with 16 bytes:

| Field | Length | Description |
|-------|--------|-------------|
| Old balance | 4 bytes | Current balance before loading |
| Online serial number | 2 bytes | Incremented by the card after each successful load |
| Key version | 1 byte | Version of the credit key identified by the key slot ID |
| Algorithm ID | 1 byte | Algorithm of that credit key |
| Random seed | 4 bytes | Card-generated pseudorandom number for session key derivation |
| MAC1 | 4 bytes | Card-computed MAC proving it holds the credit key |

The session key (process key) is derived as: `encrypt(random[4] | serial[2] | 0x8000, credit_key)`, first 8 bytes.
MAC1 is: `DES-CBC-MAC(old_bal[4] | amount[4] | type[1] | terminal[6], process_key)`.
The terminal verifies MAC1 to confirm the card holds the correct key before proceeding.
If MAC1 does not match, the transaction is aborted and the balance is unchanged.

**Phase 2 -- CREDIT FOR LOAD** (`INS 52`, P1=00):

Authorizes and commits the balance update.
The terminal sends the host transaction date (4 bytes), time (3 bytes), and MAC2 (4 bytes).
MAC2 is: `DES-CBC-MAC(amount[4] | type[1] | terminal[6] | date[4] | time[3], process_key)`.

On success the card:
- Adds the loaded amount to the balance.
- Increments the online serial number by 1.
- Appends a 23-byte transaction record (serial, overdraft limit, amount, type, terminal, date, time) to the linked loop EF for auditing.

The card responds with the TAC (Transaction Authentication Code, 4 bytes):
`DES-CBC-MAC(new_bal[4] | serial[2] | amount[4] | type[1] | terminal[6] | date[4] | time[3], dtk_xor)`,
where `dtk_xor` is the left 8 bytes XOR right 8 bytes of the internal key (DTK).
The terminal verifies the TAC to confirm the card committed the transaction.

```
hf fmcos credit --type wallet --id 01 --amount 1000 \
  --terminal 666666666666 \
  --key a9e6e145f5df09500a58eef8575d49db \
  --ikey 2b8a438742c851566f02d881b09d58c0

hf fmcos credit --type passbook --id 01 --amount 2000 \
  --terminal 666666666666 \
  --key a9e6e145f5df09500a58eef8575d49db \
  --ikey 2b8a438742c851566f02d881b09d58c0
```

| Flag | Description |
|------|-------------|
| `--type <type>` | `wallet` or `passbook` |
| `--id <n>` | Credit key slot ID (1 byte decimal) |
| `--amount <n>` | Credit amount (integer, units match card configuration) |
| `--terminal <hex>` | Terminal ID (6 bytes) |
| `--key <hex>` | Credit key (16 bytes) |
| `--ikey <hex>` | Internal key (16 bytes) for TAC verification |
| `-k` / `--keep` | Keep field on after command |

> **Note**: FMCOS resets the card's security status after each completed financial transaction.
> Re-verify PIN before each credit or purchase operation (SW:6985 indicates the security status was cleared).

Example output:

```
[=] MAC1 OK  old balance 0
[+] TAC OK  new balance 1000
[+] SW: 9000 - Success
```

### purchase

PURCHASE -- two-phase offline debit transaction from wallet or passbook
(PBOC INITIALIZE FOR PURCHASE + DEBIT FOR PURCHASE).

Passbook purchase requires a successful PIN verify beforehand; wallet purchase does not.

**Phase 1 -- INITIALIZE FOR PURCHASE** (`INS 50`, P1=01):

Initiates the purchase transaction and returns the card state needed for the terminal to derive
the session key and compute the authorization MAC.
The terminal sends the purchase key slot ID, the debit amount (4 bytes), and the terminal ID (6 bytes).
The card responds with 15 bytes:

| Field | Length | Description |
|-------|--------|-------------|
| Old balance | 4 bytes | Current balance before the debit |
| Offline serial number | 2 bytes | Incremented by the card after each successful purchase |
| Overdraft limit | 3 bytes | Maximum permitted overdraft on this file |
| Key version | 1 byte | Version of the purchase key identified by the key slot ID |
| Algorithm ID | 1 byte | Algorithm of that purchase key |
| Random seed | 4 bytes | Card-generated pseudorandom number for session key derivation |

Unlike the credit transaction, the card does not return a MAC1 in this phase.
Instead, the terminal uses the card's response to derive the session key and compute MAC1 locally:

- Session key (process key): `encrypt(random[4] | offline_serial[2] | tx_serial_low2[2], purchase_key)[:8]`,
  where `tx_serial_low2` is the rightmost 2 bytes of the terminal transaction serial number.
- MAC1 (computed by terminal): `DES-CBC-MAC(amount[4] | type[1] | terminal[6] | date[4] | time[3], process_key)`.

If the card returns a non-9000 status the transaction is aborted and the balance is unchanged.

**Phase 2 -- DEBIT FOR PURCHASE** (`INS 54`, P1=01, P2=00):

Authorizes and commits the balance deduction.
The terminal sends the terminal transaction serial (4 bytes), date (4 bytes), time (3 bytes), and MAC1 (4 bytes).
The card verifies MAC1, then deducts the amount and returns 8 bytes:

| Field | Length | Description |
|-------|--------|-------------|
| TAC | 4 bytes | Transaction Authentication Code for terminal verification |
| MAC2 | 4 bytes | Card-computed MAC over the debit amount |

TAC is: `DES-CBC-MAC(amount[4] | type[1] | terminal[6] | tx_serial[4] | date[4] | time[3], dtk_xor)`,
where `dtk_xor` is the left 8 bytes XOR right 8 bytes of the internal key (DTK).
MAC2 is: `DES-CBC-MAC(amount[4], process_key)`.

On success the card:
- Deducts the purchase amount from the balance.
- Increments the offline serial number by 1.

Transaction type byte: `0x05` for passbook purchase, `0x06` for wallet purchase.

```
# Wallet purchase of 50 units
hf fmcos purchase --type wallet --id 01 --amount 50 \
  --terminal 666666666666 \
  --key eb18ce6986c820970e876219052ce0cf \
  --ikey 2b8a438742c851566f02d881b09d58c0 \
  --serial 01020304

# Passbook purchase (no explicit serial -- defaults to 00000001)
hf fmcos purchase --type passbook --id 01 --amount 50 \
  --terminal 666666666666 \
  --key eb18ce6986c820970e876219052ce0cf \
  --ikey 2b8a438742c851566f02d881b09d58c0
```

| Flag | Description |
|------|-------------|
| `--type <type>` | `wallet` or `passbook` |
| `--id <n>` | Purchase key slot ID |
| `--amount <n>` | Debit amount |
| `--terminal <hex>` | Terminal ID (6 bytes) |
| `--key <hex>` | Purchase key (16 bytes) |
| `--ikey <hex>` | Internal key (16 bytes) for TAC verification |
| `--serial <hex>` | 4-byte transaction serial (optional, default `00000001`) |
| `-k` / `--keep` | Keep field on |

Example output:

```
[=] Old balance: 1000
[+] TAC OK  new balance 950
[+] SW: 9000 - Success
```

### overdraft

UPDATE OVERDRAFT LIMIT -- two-phase online overdraft-limit update on the passbook
(PBOC INITIALIZE FOR UPDATE + UPDATE OVERDRAW LIMIT).

The overdraft limit allows transactions to continue when the actual passbook funds are
insufficient, up to the issuer-permitted limit.
This transaction must be performed online at a financial terminal and requires a successful
PIN verify beforehand.  It applies to passbook only; wallet files do not carry an overdraft limit.

**Phase 1 -- INITIALIZE FOR UPDATE** (`INS 50`, P1=04, P2=01):

Initiates the overdraft-limit update and authenticates the card to the terminal.
The terminal sends the overdraft key slot ID (1 byte) and the terminal ID (6 bytes).
Note that no amount is sent in this phase; the new limit is supplied in Phase 2.
The card responds with 19 bytes:

| Field | Length | Description |
|-------|--------|-------------|
| Old balance | 4 bytes | Current stored balance (actual funds + current overdraft limit) |
| Online serial number | 2 bytes | Incremented by the card after each successful online transaction |
| Old overdraft limit | 3 bytes | Current overdraft limit before the update |
| Key version | 1 byte | Version of the overdraft key identified by the key slot ID |
| Algorithm ID | 1 byte | Algorithm of that overdraft key |
| Random seed | 4 bytes | Card-generated pseudorandom number for session key derivation |
| MAC1 | 4 bytes | Card-computed MAC proving it holds the overdraft key |

Session key (process key): `encrypt(random[4] | serial[2] | 0x8000, overdraft_key)[:8]`.
MAC1 is: `DES-CBC-MAC(old_bal[4] | old_limit[3] | 0x07[1] | terminal[6], process_key)`,
where `0x07` is the fixed transaction type identifier for overdraft limit updates.
The terminal verifies MAC1 to confirm the card holds the correct key before proceeding.
If MAC1 does not match, the transaction is aborted and the limit is unchanged.

**Phase 2 -- UPDATE OVERDRAW LIMIT** (`INS 58`, P1=00, P2=00):

Authorizes and commits the new overdraft limit.
The terminal sends the new limit (3 bytes), host transaction date (4 bytes), time (3 bytes),
and MAC2 (4 bytes).
MAC2 is: `DES-CBC-MAC(new_limit[3] | 0x07[1] | terminal[6] | date[4] | time[3], process_key)`.

The card responds with TAC (4 bytes).
TAC is: `DES-CBC-MAC(tac_bal[4] | serial[2] | new_limit[3] | 0x07[1] | terminal[6] | date[4] | time[3], dtk_xor)`,
where `dtk_xor` is the left 8 bytes XOR right 8 bytes of the internal key (DTK), and
`tac_bal = old_balance + new_limit - old_overdraft_limit` (the new stored balance after the limit shift).

The card stores `actual_funds + overdraft_limit` as its balance field, so changing the limit
by a delta shifts the stored balance value by the same delta without altering actual funds.

On success the card:
- Updates the overdraft limit to the new value.
- Adjusts the stored balance to `actual_funds + new_limit`.
- Increments the online serial number by 1.
- Appends a 23-byte transaction record (serial, new limit, amount, type `0x07`, terminal, date, time)
  to the linked loop EF for auditing.

```
hf fmcos overdraft --id 01 --limit 1000 \
  --terminal 666666666666 \
  --key 94f63c4fae5e4977d749928ad12bc128 \
  --ikey 659a500f0f1fce35b6884bdff966576a
```

| Flag | Description |
|------|-------------|
| `--id <hex>` | Overdraft key slot ID |
| `--limit <n>` | New overdraft limit (24-bit integer, max 16777215) |
| `--terminal <hex>` | Terminal ID (6 bytes) |
| `--key <hex>` | Overdraft key (16 bytes) |
| `--ikey <hex>` | Internal key DTK (16 bytes) for TAC verification (optional) |
| `-k` / `--keep` | Keep field on |

Example output:

```
[=] Old balance: 1000  old overdraft limit: 0
[=] MAC1 OK
[+] SW: 9000 - Success
[+] Overdraft limit updated to 1000
[+] TAC OK  aabbccdd
```

### history

READ TRANSACTION HISTORY -- decode all records in the loop (cyclic) EF used as a transaction
log.  The card appends a 23-byte record to the loop file after every financial operation.

```
# Wallet transaction log (loop file SFI 0x18 in the example setup)
hf fmcos history --fid 18

# Passbook transaction log, read up to 20 records
hf fmcos history --fid 19 --count 20
```

| Flag | Description |
|------|-------------|
| `--fid <hex>` | Loop file SFI byte (1 byte, e.g. `18` for wallet loop, `19` for passbook loop) |
| `--count <n>` | Max records to read (default 10; `0` = read all, up to 255) |
| `-k` / `--keep` | Keep field on after command |
| `-a` / `--apdu` | Show raw APDU traffic |

**Record layout (23 bytes):**

| Offset | Length | Field | Notes |
|--------|--------|-------|-------|
| 0 | 2 | Serial | Transaction serial number (big-endian) |
| 2 | 3 | OD limit | Overdraft limit at time of transaction |
| 5 | 4 | Amount | Transaction amount (big-endian) |
| 9 | 1 | Type | Transaction type byte |
| 10 | 6 | Terminal | Terminal ID |
| 16 | 4 | Date | BCD date `YYYYMMDD` |
| 20 | 3 | Time | BCD time `HHMMSS` |

**Transaction type codes:**

| Code | Description |
|------|-------------|
| `0x04` | Passbook cash withdrawal |
| `0x05` | Passbook purchase |
| `0x06` | Wallet purchase |
| `0x07` | Overdraft limit update |
| `0x09` | Compound purchase |

Example output:

```
 # | Date       | Time     | Type         | Amount     | OD Limit | Serial | Terminal
---+------------+----------+--------------+------------+----------+--------+-------------------
 1 | 2026-05-24 | 14:30:22 | WL purchase  |         50 |        0 | 000002 | 66 66 66 66 66 66
 2 | 2026-05-24 | 14:28:05 | WL purchase  |       1000 |        0 | 000001 | 66 66 66 66 66 66
[+] 2 records
```

> **Note**: Record 1 is always the most recently written entry.  Reading stops automatically
> when the card returns a non-9000 SW (record number exceeds log capacity).

---

## Card Lifecycle

### block

BLOCK the entire card (CARD BLOCK, `INS 16`) or the currently selected application
(APP BLOCK, `INS 1E`).  Uses the line-protection key to compute a packet MAC over the
command header via GET CHALLENGE.

```
# Block the card permanently
hf fmcos block --card --key 8a021972bfec9d152ca9eb82d7d12c09

# Block application temporarily (default)
hf fmcos block --app --key 8a021972bfec9d152ca9eb82d7d12c09

# Block application permanently
hf fmcos block --app --perm --key 8a021972bfec9d152ca9eb82d7d12c09
```

| Flag | Description |
|------|-------------|
| `--card` | Block the whole card |
| `--app` | Block the current application |
| `--perm` | Permanent block (default is temporary for `--app`) |
| `--key <hex>` | Line-protection key (8 or 16 bytes) |

### unblock

UNBLOCK the currently selected application (APP UNBLOCK, `INS 18`).
Same MAC pattern as block.

```
hf fmcos unblock --key 8a021972bfec9d152ca9eb82d7d12c09
```

| Flag | Description |
|------|-------------|
| `--key <hex>` | Line-protection key (8 or 16 bytes) |

---

## File Access Reference

### MF (Master File)

- Automatically selected on card reset.
- Can be selected at any DF level using FID `3F00` or the MF name.
- Default name assigned at creation: `1PAY.SYS.DDF01`.

### DF (Directory File)

- Selected by file identifier (FID) or directory name (DF name).

### Binary EF (type `0x28`)

- Read with READ BINARY when the read condition is satisfied.
- Updated with UPDATE BINARY when the write condition is satisfied.

### Fixed-Length Record EF (type `0x2A`)

- Read a specific record with READ RECORD when the read condition is satisfied.
- Update a specific record with UPDATE RECORD when the write condition is satisfied.
- Append a record at the end with APPEND RECORD when the append condition is satisfied.

### Cyclic (Loop) EF (type `0x2E`)

- Read a specific record with READ RECORD when the read condition is satisfied.
- Prepend a new record at the front with APPEND RECORD when the append condition is satisfied.
- When the file is full, the oldest record is automatically overwritten.
- The most recently written record always has record number 1; the prior record is number 2; and so on.

### Wallet/Purse EF (EDEP/EP, type `0x2F`)

- GET BALANCE reads the current balance.
- Under key control: CREDIT FOR LOAD, DEBIT FOR PURCHASE / CASH WITHDRAW,
  DEBIT FOR UNLOAD, and UPDATE OVERDRAFT LIMIT.

### Variable-Length Record EF (type `0x2C`)

- Read a specific record with READ RECORD when the read condition is satisfied.
- Update an existing record with UPDATE RECORD; append a new record with APPEND RECORD.
- **TLV format:** each record is `Tag (1 byte) | Length (1 byte) | Value (Length bytes)`.
  Tag `0x00` is used by FMCOS for the standard record wrapper.
- UPDATE RECORD requires the new record's total TLV length to equal the original; otherwise the
  command fails (SW `6A83`).

### KEY File (type `0x3F`)

- Only one KEY file is allowed per DF/MF; it **must be created before any other file** in that directory.
- Key data can **never be read out** from the card.
- While a DF/MF has no KEY file (and no other files), any file can be created and accessed without
  access-rights restrictions.  Once you leave and re-enter that directory, access rights are enforced.
- Each key is stored as a variable-length record: `key_data + 8 header bytes`.
  - Triple-DES (16-byte) key record: **24 bytes** total.
  - Single-DES (8-byte) key record: **16 bytes** total.
- WRITE KEY adds a new key (when the "add key" permission is satisfied) or updates key data
  (when that specific key's "change" permission is satisfied).
- Key data can only be used when the key's "use" permission is satisfied.

### Key Independence

Each key is bound to exactly one function (encrypt, decrypt, MAC, etc.) and cannot be used
for any other function - including keys that generate, derive, or transport other card keys.

### PIN Key

- VERIFY checks the PIN; PIN CHANGE / UNBLOCK changes and optionally unlocks it.
- On a successful VERIFY, the security-status register is updated to the post-condition value
  stored in the PIN key record.
- An error counter decrements on every failed VERIFY; when it reaches 0 the PIN key is locked.

### Unlock-PIN Key

- UNBLOCK verifies the unlock password and simultaneously unlocks a PIN key that was blocked
  by repeated wrong attempts, while also setting a new PIN.
- Once the unlock-PIN key's own error counter reaches 0, it is permanently locked with no recovery.

### External Authentication Key

- EXTERNAL AUTHENTICATE can be executed when the key's use condition is satisfied.
- WRITE KEY updates the key when the change condition is satisfied.
- Once locked by exhausting its error counter, it **cannot be unlocked**.

---

## Key Types Reference

FMCOS keys are stored in a keyfile EF.  Each key entry begins with a type byte that
encodes both the functional role (high nibble = 0x3x) and the line-protection mode
OR-ed in by `--prot` when writing the key itself.

| Type name | Byte | Role |
|-----------|------|------|
| `desenc` | 0x30 | 3DES ECB encryption |
| `desdec` | 0x31 | 3DES ECB decryption |
| `desmac` | 0x32 | DES MAC generation |
| `internal` | 0x34 | Internal-authenticate / TAC key |
| `lineprotect` | 0x36 | Line-protection key (MAC-only or MAC+enc mode) |
| `unlockpin` | 0x37 | Authorize PIN unblock |
| `changepin` | 0x38 | Authorize PIN reset |
| `extauth` | 0x39 | External-authenticate key |
| `pin` | 0x3A | PIN code key |
| `overdraft` | 0x3C | Overdraft-limit session key |
| `debit` | 0x3D | Online-transfer (debit) session key |
| `purchase` | 0x3E | Purchase / offline-debit session key |
| `credit` | 0x3F | Credit session key |

---

## File Protection Modes

When creating a file or writing with protection, the `--prot` flag selects the mode:

| Mode | Value | Description |
|------|-------|-------------|
| `none` | 0x00 | No line protection |
| `mac` | 0x80 | MAC-only; command includes 4-byte packet MAC, response includes MAC |
| `enc` | 0xC0 | MAC + encryption; data encrypted, 4-byte MAC appended |

MAC is computed by `fmcos_packet_mac`: DES(8-byte key) or 3DES-Retail-MAC(16-byte key)
over `CLA|INS|P1|P2|Lc[|data]` with a GET CHALLENGE response as the CBC IV.

---

## Access Rights Byte

The access-rights byte passed to `createfile` controls whether line protection is needed
and which key slot guards read / write access.

```
Bit 7 (MSB): 1 = protection NOT required, 0 = protection required
Bit 6-5:     reserved
Bits 4-3:    read key index  (11=key0, 10=key1, 01=key2, 00=key3)
Bits 2-1 (LSB): write key index (11=key0, 10=key1, 01=key2, 00=key3)
```

Common values:

| Value | Meaning |
|-------|---------|
| `ff` | No protection required, key0 for both read/write |
| `7f` | Protection required, key0 for both read/write |
| `f0` | No protection required (permission byte for directories/keys) |

---

## TID Tag Provisioning

A TID tag is a magic FMCOS tag that bypasses certain authentication mechanisms and
allows custom UID. These commands below allow a TID tag to be provisioned - UID,
auth key, and file system, these commands are not the same as the standard fmcos commands.

These cards can often be found on taobao by searching for "CPU TID card".
When hf fmcos authexternal is called with any key, the card will always return
[+] SW: 9000 - Success
[+] External authentication successful

All TID commands are direct subcommands of `hf fmcos`, prefixed with `tid`.

| Command | Description |
|---------|-------------|
| `tidsetcard` | Write fixed card configuration block (`INS 0xEF`) |
| `tidsetuid` | Program the ISO14443-A UID (`INS 0x85`) |
| `tidsetauth` | Write the internal auth key and lock state (`INS 0x21`) |
| `tiderase` | Erase the card file system (`CLA 0xE0 INS 0xEC`) |
| `tidprovision` | Full provisioning sequence in one command |
| `tidcreatedf` | CREATE sub-DF (TID format) |
| `tidcreatebin` | CREATE binary EF or KEYFILE (TID format) |
| `tidcreaterec` | CREATE record EF (TID format) |

> **Order matters.** When provisioning manually, always run `tidsetcard` -> `tidsetuid` -> `tidsetauth`
> -> `tiderase` -> create file structure.  `tidprovision` does this automatically.

---

### tidsetcard

Send the fixed 39-byte SET CARD configuration APDU.  The payload is hardcoded - there is
limited information on what the fields do.  This must be sent before any other provisioning step.

```
hf fmcos tidsetcard
```

| Flag | Description |
|------|-------------|
| `-k` / `--keep` | Keep field on after command |

**APDU:** `00 EF 00 00 27 <39-byte config>`

---

### tidsetuid

Program the card's ISO14443-A UID.

```
hf fmcos tidsetuid --uid 13371337
hf fmcos tidsetuid --uid 0102030405060708
```

| Flag | Description |
|------|-------------|
| `--uid <hex>` | UID bytes (4-7 bytes, i.e. 8-14 hex chars) |
| `-k` / `--keep` | Keep field on after command |

**APDU:** `00 85 00 00 <len> <uid>`

---

### tidsetauth

Write the 8-byte internal authentication key and set the lock state.

```
hf fmcos tidsetauth --key 1122334455667788
hf fmcos tidsetauth --key 1122334455667788 --lock
```

| Flag | Description |
|------|-------------|
| `--key <hex>` | Internal auth key (8 bytes) |
| `--lock` | Lock the key permanently (`0xAA`); default is unlocked (`0x55`) |
| `-k` / `--keep` | Keep field on after command |

**APDU:** `00 21 00 00 0A <key[8]> <lock_byte> 00`

> **Warning:** `--lock` not much is known about how this functions, use with care.

---

### tiderase

Erase the card's file system.  Uses `CLA=0xE0` (not `0x80` as in standard FMCOS erase).

```
hf fmcos tiderase
```

| Flag | Description |
|------|-------------|
| `-k` / `--keep` | Keep field on after command |

**APDU:** `E0 EC 00 00 00`

---

### tidprovision

Full provisioning sequence in a single command.  Chains all steps with the RF field held on
and aborts with an error message if any step fails.

Steps performed:
1. SET CARD (fixed config block)
2. SET UID
3. SET INTERNAL AUTH
4. ERASE
5. SELECT MF (`3F00`)
6. CREATE MF (`3F00`, name `1PAY.SYS.DDF01`)
7. SELECT MF (`3F00`)
8. CREATE KEYFILE

```
hf fmcos tidprovision --uid 13371337 --key 1122334455667788
hf fmcos tidprovision --uid 13371337 --key 1122334455667788 --lock
```

| Flag | Description |
|------|-------------|
| `--uid <hex>` | UID bytes (4-7 bytes) |
| `--key <hex>` | Internal auth key (8 bytes) |
| `--lock` | Lock the auth key permanently after writing |
| `-k` / `--keep` | Keep field on after completion |

After `tidprovision`, use `tidcreatedf` / `tidcreatebin` / `tidcreaterec` to build
the file structure, then `hf fmcos writebinary` / `hf fmcos writerecord` to populate data.

---

### tidcreatedf

CREATE a sub-DF using the TID APDU format.  The standard `hf fmcos createdir` uses a
different data layout (FID in P1/P2, leading `0x38` byte); this command uses the TID layout
where P1=`0x01` and the FID is the first field in the data.

```
hf fmcos tidcreatedf --id 3f01 --size 0f00 --sfi 96 --name 444446303133
```

| Flag | Description |
|------|-------------|
| `--id <4hex>` | 2-byte file ID |
| `--size <hex>` | DF space to allocate in bytes (hex) |
| `--sfi <hex>` | Short file ID (1 byte) |
| `--name <hex>` | DF name bytes (0-16 bytes, optional) |
| `-k` / `--keep` | Keep field on after command |

**APDU:** `80 E0 01 00 <lc> [fid_hi][fid_lo] [size_hi][size_lo] F0 F0 [sfi] 01 FF [name...]`

---

### tidcreatebin

CREATE a binary EF or KEYFILE using the TID APDU format.  The standard `hf fmcos createfile --type bin`
uses a different layout (FID in P1/P2, 7-byte payload); this command uses the TID layout
where P1=`0x02` and the FID is in the data with a fixed 11-byte payload.

Use `--type keyfile` to create the fixed TID keyfile (subtype `1E`) in the currently selected DF.
Every sub-DF needs a keyfile before EFs can be created inside it.

```
hf fmcos tidcreatebin --id 0001 --size 0100 --sfi 01
hf fmcos tidcreatebin --id 0002 --size 0040 --sfi 02 --rperm 20 --wperm f0
hf fmcos tidcreatebin --type keyfile
```

| Flag | Description |
|------|-------------|
| `--type <type>` | `bin` (default) or `keyfile` |
| `--id <4hex>` | 2-byte file ID (required for `bin`) |
| `--size <hex>` | File size in bytes, hex (required for `bin`) |
| `--sfi <hex>` | Short file ID, 1 byte (required for `bin`) |
| `--rperm <hex>` | Read permission byte (default `F0`, `bin` only) |
| `--wperm <hex>` | Write permission byte (default `F0`, `bin` only) |
| `-k` / `--keep` | Keep field on after command |

**APDU (bin):** `80 E0 02 00 0B 00 [fid_hi][fid_lo] [size_hi][size_lo] [rperm][wperm] [sfi] 00 FF 00`

**APDU (keyfile):** `80 E0 02 00 0B 1E 00 00 00 30 FF FF 00 30 00 00`

---

### tidcreaterec

CREATE a fixed-length record EF using the TID APDU format.  The standard `hf fmcos createfile --type fix`
uses a different layout; this command uses the TID layout where P1=`0x02`, subtype=`0x01`,
and count+reclen replace the size field.

```
hf fmcos tidcreaterec --id 0003 --count 04 --reclen 08 --sfi 03
hf fmcos tidcreaterec --id 0003 --count 04 --reclen 10 --sfi 03 --rperm 20 --wperm f0
```

| Flag | Description |
|------|-------------|
| `--id <4hex>` | 2-byte file ID |
| `--count <hex>` | Number of records (1 byte) |
| `--reclen <hex>` | Bytes per record (1 byte) |
| `--sfi <hex>` | Short file ID (1 byte) |
| `--rperm <hex>` | Read permission byte (default `F0`) |
| `--wperm <hex>` | Write permission byte (default `F0`) |
| `-k` / `--keep` | Keep field on after command |

**APDU:** `80 E0 02 00 0B 01 [fid_hi][fid_lo] [count][reclen] [rperm][wperm] [sfi] 00 FF 00`

> **Note**: To write data into TID EFs after creation, use the standard `hf fmcos writebinary`
> and `hf fmcos writerecord` - those APDUs (`00 D6` / `00 DC`) are identical in TID and standard FMCOS.

---

## TID Vendor Card Templates

Six real-world Chinese access-control layouts were translated from the app that is
normally provided when you buy these TID cards.

### Provisioning notes

- Replace `--uid` and `--key` in the `provision` call with your actual values.
- `-k` keeps the RF field on between commands, preserving the card's file context.  When a
  command finishes without `-k` the field drops and the card resets to MF context on the
  next activation.
- Each sub-DF requires a TID-format keyfile created immediately after selecting it.  Use
  `hf fmcos tidcreatebin --type keyfile` - the standard `hf fmcos createkeyfile` uses a
  different APDU layout and cannot create TID keyfiles.

---

### 01 - Dingbo

```
MF  3F00  "1PAY.SYS.DDF01"  SFI 0x02
+-- DF  7572  39 01 30 99 08 07  SFI 0x02  (proprietary 6-byte name)
    +-- EF-rec  0001  SFI 0x03  6 records x 16 bytes
```

```
hf fmcos tidprovision --uid 13371337 --key 0001020304050607
hf fmcos tidcreatedf --id 7572 --size 0200 --sfi 02 --name 390130990807 -k
hf fmcos select --id 7572 -k
hf fmcos tidcreatebin --type keyfile -k
hf fmcos tidcreaterec --id 0001 --count 06 --reclen 10 --sfi 03 -k
hf fmcos writerecord --rec 01 --fid 03 --data 018609DD110000000000010100000000 -k
hf fmcos writerecord --rec 02 --fid 03 --data 00000000000000000000000000000000 -k
hf fmcos writerecord --rec 03 --fid 03 --data 0000000000070A0D1707120000008800 -k
hf fmcos writerecord --rec 04 --fid 03 --data 00000000000000000000000000000000 -k
hf fmcos writerecord --rec 05 --fid 03 --data 00000000000000000000000000000000 -k
hf fmcos writerecord --rec 06 --fid 03 --data 00000000000000000000000000000000
```

---

### 02 - Anjubao

```
MF  3F00  "1PAY.SYS.DDF01"  SFI 0x02
+-- DF  1001  A0 00 00 00 03 86 98 07 01  SFI 0x02  (9-byte AID)
    +-- EF-bin  0018  SFI 0x18  140 bytes  (wallet balance file)
    +-- EF-bin  0019  SFI 0x19  140 bytes  (passbook balance file)
```

```
hf fmcos tidprovision --uid 13371337 --key 0001020304050607
hf fmcos tidcreatedf --id 1001 --size 0200 --sfi 02 --name A00000000386980701 -k
hf fmcos select --id 1001 -k
hf fmcos tidcreatebin --type keyfile -k
hf fmcos tidcreatebin --id 0018 --size 008C --sfi 18 -k
hf fmcos select --id 0018 -k
hf fmcos writebinary --p1 00 --p2 00 --data 001FD921090700000001000023590000000000E0FFFFFF7F0700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 -k
hf fmcos tidcreatebin --id 0019 --size 008C --sfi 19 -k
hf fmcos select --id 0019 -k
hf fmcos writebinary --p1 00 --p2 00 --data 001FD921090700000001000023590000FFFFFFFFFFFF010000000000E0FFFFFF0F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

---

### 03 - Jinbo

```
MF  3F00  "1PAY.SYS.DDF01"  SFI 0x02
+-- DF  4A54  6A 69 6E 00 00 00 62 6F A5 04 9F 08 01 02  SFI 0x02  (14-byte name, starts "jin")
    +-- EF-bin  4200  SFI 0x01  624 bytes  (32 B payload at offset 592, remainder zeros)
```

```
hf fmcos tidprovision --uid 13371337 --key 0001020304050607
hf fmcos tidcreatedf --id 4A54 --size 0300 --sfi 02 --name 6A696E00000000626FA5049F080102 -k
hf fmcos select --id 4A54 -k
hf fmcos tidcreatebin --type keyfile -k
hf fmcos tidcreatebin --id 4200 --size 0270 --sfi 01 -k
hf fmcos select --id 4200 -k
hf fmcos writebinary --p1 02 --p2 50 --data 530030FFFFFFFFFFFFFF3A2B0000000022012200002403081106000000007F00
```

---

### 04 - Jingkong

```
MF  3F00  "1PAY.SYS.DDF01"  SFI 0x02
+-- DF  3F01  "DDF01"  SFI 0x02
    +-- EF-bin  0001  SFI 0x01    1 byte   (placeholder)
    +-- EF-bin  0003  SFI 0x03   28 bytes  (key / config data)
    +-- EF-bin  0004  SFI 0x04  120 bytes  (zeroed)
    +-- EF-bin  0005  SFI 0x05   36 bytes  (key / config data)
    +-- EF-bin  0006  SFI 0x06  132 bytes  (key / config data)
    +-- EF-bin  0007  SFI 0x07  102 bytes  (zeroed)
```

```
hf fmcos tidprovision --uid 13371337 --key 0001020304050607
hf fmcos tidcreatedf --id 3F01 --size 0400 --sfi 02 --name 4444463031 -k
hf fmcos select --id 3F01 -k
hf fmcos tidcreatebin --type keyfile -k
hf fmcos tidcreatebin --id 0001 --size 0001 --sfi 01 -k
hf fmcos tidcreatebin --id 0003 --size 001C --sfi 03 -k
hf fmcos select --id 0003 -k
hf fmcos writebinary --p1 00 --p2 00 --data FE937B922D7EDEF50000000000000000000000000000000000000000 -k
hf fmcos tidcreatebin --id 0004 --size 0078 --sfi 04 -k
hf fmcos select --id 0004 -k
hf fmcos writebinary --p1 00 --p2 00 --data 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 -k
hf fmcos tidcreatebin --id 0005 --size 0024 --sfi 05 -k
hf fmcos select --id 0005 -k
hf fmcos writebinary --p1 00 --p2 00 --data 6403FE9C7434FCBC6E00FC9F2802F1448F06F3BA8CF6F0B98DF7F1B84D0BF60000000000 -k
hf fmcos tidcreatebin --id 0006 --size 0084 --sfi 06 -k
hf fmcos select --id 0006 -k
hf fmcos writebinary --p1 00 --p2 00 --data 616BEACE7705FCBD7604FDBC7107F2BB7006F3BA7309F0B97208F1B84D0B09B74C0AF7494F0DF4B5B10CF5B449F0EAB3480E14B24B31E84E4A30E9B0BA33EEAF44CDEFAE473513AD4634ED534137E2ABBF36E3AA43C6E0A942381EA85D3BE6585C3AE7A6A03DE4A55E000000000000000000000000000000000000000000000000000000 -k
hf fmcos tidcreatebin --id 0007 --size 0066 --sfi 07 -k
hf fmcos select --id 0007 -k
hf fmcos writebinary --p1 00 --p2 00 --data 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

---

### 05 - Kangtuo

```
MF  3F00  "1PAY.SYS.DDF01"  SFI 0x02
+-- DF  D0F1  "XL123"  SFI 0x02
|   +-- EF-bin  0005  SFI 0x05  64 bytes
+-- DF  D0F2  "XL456"  SFI 0x02
    +-- EF-bin  0005  SFI 0x05  64 bytes
```

```
hf fmcos tidprovision --uid 13371337 --key 0001020304050607
hf fmcos tidcreatedf --id D0F1 --size 0100 --sfi 02 --name 584C313233 -k
hf fmcos select --id D0F1 -k
hf fmcos tidcreatebin --type keyfile -k
hf fmcos tidcreatebin --id 0005 --size 0040 --sfi 05 -k
hf fmcos select --id 0005 -k
hf fmcos writebinary --p1 00 --p2 00 --data 0200FC20006200000000000000000000000000272E2C6A0000000000000000080000000000000000000000000000000000000000000000000000000000000000
hf fmcos tidcreatedf --id D0F2 --size 0100 --sfi 02 --name 584C343536 -k
hf fmcos select --id D0F2 -k
hf fmcos tidcreatebin --type keyfile -k
hf fmcos tidcreatebin --id 0005 --size 0040 --sfi 05 -k
hf fmcos select --id 0005 -k
hf fmcos writebinary --p1 00 --p2 00 --data 0200FC20006200000000000000000000000000272E2C6A0000000000000000080000000000000000000000000000000000000000000000000000000000000000
```

---

### 06 - Youhe

```
MF  3F00  "1PAY.SYS.DDF01"  SFI 0x02
+-- DF  3F01  "ADF01"  SFI 0x02
    +-- EF-bin  0003  SFI 0x03  250 bytes  (key / credential data)
```

```
hf fmcos tidprovision --uid 13371337 --key 0001020304050607
hf fmcos tidcreatedf --id 3F01 --size 0200 --sfi 02 --name 4144463031 -k
hf fmcos select --id 3F01 -k
hf fmcos tidcreatebin --type keyfile -k
hf fmcos tidcreatebin --id 0003 --size 00FA --sfi 03 -k
hf fmcos select --id 0003 -k
hf fmcos writebinary --p1 00 --p2 00 --data D15190D7E1E379732295C97D62A3172BE3BBA1D1B32CE32FED72CB3DCDB115E7DC2670978E241822F298C9951260FC55D54F9988C7FCAC5032F94281DFC39C973E570101764D5BBF367F84EBDA1B012ABD4568F35D5BC08BAFD76B988CA916C985692337FCF02C9FD2C8BDD583BC05EF55582C3921FA2CAFAE26308FBADE0598DB750EE1F0522D29EAB6FA5D0F3971F785692337FCF02C9FD2C8BDD583BC05EF55582C3921FA2CAFAE26308FBADE0598DB750EE1F0522D29EAB6FA5D0F3971F7EA545FC5B27B7F40DF6D0F71FCEE2A1BCED2DEDE67BB57B1C1F98C8CDA5259CC7BD83158086F215F5E1E0246EE0504760000000000 -k
hf fmcos writebinary --p1 00 --p2 F5 --data 0000000000
```
