# FMCOS Wallet Walkthrough

When commands are chained in a session the RF field must stay on between them.
Add `-k` (keep field on) to every command in a chain except the last one.

## Keys used throughout


| Variable | Hex |
|---|---|
| `external_auth_key` | `f49dc1ba1b4deb52647186bc59106c0d` |
| `internal_key` | `2b8a438742c851566f02d881b09d58c0` |
| `line_protection_key` | `8a021972bfec9d152ca9eb82d7d12c09` |
| `unlock_pin_key` | `d8f60fa2d791f3a658d27c05458243ed` |
| `change_pin_key` | `fb487a6d1b7cbf1bf84c666b8338376e` |
| `purchase_key` | `eb18ce6986c820970e876219052ce0cf` |
| `credit_key` | `a9e6e145f5df09500a58eef8575d49db` |
| `debit_key` | `97fb4eda4b5237035946ee62d325d909` |
| `overdraw_limit_key` | `94f63c4fae5e4977d749928ad12bc128` |
| `int_enc` | `c4608b786af1992343e91a076670ae7c` |
| `int_dec` | `b8d4190c76856901fc686f36ab9b1ce0` |
| `int_mac` | `46a3ea8b254ee2749cc681050fd0dbcc` |
| PIN (`\x12\x34\x56`) | `123456` (3 bytes, raw BCD) |
| New PIN (`\x13\x37\x13\x37`) | `13371337` (4 bytes, raw BCD) |
| Terminal ID | `666666666666` (6 bytes) |

---

## 1. reset - select MF and erase DF

Select the Master File then erase the application directory from a previous run:

```
hf fmcos select --id 3f00 -k
hf fmcos erase
```

`hf fmcos erase` sends INS=0x0E to delete the currently-selected DF and all
its children.  Run it only when the card already has a DF selected (the MF
itself cannot be erased this way).

---

## 2. setup - create directory, keyfile, keys, loop files, balance files

### 2a. Create the application directory (ADF)

> **Note**: `--space` and `--size` arguments are parsed as **hexadecimal**.
> `--space 1500` = 0x1500 = 5376 bytes,  `--size 0208` = 0x0208 = 520 bytes.

`77616C6C657454657374` is the hex encoding of ASCII `walletTest`.

```
hf fmcos select --id 3f00 -k
hf fmcos createdir --id 3F01 --space 1500 --cperm F0 --eperm F0 --appid 95 --name 77616C6C657454657374 -k
```

### 2b. Select the new ADF by name

```
hf fmcos select --name 77616C6C657454657374 -k
```

All subsequent setup commands assume this DF remains selected (field stays on).

### 2c. Create the keyfile

```
hf fmcos createkeyfile --id 0000 --space 200 --dfsid 95 --perm F0 -k
```

### 2d. Write keys

- `--op 01` = P1, authorization operation code (0x01 = add/update)
- `--id 00` = P2, key slot to write (0x00 = auto-assign next slot)
- `--usage F0` = usage rights byte

All key writes continue in the same session so every command carries `-k`.

**Key 0 - DES Encrypt (int_enc)**
```
hf fmcos key --op 01 --id 00 --usage F0 --type desenc --change F4 --version 05 --algo 98 --key c4608b786af1992343e91a076670ae7c -k
```

**Key 1 - DES Decrypt (int_dec)**
```
hf fmcos key --op 01 --id 00 --usage F0 --type desdec --change F4 --version 05 --algo 98 --key b8d4190c76856901fc686f36ab9b1ce0 -k
```

**Key 2 - DES MAC (int_mac)**
```
hf fmcos key --op 01 --id 00 --usage F0 --type desmac --change F4 --version 05 --algo 98 --key 46a3ea8b254ee2749cc681050fd0dbcc -k
```

**Key 3 - Internal Key (internal_key)**
```
hf fmcos key --op 01 --id 00 --usage F0 --type internal --change 02 --version 00 --algo 01 --key 2b8a438742c851566f02d881b09d58c0 -k
```

**Key 4 - File Line Protection Key (line_protection_key)**

Group C type - uses `--change` and `--errcount`.
```
hf fmcos key --op 01 --id 00 --usage F0 --type lineprotect --change 02 --errcount 33 --key 8a021972bfec9d152ca9eb82d7d12c09 -k
```

**Key 5 - Unlock PIN Key (unlock_pin_key)**
```
hf fmcos key --op 01 --id 00 --usage F0 --type unlockpin --change 02 --errcount 33 --key d8f60fa2d791f3a658d27c05458243ed -k
```

**Key 6 - Change PIN Key (change_pin_key)**
```
hf fmcos key --op 01 --id 00 --usage F0 --type changepin --change 02 --errcount 33 --key fb487a6d1b7cbf1bf84c666b8338376e -k
```

**Key 7 - External Authentication Key (external_auth_key)**

Group B type with `--change` - uses `--change`, `--followup`, and `--errcount`.
```
hf fmcos key --op 01 --id 00 --usage F0 --type extauth --change 02 --followup 44 --errcount 33 --key f49dc1ba1b4deb52647186bc59106c0d -k
```

**Key 8 - Purchase Key (purchase_key)**
```
hf fmcos key --op 01 --id 00 --usage F0 --type purchase --change 02 --version 00 --algo 01 --key eb18ce6986c820970e876219052ce0cf -k
```

**Key 9 - Credit Key (credit_key)**
```
hf fmcos key --op 01 --id 00 --usage F0 --type credit --change 02 --version 00 --algo 01 --key a9e6e145f5df09500a58eef8575d49db -k
```

**Key 10 - Debit Key (debit_key)**
```
hf fmcos key --op 01 --id 00 --usage F0 --type debit --change 02 --version 00 --algo 01 --key 97fb4eda4b5237035946ee62d325d909 -k
```

**Key 11 - Overdraw Limit Key (overdraw_limit_key)**
```
hf fmcos key --op 01 --id 00 --usage F0 --type overdraft --change 02 --version 00 --algo 01 --key 94f63c4fae5e4977d749928ad12bc128 -k
```

**Key 12 - PIN Key (pin_code)**

The PIN `\x12\x34\x56` is 3 raw BCD bytes.
Group B type - uses `--followup` and `--errcount`.
```
hf fmcos key --op 01 --id 00 --usage F0 --type pin --followup 01 --errcount 33 --key 123456 -k
```

### 2e. Create loop files for transaction logging

Loop file 0x0018 (to be linked to the wallet balance file):
```
hf fmcos createfile --id 0018 --type loop --size 0517 --rperm F0 --wperm EF --access FF -k
```

Loop file 0x0019 (to be linked to the passbook balance file):
```
hf fmcos createfile --id 0019 --type loop --size 0517 --rperm F0 --wperm EF --access FF -k
```

### 2f. Create wallet and passbook balance files

Wallet balance file (EF 0x0002, linked to loop file 0x0018):
```
hf fmcos createfile --id 0002 --type wallet --size 0208 --rperm F0 --wperm 00 --access 18 -k
```

Passbook balance file (EF 0x0001, linked to loop file 0x0019):
```
hf fmcos createfile --id 0001 --type wallet --size 0208 --rperm F0 --wperm 00 --access 19
```

The last command drops the field to end the setup session.

---

## 3. verify_pin - verify the PIN

The PIN `\x12\x34\x56` is 3 raw BCD bytes.

```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456
```

---

## 4. get_balance - read wallet and passbook balances

```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos balance --type wallet -k
hf fmcos balance --type passbook
```

The command prints the 4-byte big-endian balance in decimal and hex.

---

## 5. add_money - credit (load funds)

Credit key index is 9 (written ninth in step 2d, 0-based index = 9 = 0x09).

Credit 1000 units to the wallet, then 2000 to the passbook in one session:
```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos credit --type wallet   --id 09 --amount 1000 --terminal 666666666666 --key a9e6e145f5df09500a58eef8575d49db --ikey 2b8a438742c851566f02d881b09d58c0 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos credit --type passbook --id 09 --amount 2000 --terminal 666666666666 --key a9e6e145f5df09500a58eef8575d49db --ikey 2b8a438742c851566f02d881b09d58c0
```

> **Note**: FMCOS resets the card's internal security status after each completed
> financial transaction (Phase 1 + Phase 2).  PIN verification must be repeated
> before each credit or purchase operation, even within the same RF session.

`--key` is the credit_key (16-byte 3DES key used to derive the process key).
`--ikey` is the internal_key used for TAC verification.

---

## 6. spend_wallet / spend_passbook - purchase (deduct funds)

Purchase key index is 8 (0-based index = 8 = 0x08).

Purchase (deduct) 50 units from the wallet:
```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos purchase --type wallet --id 08 --amount 50 --terminal 666666666666 --key eb18ce6986c820970e876219052ce0cf --ikey 2b8a438742c851566f02d881b09d58c0
```

Purchase 50 units from the passbook:
```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos purchase --type passbook --id 08 --amount 50 --terminal 666666666666 --key eb18ce6986c820970e876219052ce0cf --ikey 2b8a438742c851566f02d881b09d58c0
```

`--serial` (optional) sets the 4-byte transaction serial number; defaults to
`00000001` when omitted.

---

## 7. withdraw_money - cash withdrawal (NOT SUPPORTED)

Cash withdrawal uses INS=0x50 P1=0x02.  There is currently no `hf fmcos`
command for this operation.

---

## 8. pin_block - deliberately block the PIN

```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 11223344 -k
hf fmcos pinverify --id 00 --pin 11223344 -k
hf fmcos pinverify --id 00 --pin 11223344 -k
hf fmcos pinverify --id 00 --pin 11223344
```

After the error counter reaches zero the card blocks the PIN and returns
SW=`6983`.

---

## 9. pin_unblock - restore a blocked PIN

Unlock PIN key index is 5 (0-based index = 5 = 0x05).

```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinunblock --id 00 --pin 123456 --key d8f60fa2d791f3a658d27c05458243ed
```

---

## 10. online_debit - online transfer (NOT SUPPORTED)

Online debit uses INS=0x50 P1=0x05 (initialize) and INS=0x54 P1=0x03
(commit).  There is currently no `hf fmcos` command for this operation.

---

## 11. update_overdraft - set the overdraft limit

Overdraft key index is 11 (0-based index = 11 = 0x0B).

```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos overdraft --id 0B --limit 1000 --terminal 666666666666 --key 94f63c4fae5e4977d749928ad12bc128 --ikey 2b8a438742c851566f02d881b09d58c0
```

`--limit` is a 24-bit unsigned integer (maximum 16777215).

`--ikey` is the internal key (DTK, 16 bytes).  When provided the card's 4-byte TAC response is
verified using DES-CBC-MAC with `tac_key = XOR(ikey[0:8], ikey[8:16])` over:
`balance[4] | online_serial[2] | new_limit[3] | 0x07[1] | terminal[6] | date[4] | time[3]`

---

## 12. get_history - read transaction history

Read the most recent 10 records from the wallet loop file (SFI 0x18):

```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos history --fid 18
```

Read up to 20 records from the passbook loop file (SFI 0x19):

```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos history --fid 19 --count 20
```

Example output (after a credit of 1000 and a purchase of 50):

```
 # | Date       | Time     | Type         | Amount     | OD Limit | Serial | Terminal
---+------------+----------+--------------+------------+----------+--------+-------------------
 1 | 2026-05-24 | 14:30:22 | WL purchase  |         50 |        0 | 000002 | 66 66 66 66 66 66
 2 | 2026-05-24 | 14:28:05 | WL purchase  |       1000 |        0 | 000001 | 66 66 66 66 66 66
[+] 2 records
```

The SFI bytes (`18`, `19`) match the loop file IDs created in step 2e.  Loop file record 1 is
always the most recently written entry.

---

## 13. pin_change - change PIN using old PIN authorization

```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos pinchange --id 00 --old 123456 --new 13371337 -k
hf fmcos pinverify --id 00 --pin 13371337 -k
hf fmcos pinchange --id 00 --old 13371337 --new 123456 -k
hf fmcos pinverify --id 00 --pin 123456
```

---

## 14. pin_reset - set new PIN using change-PIN key (no old PIN needed)

Change PIN key index is 6 (0-based index = 6 = 0x06).

```
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos pinreset --id 00 --pin 13371337 --key fb487a6d1b7cbf1bf84c666b8338376e -k
hf fmcos pinverify --id 00 --pin 13371337 -k
hf fmcos pinchange --id 00 --old 13371337 --new 123456 -k
hf fmcos pinverify --id 00 --pin 123456
```

---

## Complete session (sequential)

The following block shows a full session in order: reset, setup, load money,
spend, and check balance.  Each sub-section starts a new session (field
activates) and ends when the last command drops the field.

> **Note**: `--space` and `--size` are hex - `--space 1500` = 5376 bytes, `--space 400` = 1024 bytes, `--size 0517` = 1303 bytes, `--size 0208` = 520 bytes.

```
# -- 1. Reset ----------------------------------------------------------------
hf fmcos select --id 3f00 -k
hf fmcos erase

# -- 2. Create ADF ------------------------------------------------------------
hf fmcos select --id 3f00 -k
hf fmcos createdir --id 3F01 --space 1500 --cperm F0 --eperm F0 --appid 95 --name 77616C6C657454657374 -k

# -- 3. Select ADF ------------------------------------------------------------
hf fmcos select --name 77616C6C657454657374 -k

# -- 4. Create keyfile --------------------------------------------------------
hf fmcos createkeyfile --id 0000 --space 400 --dfsid 95 --perm F0 -k

# -- 5. Write 13 keys (indexes 0-12) -----------------------------------------
hf fmcos key --op 01 --id 00 --usage F0 --type desenc    --change F4 --version 05 --algo 98 --key c4608b786af1992343e91a076670ae7c -k
hf fmcos key --op 01 --id 00 --usage F0 --type desdec    --change F4 --version 05 --algo 98 --key b8d4190c76856901fc686f36ab9b1ce0 -k
hf fmcos key --op 01 --id 00 --usage F0 --type desmac    --change F4 --version 05 --algo 98 --key 46a3ea8b254ee2749cc681050fd0dbcc -k
hf fmcos key --op 01 --id 00 --usage F0 --type internal  --change 02 --version 00 --algo 01 --key 2b8a438742c851566f02d881b09d58c0 -k
hf fmcos key --op 01 --id 00 --usage F0 --type lineprotect --change 02 --errcount 33 --key 8a021972bfec9d152ca9eb82d7d12c09 -k
hf fmcos key --op 01 --id 00 --usage F0 --type unlockpin   --change 02 --errcount 33 --key d8f60fa2d791f3a658d27c05458243ed -k
hf fmcos key --op 01 --id 00 --usage F0 --type changepin   --change 02 --errcount 33 --key fb487a6d1b7cbf1bf84c666b8338376e -k
hf fmcos key --op 01 --id 00 --usage F0 --type extauth  --change 02 --followup 44 --errcount 33 --key f49dc1ba1b4deb52647186bc59106c0d -k
hf fmcos key --op 01 --id 00 --usage F0 --type purchase --change 02 --version 00 --algo 01 --key eb18ce6986c820970e876219052ce0cf -k
hf fmcos key --op 01 --id 00 --usage F0 --type credit   --change 02 --version 00 --algo 01 --key a9e6e145f5df09500a58eef8575d49db -k
hf fmcos key --op 01 --id 00 --usage F0 --type debit    --change 02 --version 00 --algo 01 --key 97fb4eda4b5237035946ee62d325d909 -k
hf fmcos key --op 01 --id 00 --usage F0 --type overdraft --change 02 --version 00 --algo 01 --key 94f63c4fae5e4977d749928ad12bc128 -k
hf fmcos key --op 01 --id 00 --usage F0 --type pin --followup 01 --errcount 33 --key 123456 -k

# -- 6. Create loop files -----------------------------------------------------
hf fmcos createfile --id 0018 --type loop --size 0517 --rperm F0 --wperm EF --access FF -k
hf fmcos createfile --id 0019 --type loop --size 0517 --rperm F0 --wperm EF --access FF -k

# -- 7. Create balance files --------------------------------------------------
hf fmcos createfile --id 0002 --type wallet --size 0208 --rperm F0 --wperm 00 --access 18 -k
hf fmcos createfile --id 0001 --type wallet --size 0208 --rperm F0 --wperm 00 --access 19

# -- 8. Verify PIN ------------------------------------------------------------
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456

# -- 9. Credit wallet +1000, passbook +2000 -----------------------------------
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos credit --type wallet   --id 09 --amount 1000 --terminal 666666666666 --key a9e6e145f5df09500a58eef8575d49db --ikey 2b8a438742c851566f02d881b09d58c0 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos credit --type passbook --id 09 --amount 2000 --terminal 666666666666 --key a9e6e145f5df09500a58eef8575d49db --ikey 2b8a438742c851566f02d881b09d58c0

# -- 10. Check balances -------------------------------------------------------
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos balance --type wallet -k
hf fmcos balance --type passbook

# -- 11. Purchase (spend) from wallet then passbook ---------------------------
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos purchase --type wallet   --id 08 --amount 50 --terminal 666666666666 --key eb18ce6986c820970e876219052ce0cf --ikey 2b8a438742c851566f02d881b09d58c0 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos purchase --type passbook --id 08 --amount 50 --terminal 666666666666 --key eb18ce6986c820970e876219052ce0cf --ikey 2b8a438742c851566f02d881b09d58c0

# -- 12. Check balances again -------------------------------------------------
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos balance --type wallet -k
hf fmcos balance --type passbook

# -- 13. Update overdraft limit to 1000 --------------------------------------
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos pinverify --id 00 --pin 123456 -k
hf fmcos overdraft --id 0B --limit 1000 --terminal 666666666666 --key 94f63c4fae5e4977d749928ad12bc128 --ikey 2b8a438742c851566f02d881b09d58c0

# -- 14. Read transaction history ---------------------------------------------
hf fmcos select --name 77616C6C657454657374 -k
hf fmcos history --fid 18 -k
hf fmcos history --fid 19
```

---

## File operations walkthrough

That script demos binary/variable/loop file creation with line protection (none, MAC, MAC+enc),
plus application block/unblock.  Two DFs are created on the same card:

- **blockTest** (DF 3FFF, appid 0x94) - block/unblock target
- **fileTest** (DF 3F01, appid 0x95) - file read/write target

### Keys used

| Variable | Hex |
|---|---|
| `internal_key` | `659a500f0f1fce35b6884bdff966576a` |
| `line_protection_key` | `980093b4d77ff65f7476bf9019a80892` |
| `external_auth_key` | `7c3f149ed331b11211d2fb62e2df9637` |
| `line_protection_key_1` | `49439874a1f623fc5e14818365d34699` |
| `external_auth_key_1` | `da152a9a56def40a1386ca258788fea6` |
| `internal_key_1` | `bb4a314981b20ce696d6c1e1cda5820c` |
| `enc_external_auth_key` | `44ea0184094995a845b612522a8ab463` |

DF names as hex: `626c6f636b54657374` = `blockTest`, `66696c6554657374` = `fileTest`

---

### reset

```
hf fmcos select --id 3f00 -k
hf fmcos erase
```

---

### setup - create both DFs

#### blockTest DF (3FFF)

```
hf fmcos select --id 3f00 -k
hf fmcos createdir --id 3FFF --space 500 --cperm F0 --eperm F0 --appid 94 --name 626c6f636b54657374 -k
hf fmcos select --name 626c6f636b54657374 -k
hf fmcos createkeyfile --id 0001 --space 200 --dfsid 94 --perm F0 -k
```

Keys written into blockTest (keyfile 0001):

```
# Key 0 - lineprotect (line_protection_key_1)
hf fmcos key --op 01 --id 00 --usage F0 --type lineprotect --change 02 --errcount 33 --key 49439874a1f623fc5e14818365d34699 -k

# Key 1 - extauth (external_auth_key_1)
hf fmcos key --op 01 --id 00 --usage F0 --type extauth --change F0 --followup AA --errcount FF --key da152a9a56def40a1386ca258788fea6 -k

# Key 2 - internal (internal_key_1)
hf fmcos key --op 01 --id 00 --usage F0 --type internal --change F0 --version 00 --algo 01 --key bb4a314981b20ce696d6c1e1cda5820c -k
```

Seed binary file 0x0002 in blockTest:

```
hf fmcos createfile --id 0002 --type bin --size 50 --rperm F0 --wperm F0 --access FF -k
hf fmcos select --id 0002 -k
hf fmcos writebinary --p1 00 --p2 00 --data 62696e66696c655f626c6f636b5f74657374
```

(`62696e66696c655f626c6f636b5f74657374` = ASCII `binfile_block_test`)

#### fileTest DF (3F01)

```
hf fmcos select --id 3f00 -k
hf fmcos createdir --id 3F01 --space 1500 --cperm F0 --eperm F0 --appid 95 --name 66696c6554657374 -k
hf fmcos select --name 66696c6554657374 -k
hf fmcos createkeyfile --id 0001 --space 200 --dfsid 95 --perm F0 -k
```

Keys written into fileTest (keyfile 0001).  Keys 2 and 3 are written with MAC+enc line protection
(`--prot enc --authkey <external_auth_key>`):

```
# Key 0 - extauth (external_auth_key), unprotected write
hf fmcos key --op 01 --id 00 --usage F0 --type extauth --change F0 --followup AA --errcount FF --key 7c3f149ed331b11211d2fb62e2df9637 -k

# Key 1 - internal (internal_key), unprotected write
hf fmcos key --op 01 --id 00 --usage F0 --type internal --change F0 --version 00 --algo 01 --key 659a500f0f1fce35b6884bdff966576a -k

# Key 2 - lineprotect (line_protection_key), written with enc protection
hf fmcos key --op 01 --id 00 --usage F0 --type lineprotect --change F0 --errcount FF --key 980093b4d77ff65f7476bf9019a80892 --authkey 7c3f149ed331b11211d2fb62e2df9637 --prot enc -k

# Key 3 (slot 02) - extauth (enc_external_auth_key), written with enc protection
hf fmcos key --op 01 --id 02 --usage F0 --type extauth --change F0 --followup AA --errcount FF --key 44ea0184094995a845b612522a8ab463 --authkey 7c3f149ed331b11211d2fb62e2df9637 --prot enc -k
```

Files created in fileTest.  Three trios: unprotected (`--access FF`), MAC (`--access 7F --prot mac`),
MAC+enc (`--access 7F --prot enc`).  `--access 7F` = protection required, use key 0.

```
# Binary files
hf fmcos createfile --id 0002 --type bin --size 50 --rperm F0 --wperm F0 --access FF -k
hf fmcos createfile --id 0003 --type bin --size 50 --rperm F0 --wperm F0 --access 7F --prot mac -k
hf fmcos createfile --id 0004 --type bin --size 50 --rperm F0 --wperm F0 --access 7F --prot enc -k

# Variable-length record files
hf fmcos createfile --id 0006 --type var --size 50 --rperm F0 --wperm F0 --access FF -k
hf fmcos createfile --id 0007 --type var --size 50 --rperm F0 --wperm F0 --access 7F --prot mac -k
hf fmcos createfile --id 0008 --type var --size 50 --rperm F0 --wperm F0 --access 7F --prot enc -k

# Loop (cyclic) files  --size 210 = 0x210 = 528 bytes
# space = record_count*(record_len+1)+8; e.g. 5 records x (0x50+1) + 8 = 0x19D
hf fmcos createfile --id 000A --type loop --size 210 --rperm F0 --wperm F0 --access FF -k
hf fmcos createfile --id 000B --type loop --size 210 --rperm F0 --wperm F0 --access 7F --prot mac -k
hf fmcos createfile --id 000C --type loop --size 210 --rperm F0 --wperm F0 --access 7F --prot enc
```

---

### write_binary

```
hf fmcos select --id 3f01 -k
hf fmcos select --id 0002 -k
hf fmcos writebinary --p1 00 --p2 00 --data 111213141516171819101a1b1c1d1e1f -k

hf fmcos select --id 0003 -k
hf fmcos writebinary --p1 00 --p2 00 --data 212223242526272829202a2b2c2d2e2f --prot mac --key 980093b4d77ff65f7476bf9019a80892 -k

hf fmcos select --id 0004 -k
hf fmcos writebinary --p1 00 --p2 00 --data 313233343536373839303a3b3c3d3e3f --prot enc --key 980093b4d77ff65f7476bf9019a80892
```

---

### write_loop (APPEND RECORD)

```
hf fmcos select --id 3f01 -k
hf fmcos select --id 000a -k
hf fmcos append --fid 0a --data 919293949596979899909a9b9c9d9e9f -k

hf fmcos select --id 000b -k
hf fmcos append --fid 0b --data a1a2a3a4a5a6a7a8a9a0aaabacadaeaf --prot mac --key 980093b4d77ff65f7476bf9019a80892 -k

hf fmcos select --id 000c -k
hf fmcos append --fid 0c --data b1b2b3b4b5b6b7b8b9b0babbbcbdbebf --prot enc --key 980093b4d77ff65f7476bf9019a80892
```

---

### write_record (UPDATE RECORD)

P2 encodes the SFI: `(file_id & 0x1F) << 3 | 4`.  The CLI `--fid` takes the raw file ID byte
(1-30) and encodes P2 automatically.

Variable-length files require `--tlv` so the data is wrapped as `00[len][data]`.

```
hf fmcos select --id 3f01 -k
hf fmcos select --id 0006 -k
hf fmcos writerecord --rec 1 --fid 06 --data 515253545556575859505a5b5c5d5e5f --tlv -k

hf fmcos select --id 0007 -k
hf fmcos writerecord --rec 1 --fid 07 --data 616263646566676869606a6b6c6d6e6f --tlv --prot mac --key 980093b4d77ff65f7476bf9019a80892 -k

hf fmcos select --id 0008 -k
hf fmcos writerecord --rec 1 --fid 08 --data 717273747576777879707a7b7c7d7e7f --tlv --prot enc --key 980093b4d77ff65f7476bf9019a80892
```

---

### read_binary

For MAC-protected reads the card appends a 4-byte MAC before the SW; the CLI strips it automatically.

```
hf fmcos select --id 3f01 -k
hf fmcos select --id 0002 -k
hf fmcos readbinary --p1 00 --p2 00 --len 16 -k

hf fmcos select --id 0003 -k
hf fmcos readbinary --p1 00 --p2 00 --len 16 --prot mac --key 980093b4d77ff65f7476bf9019a80892 -k

hf fmcos select --id 0004 -k
hf fmcos readbinary --p1 00 --p2 00 --len 16 --prot enc --key 980093b4d77ff65f7476bf9019a80892
```

---

### read_record

Variable-length files need `--tlv`; the CLI requests 2 extra bytes and strips the `00[len]` prefix before printing.

```
hf fmcos select --id 3f01 -k
hf fmcos readrecord --rec 01 --fid 06 --len 16 --tlv -k
hf fmcos readrecord --rec 01 --fid 07 --len 16 --tlv --prot mac --key 980093b4d77ff65f7476bf9019a80892 -k
hf fmcos readrecord --rec 01 --fid 08 --len 16 --tlv --prot enc --key 980093b4d77ff65f7476bf9019a80892
```

---

### read_loop

Loop files use the same READ RECORD command; `--rec 01` reads the most recently appended record.

```
hf fmcos select --id 3f01 -k
hf fmcos readrecord --rec 01 --fid 0a --len 16 -k
hf fmcos readrecord --rec 01 --fid 0b --len 16 --prot mac --key 980093b4d77ff65f7476bf9019a80892 -k
hf fmcos readrecord --rec 01 --fid 0c --len 16 --prot enc --key 980093b4d77ff65f7476bf9019a80892
```

---

### card_block / app_block

Permanent application block

```
hf fmcos select --name 626c6f636b54657374 -k
hf fmcos block --app --perm --key 49439874a1f623fc5e14818365d34699
```

Temporary application block:

```
hf fmcos select --name 626c6f636b54657374 -k
hf fmcos block --app --key 49439874a1f623fc5e14818365d34699
```

---

### app_unblock

After a block the app cannot be selected normally (SELECT returns an error SW), but the DF is still
addressed.  Send unblock while the field is still on from the failed select, then re-select:

```
hf fmcos select --name 626c6f636b54657374 -k
hf fmcos unblock --key 49439874a1f623fc5e14818365d34699 -k
hf fmcos select --name 626c6f636b54657374 -k
hf fmcos select --id 0002 -k
hf fmcos readbinary --p1 00 --p2 00 --len 16
```
