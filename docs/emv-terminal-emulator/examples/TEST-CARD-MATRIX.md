# Test Card Matrix — EMV Terminal Emulator Lab

Use this checklist when validating scheme profiles and host-sim. **Authorized test cards only.**

## Interac (RID A000000277)

| Case | AID | Channel | PIN | Profile | Expected outcome | MAN IDs |
|------|-----|---------|-----|---------|------------------|---------|
| TC01 approve online | A0000002771010 | Contact | 1111 | interac | ARQC → host-sim → approved_online | MAN-V2-001, 017 |
| TC01 Flash CL | A0000002771010 | Contactless | — | interac | ARQC, no VERIFY | MAN-V2-016, 147 |
| TC02 wrong PIN | A0000002771010 | Contact | 2222 (wrong) | interac | declined (AAC) | MAN-V2-023 |
| TC03 PIN OK | A0000002771010 | Contact | 3333 | interac | ARQC or TC per amount | MAN-V2-148 |
| TC04 decline | A0000002771010 | Contact | 4444 | interac | declined | MAN-V2-149 |

**CVM list contact TC01:** `440301030203`  
**ARPC-RC contact:** `8840`  
**Keys:** [interac_test_keys.json](./interac_test_keys.json)

---

## Visa

| Case | AID | Channel | Profile | Expected | MAN IDs |
|------|-----|---------|---------|----------|---------|
| qVSDC CL | A0000000031010 | Contactless | visa | TC or ARQC | MAN-V2-012 |
| VSDC contact | A0000000031010 | Contact | visa | GEN AC1 TC/ARQC | MAN-V2-012 |
| MSD fallback | (MSD card) | CL | visa | MSD path warning | MAN-V2-111 |

---

## Mastercard

| Case | AID | Channel | Profile | Expected | MAN IDs |
|------|-----|---------|---------|----------|---------|
| M/Chip CL | A0000000043060 | Contactless | mc | ARQC typical | MAN-V2-013 |
| M/Chip contact | A0000000041010 | Contact | mc | GET CHALLENGE + AC1 | MAN-V2-013 |

---

## Regression Commands

```bash
# Interac contact full path
./pm3 -- emv terminal run -satjw -j --profile interac --host-sim --pin 1111 -o /tmp/interac_tc01.json

# Interac contactless Flash
./pm3 -- emv terminal run -satj --profile interac --qvsdc --host-sim -o /tmp/interac_cl.json

# Profile auto
./pm3 -- emv terminal run -j --profile auto -o /tmp/auto.json

# Golden (no card)
./pm3 -- emv terminal test --golden
```

---

## Recording New Matrix Rows

1. `emv scan -at card.json` — anonymize before commit
2. `emv terminal run --record-apdu trace.json ...`
3. Add fixture under `client/src/emv/test/fixtures/<name>/`
4. Update this matrix with date and operator initials
