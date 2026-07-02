# SPEC: Connectivity

## Purpose

USB and protocol connectivity between host client and PM3 for EMV terminal sessions.

## Scope

USB serial, existing `SendCommandNG` path, ISO7816 over HF and smartcard

## Functional Requirements

REQ-CONN-001: Terminal sessions use standard PM3 USB connection; no new drivers.

REQ-CONN-002: Contactless path: client → `Iso7816ExchangeEx(CC_CONTACTLESS)` → firmware ISO14443-4.

REQ-CONN-003: Contact path: `CC_CONTACT` → smartcard I2C when compiled with SMARTCARD.

REQ-CONN-004: TCP bridge (`pm3 --port`) shall support terminal commands identically to local USB.

REQ-CONN-005: Session abort via pm3 button sends signal; client drops field and saves partial session.

## Data Flow

Existing frame format per [doc/new_frame_format.md](../../doc/new_frame_format.md).

No new NG command required for MVP.

## Failure Handling

USB stall → `PM3_EIO`; operator reconnects and restarts session.

## Acceptance Criteria

AC-CONN-001: Terminal run works over USB and TCP bridge with same outcome.

## Test Coverage Notes

MAN-CONN-001: TCP bridge terminal smoke test
