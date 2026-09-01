# Proxmark5 BWM — Battery, BLE & WiFi

The **Battery / Wireless Module (BWM)** adds a battery + charger and an ESP32 that
bridges the Proxmark5 to **BLE** and **WiFi**. Everything below is **PM5-only** and
is compiled in with the BWM platform extra.

## Contents

- [Build](#build)
- [1. Battery / BWM control](#1-battery--bwm-control)
- [2. BLE](#2-ble)
- [3. WiFi](#3-wifi)
- [Notes](#notes)

---

## Build

Build the firmware with the BWM extra — this enables `WITH_BWM_FORWARD` (the
UART4 / `app_com` driver, battery telemetry, and BLE/WiFi forwarding):

```
make clean
make PLATFORM=PM5 PLATFORM_EXTRAS=BWM
make client        # or your usual client build
```

Or set it persistently in `Makefile.platform`:

```
PLATFORM=PM5
PLATFORM_EXTRAS=BWM
```

> [!NOTE]
> Without `PLATFORM_EXTRAS=BWM` the firmware builds a plain PM5 with **none** of the
> battery / BLE / WiFi commands below.

---

## 1. Battery / BWM control

These run over any active connection — USB, BLE, or WiFi.

### `hw status` — battery + charger telemetry

```
[usb] pm3 --> hw status
```

The **Battery / BWM** section reports the **AW32001** charger (power path, fault,
charge state, input limit, charge current/voltage/enable) and the **BQ27427** fuel
gauge (state-of-charge %, voltage, current, remaining/full capacity, temperature,
health).

### `hw bwmsetcap` — set fuel-gauge design capacity

Program the BQ27427 **Design Capacity** for the fitted cell.

| Argument      | Description                            |
| ------------- | -------------------------------------- |
| `--cap <mAh>` | Design capacity in mAh (default `500`) |

```
hw bwmsetcap             # set design capacity to the default 500 mAh
hw bwmsetcap --cap 500   # set design capacity to 500 mAh
```

> [!WARNING]
> Run this **once** after fitting or replacing the battery. Running it repeatedly
> triggers a gauge config-update and disrupts the Impedance Track learning cycle.

### `hw bwmcharge` — enable/disable charging (one-shot)

Clears/sets the AW32001E charge-enable bit (`CEB`, `REG01[3]`).

| Argument | Description                          |
| -------- | ------------------------------------ |
| `--off`  | Disable charging (default is enable) |

```
hw bwmcharge          # enable charging
hw bwmcharge --off    # disable charging
```

> [!NOTE]
> **One-shot:** the charger watchdog reverts this after ~160 s unless serviced, so
> charging may stop on its own. Use it to nudge a top-up.

### `hw bwmvchg` — set charge-voltage limit

Sets the AW32001E charge-voltage regulation target (`VBAT_REG`, `REG04[7:2]`).
Lowering it below 4.2 V reduces top-of-charge stress and extends cell life.

| Argument    | Description                                                  |
| ----------- | ----------------------------------------------------------- |
| `--mv <mV>` | Charge voltage in mV (default `4100`, clamped `3600`..`4200`) |

```
hw bwmvchg            # set the default 4100 mV target (-> 4.095 V)
hw bwmvchg --mv 4200  # set 4200 mV
```

The value snaps to the nearest 15 mV hardware step, and the command reports the
voltage actually applied (e.g. `4100` → `4.095 V`; `4110` would be the next step).

> [!NOTE]
> The firmware applies the `4100` mV default (4.095 V) at **every boot** — the
> AW32001E's own power-on default is 4.2 V. It is a runtime register write, but
> because the boot config disables the charger watchdog the value then holds until
> the next power cycle (which re-applies it), so you don't need to re-run it per
> charge.

### `hw bwmautooff` — auto power-off on USB unplug

Toggles automatic power-off when the PM5 is unplugged from USB. **Default is `on`:**
the board powers down after USB is removed so a BWM-equipped PM5 doesn't silently
drain the battery. Button power-on is unaffected.

| Argument | Description                     |
| -------- | ------------------------------- |
| `--on`   | Enable auto power-off (default) |
| `--off`  | Disable auto power-off          |

```
hw bwmautooff --off   # disable auto power-off
hw bwmautooff --on    # re-enable auto power-off
```

> [!NOTE]
> **Runtime only** — resets to `on` at each boot. Disable it for an uninterrupted
> move from USB to standalone / BLE / WiFi use on battery. For regular standalone /
> BLE / WiFi use on battery, one can just turn it on when needed, no need to touch
> that setting.

---

## 2. BLE

The BWM advertises as:

| Property  | Value                                          |
| --------- | ---------------------------------------------- |
| Name      | `Proxmark5`                                    |
| Address   | `58:2A:BD:34:F1:82` (LE Public, Espressif OUI) |
| Service   | `0xAE86` (16-bit)                              |
| Data char | `0xAE88` (`WRITE` / `WRITE_NO_RSP` / `NOTIFY`) |
| Security  | none (plaintext GATT, no bonding)              |

> [!NOTE]
> `58:2A:BD:34:F1:82` is just an example — each module has its own address. Find
> yours with `btmgmt find`, or use the bridge's name-scan (`-n Proxmark5`), which
> avoids needing the address at all.

There are two ways to connect: a **native transport** (Linux) and a **cross-platform
Python bridge** (Linux / macOS / Windows / WSL / iOS).

### 2.1 Native BLE transport — Linux only, no bridge

Uses a raw L2CAP/ATT socket — no `bleak`, no `bluetoothd` daemon dependency.
Needs the Bluetooth dev headers at build time:

```
sudo apt install libbluetooth-dev
make client            # rebuild so HAVE_BLUEZ is picked up
```

Then connect by address:

```
./pm3 -p ble:58:2A:BD:34:F1:82
```

On success you'll see e.g. `BLE connected, MTU 512, char handle 0x0014`.

### 2.2 BLE bridge — cross-platform (`pm5_ble_bridge.py`)

Requires Python 3 and `bleak` (`pip install bleak`). It bridges the BWM's BLE SPP
to a PTY or a TCP socket that the pm3 client then opens.

> [!IMPORTANT]
> Run the bridge on the machine that has the **Bluetooth radio**.

Common options:

| Option                | Description                                       |
| --------------------- | ------------------------------------------------- |
| `-n, --name <name>`   | Advertised name to scan for (default `Proxmark5`) |
| `-a, --address <mac>` | Connect by address instead of scanning by name    |
| `--dump`              | Hexdump traffic both directions (debug)           |
| `-v, --verbose`       | Verbose logging                                   |

**a) PTY** (Linux/macOS) — simplest, one process:

```
python3 pm5_ble_bridge.py --pty        # default link /tmp/pm5-ble
./pm3 -p /tmp/pm5-ble
```

**b) TCP listener** — bridge listens, client connects in:

```
python3 pm5_ble_bridge.py --tcp 7777   # or HOST:PORT
./pm3 -p tcp:127.0.0.1:7777
```

**c) Outbound TCP** (`--connect`) — bridge dials **out** to a listener. Pairs with
the client's `--wait` mode ([2.3](#23-client-listen-mode--pm3----wait)) and crosses
the WSL2 NAT boundary:

```
python3 pm5_ble_bridge.py --connect 127.0.0.1:7777
```

**d) Relay only** (no BLE) — TCP listener ↔ PTY, for chaining:

```
python3 pm5_ble_bridge.py --relay --listen 7777 --pty
```

> [!NOTE]
> **Windows / WSL:** run the bridge on Windows (where the radio is) with `py`, and
> let only TCP cross into WSL.

### 2.3 Client listen mode — `pm3 … --wait`

With a `tcp:` port, `--wait` makes the client **bind / listen** and wait for an
incoming connection instead of dialing out. Start the client first, then point the
bridge at it with `--connect`. This removes the relay/PTY hop.

```
# window 1 — client listens (blocks until something connects)
./pm3 -p tcp:127.0.0.1:7777 --wait

# window 2 — bridge dials in (on the machine with the radio)
python3 pm5_ble_bridge.py --connect 127.0.0.1:7777
```

> [!NOTE]
> For a plain **serial** port, `--wait` keeps its original meaning: wait ~20 s for
> the device node to appear.

---

## 3. WiFi (STA + TCP server)

`hw bwmwifi` joins your WiFi network as a **station** and starts a **TCP server** on
the BWM. You then connect the client over plain TCP. Run `hw bwmwifi` over an
existing link (USB, or an existing BLE connection). Use `--status` to check an
existing connection without touching the config.

### 3.1 Bring up WiFi

```
hw bwmwifi --ssid <ssid> [--pwd <password>] [--port <n>] [--hostname <name>]
```

| Argument            | Description                              |
| ------------------- | ---------------------------------------- |
| `--ssid <ssid>`     | WiFi network to join **(required)**      |
| `--pwd <password>`  | WiFi password (omit for an open network) |
| `--port <dec>`      | TCP server listen port (default `7777`)  |
| `--hostname <name>` | DHCP hostname (default `Proxmark5`)      |
| `--status`          | Show current WiFi connection state + IP (no reconnect) |
| `--stop`            | Tear down WiFi and return to BLE-only     |

```
hw bwmwifi --ssid Home --pwd secret
hw bwmwifi --ssid Home --pwd secret --port 9000 --hostname pm5-lab
hw bwmwifi --ssid OpenGuestWiFi                       # open network
```

The join can take ~15 s. On success it prints the assigned IP and the connect
strings:

```
[+] BWM on WiFi at 192.168.1.77
[?] Connect with: pm3 -p tcp:192.168.1.77:7777
[?] Or by name (router-dependent): pm3 -p tcp:pm5-lab:7777
```

### 3.2 Connect over WiFi

```
./pm3 -p tcp:192.168.1.77:7777
```

> [!NOTE]
> Connecting **by hostname** works only if your router registers DHCP client names
> in its local DNS (some need a suffix like `<name>.lan` or `<name>.home`; some
> don't do it at all). There is **no mDNS / `.local`** responder, so the IP is the
> reliable path.

### 3.3 Check WiFi status — `hw bwmwifi --status`

Queries the BWM's current connection state and IP **without** reconnecting or
changing the WiFi config. Handy to confirm a join actually completed — the
bring-up occasionally reports failure if the DHCP lease lands late, even though
the STA connected a moment later.

```
hw bwmwifi --status
```

```
[+] BWM WiFi connected, IP 192.168.1.77
[?] Connect with: pm3 -p tcp:192.168.1.77:<port>
```

> [!NOTE]
> "Connected" here means the STA has a DHCP lease (a usable IP). If it reports
> not connected right after a bring-up, wait a few seconds and re-check — the
> lease may still be in flight.

### 3.4 Stop WiFi — `hw bwmwifi --stop`

Tears down the WiFi station and TCP server and returns the BWM to **BLE-only**.
Run it over an existing link (USB or BLE); it does not need any other arguments.

```
hw bwmwifi --stop
```

> [!NOTE]
> If you issue `--stop` over the **WiFi** connection itself, that connection
> drops as the TCP server goes away — reconnect over USB or BLE afterwards.

---

## Notes

- Bulk transfers over BLE/WiFi (`lf read`, `mem dump`, trace download) are paced by
  the BWM flow control so they don't drop — expect them to be **slower than USB**.
- COTAG / large realtime LF reads use a separate streaming
  path and are **not** covered by this flow control.
- All BWM commands are **PM5-only** and require the firmware built with
  `PLATFORM_EXTRAS=BWM`.
