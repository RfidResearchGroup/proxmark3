#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# pm5_ble_bridge.py
#
# Bridge the Proxmark5 Battery Wireless Module (BWM) BLE SPP to a serial-like
# endpoint, so the stock proxmark3 client talks over BLE with no client changes.
#
# Roles:
#   BLE side (has the radio):
#     --pty [LINK]        BLE <-> local PTY            pm3 /tmp/pm5-ble     (POSIX)
#     --tcp [HOST:]PORT   BLE <-> inbound TCP listener pm3 tcp:host:port
#     --connect HOST:PORT BLE <-> OUTBOUND TCP client  (dials a --relay)     [NEW]
#   Relay side (NO radio, no bleak needed):
#     --relay --listen PORT [--pty LINK]
#                         TCP listener (accepts a --connect bridge) <-> PTY   [NEW]
#
# WSL2 without admin, NAT networking:  Windows can only make OUTBOUND
# connections, but by default localhostForwarding lets Windows reach a WSL
# listener at 127.0.0.1:PORT.  So:
#     WSL:      python3 pm5_ble_bridge.py --relay --listen 7777 --pty /tmp/pm5-ble
#     Windows:  py      pm5_ble_bridge.py -n Proxmark5 --connect 127.0.0.1:7777
#     WSL:      ./pm3 /tmp/pm5-ble
# If localhostForwarding is off, point --connect at WSL's own IP
# (WSL: `hostname -I`) instead of 127.0.0.1.
#
# BLE roles require:  pip install bleak     (the --relay role does NOT)
# -----------------------------------------------------------------------------

import argparse
import asyncio
import os
import sys
import signal

BT_BASE = "-0000-1000-8000-00805f9b34fb"
DEF_SVC = "ae86"
DEF_CHR = "ae88"
DEF_NAME = "Proxmark5"


def uuid16_to_128(u: str) -> str:
    u = u.strip().lower()
    if len(u) == 4:
        return "0000" + u + BT_BASE
    return u


def log(verbose, *a):
    if verbose:
        print("[bridge]", *a, file=sys.stderr, flush=True)


def hexdump(tag: str, data: bytes, width: int = 16):
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"[{tag}] {off:04x}  {hexs:<{width*3}}  {ascii_}",
              file=sys.stderr, flush=True)


class BleLink:
    def __init__(self, args):
        self.args = args
        self.svc = uuid16_to_128(args.service)
        self.chr = uuid16_to_128(args.char)
        self.client = None
        self.chunk = 20
        self.tx_q = asyncio.Queue()
        self.sink = None
        self.dump = getattr(args, "dump", False)
        self._writer_task = None
        self._closing = False

    async def connect(self):
        from bleak import BleakClient, BleakScanner

        target = self.args.address
        if target is None:
            log(self.args.verbose, f"scanning for name '{self.args.name}' "
                                   f"(svc {self.args.service}) ...")
            dev = await BleakScanner.find_device_by_filter(
                lambda d, ad: (
                    (d.name or "") == self.args.name
                    or self.svc in [s.lower() for s in (ad.service_uuids or [])]
                ),
                timeout=self.args.scan_timeout,
            )
            if dev is None:
                raise RuntimeError(
                    f"no BWM found (name '{self.args.name}' / svc {self.args.service}) "
                    f"in {self.args.scan_timeout}s")
            target = dev.address
            log(self.args.verbose, f"found {dev.name!r} @ {target}")

        self.client = BleakClient(target, disconnected_callback=self._on_disc)
        await self.client.connect()
        if not self.client.is_connected:
            raise RuntimeError(f"failed to connect to {target}")

        try:
            mtu = self.client.mtu_size
            if isinstance(mtu, int) and mtu > 23:
                self.chunk = mtu - 3
        except Exception:
            pass
        log(self.args.verbose, f"connected; write chunk = {self.chunk} bytes")

        await self.client.start_notify(self.chr, self._on_notify)
        self._writer_task = asyncio.create_task(self._tx_loop())
        return target

    def _on_disc(self, _client):
        if not self._closing:
            print("[bridge] device disconnected", file=sys.stderr, flush=True)
        try:
            self.tx_q.put_nowait(None)
        except Exception:
            pass

    def _on_notify(self, _sender, data: bytearray):
        if data and self.dump:
            hexdump("dev->host", bytes(data))
        if self.sink is not None and data:
            self.sink(bytes(data))

    def submit(self, data: bytes):
        if data and self.dump:
            hexdump("host->dev", data)
        self.tx_q.put_nowait(data)

    async def _tx_loop(self):
        resp = self.args.write_response
        while True:
            data = await self.tx_q.get()
            if data is None:
                break
            if self.client is None or not self.client.is_connected:
                break
            try:
                for i in range(0, len(data), self.chunk):
                    await self.client.write_gatt_char(
                        self.chr, data[i:i + self.chunk], response=resp)
            except Exception as e:
                print(f"[bridge] BLE write error: {e}", file=sys.stderr, flush=True)
                break

    async def close(self):
        self._closing = True
        try:
            self.tx_q.put_nowait(None)
        except Exception:
            pass
        if self._writer_task:
            try:
                await asyncio.wait_for(self._writer_task, timeout=1.0)
            except Exception:
                pass
        if self.client and self.client.is_connected:
            try:
                await self.client.stop_notify(self.chr)
            except Exception:
                pass
            try:
                await self.client.disconnect()
            except Exception:
                pass


def open_pty(link_path):
    import termios
    import tty
    master_fd, slave_fd = os.openpty()
    slave_name = os.ttyname(slave_fd)
    tty.setraw(slave_fd, termios.TCSANOW)  # binary-clean: no CR/LF xlate, no echo
    if link_path:
        try:
            if os.path.islink(link_path) or os.path.exists(link_path):
                os.remove(link_path)
        except OSError:
            pass
        os.symlink(slave_name, link_path)
    return master_fd, slave_fd, slave_name


async def run_pty(link: BleLink, args):
    master_fd, slave_fd, slave_name = open_pty(args.pty)
    loop = asyncio.get_running_loop()
    link.sink = lambda b: os.write(master_fd, b)

    def on_master_readable():
        try:
            data = os.read(master_fd, 4096)
        except OSError:
            return
        if data:
            link.submit(data)

    loop.add_reader(master_fd, on_master_readable)
    shown = args.pty if args.pty else slave_name
    print(f"[bridge] PTY ready: {slave_name}")
    if args.pty:
        print(f"[bridge] symlink : {args.pty}")
    print(f"[bridge] connect with:  pm3 {shown}")

    stop = asyncio.Event()
    _install_signals(stop)
    await stop.wait()

    loop.remove_reader(master_fd)
    if args.pty:
        try:
            os.remove(args.pty)
        except OSError:
            pass
    os.close(master_fd)
    os.close(slave_fd)


async def run_tcp(link: BleLink, args):
    host, port = args.tcp
    state = {"writer": None}
    link.sink = lambda b: (state["writer"].write(b)
                           if state["writer"] and not state["writer"].is_closing()
                           else None)

    async def handle(reader, writer):
        peer = writer.get_extra_info("peername")
        if state["writer"] is not None:
            writer.close()
            return
        state["writer"] = writer
        print(f"[bridge] client connected: {peer}", file=sys.stderr, flush=True)
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                link.submit(data)
        except Exception:
            pass
        finally:
            state["writer"] = None
            try:
                writer.close()
            except Exception:
                pass
            print(f"[bridge] client gone: {peer}", file=sys.stderr, flush=True)

    server = await asyncio.start_server(handle, host, port)
    addr = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"[bridge] TCP listening on {addr}")
    print(f"[bridge] connect with:  pm3 tcp:{host}:{port}")

    stop = asyncio.Event()
    _install_signals(stop)
    async with server:
        await asyncio.wait(
            [asyncio.create_task(server.serve_forever()),
             asyncio.create_task(stop.wait())],
            return_when=asyncio.FIRST_COMPLETED)


async def run_connect(link: BleLink, args):
    host, port = args.connect
    state = {"writer": None}
    link.sink = lambda b: (state["writer"].write(b)
                           if state["writer"] and not state["writer"].is_closing()
                           else None)

    stop = asyncio.Event()
    _install_signals(stop)
    print(f"[bridge] will dial relay at {host}:{port} (outbound)")

    while not stop.is_set():
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except Exception as e:
            log(args.verbose, f"relay {host}:{port} not up ({e}); retrying in 1s")
            try:
                await asyncio.wait_for(stop.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            continue

        state["writer"] = writer
        print(f"[bridge] connected to relay {host}:{port}", file=sys.stderr, flush=True)
        try:
            while not stop.is_set():
                data = await reader.read(4096)
                if not data:
                    break
                link.submit(data)
        except Exception as e:
            log(args.verbose, f"relay read error: {e}")
        finally:
            state["writer"] = None
            try:
                writer.close()
            except Exception:
                pass
            print("[bridge] relay disconnected", file=sys.stderr, flush=True)
        # loop and re-dial (relay/pm3 restarted) while BLE stays connected


async def run_relay(args):
    host = args.listen_host
    port = args.listen_port
    master_fd, slave_fd, slave_name = open_pty(args.pty)
    loop = asyncio.get_running_loop()
    state = {"writer": None}

    # PTY (pm3) -> current bridge socket
    def on_master_readable():
        try:
            data = os.read(master_fd, 4096)
        except OSError:
            return
        w = state["writer"]
        if data and args.dump:
            hexdump("pm3->dev", data)
        if data and w is not None and not w.is_closing():
            w.write(data)

    loop.add_reader(master_fd, on_master_readable)

    async def handle(reader, writer):
        peer = writer.get_extra_info("peername")
        if state["writer"] is not None:
            writer.close()
            return
        state["writer"] = writer
        print(f"[relay] bridge connected: {peer}", file=sys.stderr, flush=True)
        try:
            while True:
                data = await reader.read(4096)   # bridge -> PTY (pm3)
                if not data:
                    break
                if args.dump:
                    hexdump("dev->pm3", data)
                os.write(master_fd, data)
        except Exception:
            pass
        finally:
            state["writer"] = None
            try:
                writer.close()
            except Exception:
                pass
            print(f"[relay] bridge gone: {peer}", file=sys.stderr, flush=True)

    server = await asyncio.start_server(handle, host, port)
    addr = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"[relay] listening on {addr} (for the Windows --connect bridge)")
    print(f"[relay] PTY ready: {slave_name}")
    if args.pty:
        print(f"[relay] symlink : {args.pty}")
    print(f"[relay] connect with:  pm3 {args.pty if args.pty else slave_name}")

    stop = asyncio.Event()
    _install_signals(stop)
    async with server:
        await asyncio.wait(
            [asyncio.create_task(server.serve_forever()),
             asyncio.create_task(stop.wait())],
            return_when=asyncio.FIRST_COMPLETED)

    loop.remove_reader(master_fd)
    if args.pty:
        try:
            os.remove(args.pty)
        except OSError:
            pass
    os.close(master_fd)
    os.close(slave_fd)


def _install_signals(stop_event: asyncio.Event):
    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, stop_event.set)
        except (NotImplementedError, RuntimeError):
            pass


def parse_hostport(spec: str, default_host="127.0.0.1"):
    if ":" in spec:
        h, p = spec.rsplit(":", 1)
        return (h or default_host, int(p))
    return (default_host, int(spec))


async def amain(args):
    if args.relay:
        await run_relay(args)
        return 0

    link = BleLink(args)
    try:
        await link.connect()
    except Exception as e:
        print(f"[bridge] {e}", file=sys.stderr, flush=True)
        return 2
    try:
        if args.connect is not None:
            await run_connect(link, args)
        elif args.tcp is not None:
            await run_tcp(link, args)
        else:
            await run_pty(link, args)
    finally:
        await link.close()
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Bridge Proxmark5 BWM BLE SPP to a serial-like endpoint for pm3.")
    # BLE options (ignored in --relay role)
    ap.add_argument("-a", "--address", metavar="MAC/UUID",
                    help="BLE address (Linux/Win MAC, macOS UUID). Skips scan.")
    ap.add_argument("-n", "--name", default=DEF_NAME,
                    help=f"advertised name to scan for (default {DEF_NAME!r})")
    ap.add_argument("--service", default=DEF_SVC, help=f"SPP service UUID (default {DEF_SVC})")
    ap.add_argument("--char", default=DEF_CHR, help=f"SPP data char UUID (default {DEF_CHR})")
    ap.add_argument("--scan-timeout", type=float, default=10.0)
    ap.add_argument("--write-response", action="store_true",
                    help="write-WITH-response (slower, safer flow control)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--dump", action="store_true",
                    help="hex-dump traffic both directions to stderr (diagnostics)")

    # roles / backends
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--pty", nargs="?", const="/tmp/pm5-ble", metavar="LINK",
                   help="BLE<->PTY (default backend). Optional symlink path "
                        "(default /tmp/pm5-ble).")
    g.add_argument("--tcp", metavar="[HOST:]PORT", type=parse_hostport,
                   help="BLE<->inbound TCP listener.")
    g.add_argument("--connect", metavar="HOST:PORT", type=parse_hostport,
                   help="BLE<->OUTBOUND TCP client; dials a --relay (WSL no-admin path).")

    # relay role (no BLE)
    ap.add_argument("--relay", action="store_true",
                    help="Relay role: TCP listener <-> PTY. No BLE. Needs --listen.")
    ap.add_argument("--listen", metavar="[HOST:]PORT",
                    type=lambda s: parse_hostport(s, default_host="0.0.0.0"),
                    help="Relay listen address (with --relay). Default host 0.0.0.0.")

    args = ap.parse_args()

    if args.relay:
        if args.listen is None:
            ap.error("--relay requires --listen [HOST:]PORT")
        args.listen_host, args.listen_port = args.listen  # host defaults to 0.0.0.0
        if args.pty is None:
            args.pty = "/tmp/pm5-ble"
        if os.name == "nt":
            ap.error("--relay uses a PTY (POSIX-only); run the relay in WSL/Linux")
    else:
        if args.tcp is None and args.connect is None and args.pty is None:
            if os.name == "nt":
                ap.error("PTY backend is POSIX-only; on Windows use --tcp PORT or --connect HOST:PORT")
            args.pty = "/tmp/pm5-ble"

    try:
        return asyncio.run(amain(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
