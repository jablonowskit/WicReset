from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import os
import time
from collections import deque

from scapy.layers.snmp import SNMP, SNMPget, SNMPresponse  # type: ignore
from scapy.asn1.asn1 import ASN1_STRING  # type: ignore


class UdpProxy(asyncio.DatagramProtocol):
    def __init__(
        self,
        target_ip: str,
        target_port: int,
        log_path: str,
        label: str,
        mac_override: bytes,
        learning_path: str | None,
        learning_merge: bool,
        fanout_window: float = 3.0,
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.log_path = log_path
        self.label = label
        self.mac_override = mac_override
        self.learning_path = learning_path
        self.learning_merge = learning_merge
        self.transport: asyncio.DatagramTransport | None = None
        self.pending: deque[tuple[str, int]] = deque()
        self.req_id_to_client: dict[int, tuple[str, int]] = {}
        self.recent_clients: deque[tuple[float, tuple[str, int]]] = deque()
        self.fanout_window = fanout_window
        self.last_printer_mac: bytes | None = None
        self.learn_map: dict[str, str] = {}

        if self.learning_path and self.learning_merge:
            self.learn_map = self._load_learn_map(self.learning_path)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        if not self.transport:
            return

        if addr[0] == self.target_ip and addr[1] == self.target_port:
            # Response from printer.
            if self.label == "SNMP":
                data = self._rewrite_snmp_mac(data)
                self._learn_snmp_response(data)
                client = self._match_snmp_response(data)
                if client:
                    self.transport.sendto(data, client)
                    self._log(f"{self.label}_RESP", addr, data)
                else:
                    self._log(f"{self.label}_RESP_DROP", addr, data)
            else:
                # Discovery: fan out to all recent clients.
                targets = self._recent_clients()
                if targets:
                    data = self._rewrite_discovery_mac(data)
                    for client in targets:
                        self.transport.sendto(data, client)
                    self._log(f"{self.label}_RESP", addr, data)
                else:
                    self._log(f"{self.label}_RESP_DROP", addr, data)
            return

        # Request from client -> forward to printer.
        if self.label == "SNMP":
            self._track_snmp_request(data, addr)
        else:
            self._track_discovery_client(addr)

        self.pending.append((addr[0], addr[1]))
        self.transport.sendto(data, (self.target_ip, self.target_port))
        self._log(self.label, addr, data)

    def _log(self, kind: str, src, payload: bytes) -> None:
        ts = _dt.datetime.now().isoformat(timespec="seconds")
        line = f"{ts} {kind} {src[0]}:{src[1]} {payload.hex()}\n"
        try:
            with open(self.log_path, "a", encoding="ascii") as f:
                f.write(line)
        except Exception:
            pass

    def _track_snmp_request(self, payload: bytes, addr) -> None:
        try:
            msg = SNMP(payload)
        except Exception:
            return
        pdu = getattr(msg, "PDU", None)
        if not isinstance(pdu, SNMPget):
            return
        req_id = getattr(getattr(pdu, "id", None), "val", pdu.id)
        try:
            self.req_id_to_client[int(req_id)] = (addr[0], addr[1])
        except Exception:
            pass

    def _match_snmp_response(self, payload: bytes) -> tuple[str, int] | None:
        try:
            msg = SNMP(payload)
        except Exception:
            return None
        pdu = getattr(msg, "PDU", None)
        if not isinstance(pdu, SNMPresponse):
            return None
        resp_id = getattr(getattr(pdu, "id", None), "val", pdu.id)
        try:
            return self.req_id_to_client.pop(int(resp_id), None)
        except Exception:
            return None

    def _rewrite_snmp_mac(self, payload: bytes) -> bytes:
        try:
            msg = SNMP(payload)
        except Exception:
            return payload
        pdu = getattr(msg, "PDU", None)
        if not isinstance(pdu, SNMPresponse):
            return payload
        vbs = getattr(pdu, "varbindlist", [])
        if not vbs:
            return payload
        changed = False
        for vb in vbs:
            oid = vb.oid.val if hasattr(vb.oid, "val") else str(vb.oid)
            if str(oid) == "1.3.6.1.4.1.1248.1.1.3.1.1.5.0":
                try:
                    self.last_printer_mac = bytes(vb.value.val)
                except Exception:
                    self.last_printer_mac = None
                vb.value = ASN1_STRING(self.mac_override)
                changed = True
        if not changed:
            return payload
        try:
            return bytes(msg)
        except Exception:
            return payload

    def _learn_snmp_response(self, payload: bytes) -> None:
        if not self.learning_path:
            return
        try:
            msg = SNMP(payload)
        except Exception:
            return
        pdu = getattr(msg, "PDU", None)
        if not isinstance(pdu, SNMPresponse):
            return
        vbs = getattr(pdu, "varbindlist", [])
        if not vbs:
            return
        vb0 = vbs[0]
        oid = vb0.oid.val if hasattr(vb0.oid, "val") else str(vb0.oid)
        try:
            val_bytes = bytes(vb0.value.val)
        except Exception:
            try:
                val_bytes = bytes(vb0.value)
            except Exception:
                return
        hex_val = val_bytes.hex()
        if self.learning_merge:
            prev = self.learn_map.get(str(oid))
            if prev == hex_val:
                return
            self.learn_map[str(oid)] = hex_val
            self._write_learn_map(self.learning_path)
        else:
            ts = _dt.datetime.now().isoformat(timespec="seconds")
            line = f"{ts} {oid} {hex_val}\n"
            try:
                with open(self.learning_path, "a", encoding="ascii") as f:
                    f.write(line)
            except Exception:
                pass

    def _load_learn_map(self, path: str) -> dict[str, str]:
        out: dict[str, str] = {}
        try:
            with open(path, "r", encoding="ascii") as f:
                for line in f:
                    parts = line.strip().split()
                    if not parts:
                        continue
                    if len(parts) >= 2 and parts[0].startswith("1.3.6."):
                        oid, hex_val = parts[0], parts[1]
                    elif len(parts) >= 3 and parts[1].startswith("1.3.6."):
                        oid, hex_val = parts[1], parts[2]
                    else:
                        continue
                    out[oid] = hex_val
        except Exception:
            pass
        return out

    def _write_learn_map(self, path: str) -> None:
        try:
            with open(path, "w", encoding="ascii") as f:
                for oid in sorted(self.learn_map):
                    f.write(f"{oid} {self.learn_map[oid]}\n")
        except Exception:
            pass

    def _rewrite_discovery_mac(self, payload: bytes) -> bytes:
        if not self.last_printer_mac:
            return payload
        try:
            return payload.replace(self.last_printer_mac, self.mac_override)
        except Exception:
            return payload

    def _track_discovery_client(self, addr) -> None:
        self.recent_clients.append((time.time(), (addr[0], addr[1])))

    def _recent_clients(self) -> list[tuple[str, int]]:
        now = time.time()
        while self.recent_clients and now - self.recent_clients[0][0] > self.fanout_window:
            self.recent_clients.popleft()
        # unique preserve order
        seen = set()
        out: list[tuple[str, int]] = []
        for _ts, client in self.recent_clients:
            if client in seen:
                continue
            seen.add(client)
            out.append(client)
        return out


async def main() -> int:
    ap = argparse.ArgumentParser(description="UDP proxy for Epson printer ports (SNMP + discovery).")
    ap.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    ap.add_argument("--target-ip", default="192.168.55.211", help="Target printer IP")
    ap.add_argument("--snmp-port", type=int, default=161, help="SNMP UDP port (default: 161)")
    ap.add_argument("--disc-port", type=int, default=3289, help="Discovery UDP port (default: 3289)")
    ap.add_argument("--log-file", default=None, help="Append request/response log file")
    ap.add_argument("--fanout-window", type=float, default=3.0, help="Discovery fanout window in seconds")
    ap.add_argument("--mac", default="44:D2:44:AA:BB:CC", help="Override MAC in SNMP OID responses")
    ap.add_argument("--learn-file", default=None, help="Append OID->hex mapping from SNMP responses")
    ap.add_argument(
        "--learn-merge",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Deduplicate OID map (overwrite learn file)",
    )
    args = ap.parse_args()

    def mac_bytes(mac: str) -> bytes:
        mac = mac.replace("-", ":").lower()
        parts = mac.split(":")
        if len(parts) != 6:
            raise ValueError(f"Invalid MAC: {mac!r}")
        return bytes(int(p, 16) for p in parts)

    mac_override = mac_bytes(args.mac)

    if args.log_file:
        log_path = args.log_file
    else:
        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        log_path = os.path.join("logs", f"epson_proxy-{ts}.log")
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

    if args.learn_file:
        learn_path = args.learn_file
    else:
        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        learn_path = os.path.join("logs", f"epson_proxy-learn-{ts}.log")
    os.makedirs(os.path.dirname(learn_path) or ".", exist_ok=True)

    loop = asyncio.get_running_loop()

    snmp_transport, _snmp_proto = await loop.create_datagram_endpoint(
        lambda: UdpProxy(
            args.target_ip,
            args.snmp_port,
            log_path,
            "SNMP",
            mac_override,
            learn_path,
            args.learn_merge,
            args.fanout_window,
        ),
        local_addr=(args.bind, args.snmp_port),
    )
    disc_transport, _disc_proto = await loop.create_datagram_endpoint(
        lambda: UdpProxy(
            args.target_ip,
            args.disc_port,
            log_path,
            "DISC",
            mac_override,
            learn_path,
            args.learn_merge,
            args.fanout_window,
        ),
        local_addr=(args.bind, args.disc_port),
    )

    try:
        print(f"Proxying udp://{args.bind}:{args.snmp_port} -> {args.target_ip}:{args.snmp_port}")
        print(f"Proxying udp://{args.bind}:{args.disc_port} -> {args.target_ip}:{args.disc_port}")
        print(f"Logging to {log_path}")
        mode = "merge" if args.learn_merge else "append"
        print(f"Learning OID map to {learn_path} ({mode})")
        print("Press Ctrl+C to stop.")
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        return 0
    finally:
        disc_transport.close()
        snmp_transport.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
