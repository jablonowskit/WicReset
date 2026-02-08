from __future__ import annotations

import argparse
import asyncio
import binascii
import datetime as _dt
import os
import socket
from dataclasses import dataclass

from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_STRING  # type: ignore
from scapy.layers.snmp import SNMP, SNMPget, SNMPresponse, SNMPvarbind  # type: ignore


# Epson discovery payload (UDP/3289) observed in the pcap (EPSONq...).
EPSON_DISCOVERY_PAYLOAD_HEX = (
    "4550534f4e7102000000000000e003000000cb"
    "4d46473a4550534f4e3b"
    "434d443a455343504c322c4244432c44342c443450582c4553435052312c454e44343b"
    "4d444c3a58502d34333220343335205365726965733b"
    "434c533a5052494e5445523b"
    "4445533a4550534f4e2058502d34333220343335205365726965733b"
    "4349443a4570736f6e5247423b"
    "4649443a46584e2c44504e2c5746412c45544e2c41464e2c44414e2c5752413b"
    "5249443a34303b"
    "4444533a3032323530303b"
    "454c473a304531303b"
    "534e3a3537333234313530333033313330333535323b"
    "58502d343332203433352053657269657300"
)


def mac_bytes(mac: str) -> bytes:
    mac = mac.replace("-", ":").lower()
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC: {mac!r}")
    return bytes(int(p, 16) for p in parts)

@dataclass(frozen=True)
class OidValue:
    kind: str  # "int" | "octets"
    value: int | bytes


class SnmpV1Responder(asyncio.DatagramProtocol):
    def __init__(self, oid_map: dict[str, OidValue], log_path: str):
        self.oid_map = oid_map
        self.log_path = log_path
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        try:
            msg = SNMP(data)
        except Exception:
            return

        # Only handle SNMPv1 GET (version=0 in BER).
        ver_field = getattr(msg, "version", None)
        ver = getattr(ver_field, "val", ver_field)
        if ver != 0:
            return
        if not isinstance(getattr(msg, "PDU", None), SNMPget):
            return

        pdu: SNMPget = msg.PDU
        varbinds = getattr(pdu, "varbindlist", [])
        if not varbinds:
            return

        vb0 = varbinds[0]
        oid = vb0.oid.val if hasattr(vb0.oid, "val") else str(vb0.oid)
        print(f"[SNMP] from={addr[0]}:{addr[1]} oid={oid} bytes={len(data)}")
        self._log_packet("SNMP", addr, data)

        mapped = self.oid_map.get(str(oid))
        if mapped is None:
            # SNMPv1 error-status: noSuchName = 2, error-index = 1
            resp_pdu = SNMPresponse(
                id=pdu.id,
                error=2,
                error_index=1,
                varbindlist=[SNMPvarbind(oid=vb0.oid, value=ASN1_INTEGER(0))],
            )
        else:
            if mapped.kind == "int":
                val = ASN1_INTEGER(int(mapped.value))  # type: ignore[arg-type]
            else:
                val = ASN1_STRING(bytes(mapped.value))  # type: ignore[arg-type]
            resp_pdu = SNMPresponse(
                id=pdu.id,
                error=0,
                error_index=0,
                varbindlist=[SNMPvarbind(oid=vb0.oid, value=val)],
            )

        resp = SNMP(version=msg.version, community=msg.community, PDU=resp_pdu)
        out = bytes(resp)
        if self.transport:
            self.transport.sendto(out, addr)
            self._log_packet("SNMP_RESP", addr, out)

    def _log_packet(self, kind: str, addr, payload: bytes) -> None:
        ts = _dt.datetime.now().isoformat(timespec="seconds")
        line = f"{ts} {kind} {addr[0]}:{addr[1]} {payload.hex()}\n"
        try:
            with open(self.log_path, "a", encoding="ascii") as f:
                f.write(line)
        except Exception:
            pass


class EpsonDiscoveryResponder(asyncio.DatagramProtocol):
    def __init__(self, payload: bytes, log_path: str):
        self.payload = payload
        self.log_path = log_path
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        print(f"[DISC] from={addr[0]}:{addr[1]} bytes={len(data)}")
        self._log_packet("DISC", addr, data)
        # Reply to whoever sent something (acts like a simple discovery responder).
        if self.transport:
            self.transport.sendto(self.payload, addr)
            self._log_packet("DISC_RESP", addr, self.payload)

    def _log_packet(self, kind: str, addr, payload: bytes) -> None:
        ts = _dt.datetime.now().isoformat(timespec="seconds")
        line = f"{ts} {kind} {addr[0]}:{addr[1]} {payload.hex()}\n"
        try:
            with open(self.log_path, "a", encoding="ascii") as f:
                f.write(line)
        except Exception:
            pass


async def main() -> int:
    ap = argparse.ArgumentParser(description="Minimal Epson XP-432/435-ish UDP simulator (SNMPv1 + Epson discovery)")
    ap.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    ap.add_argument("--snmp-port", type=int, default=161, help="UDP port for SNMPv1 (default: 161)")
    ap.add_argument("--disc-port", type=int, default=3289, help="UDP port for Epson discovery (default: 3289)")
    ap.add_argument("--log-file", default=None, help="Append request/response log file")
    ap.add_argument("--admin-community", default="admin", help="(Informational) admin community name (not enforced)")
    args = ap.parse_args()

    if args.log_file:
        log_path = args.log_file
    else:
        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        log_path = os.path.join("logs", f"epson_sim-{ts}.log")
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

    # OIDs observed in epson-snmp-161.pcap:
    # - 1.3.6.1.4.1.1248.1.1.3.1.1.5.0 -> MAC bytes
    # - 1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.115.116.1.0.1 -> big blob
    # - 1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.118.105.1.0.0 -> 0x0076693a30303a4d45323348363b0c
    # - 1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.7.0.133.5.65.190.160.(24|25|26|27|30|34).0 -> values below
    oid_map: dict[str, OidValue] = {
        "1.3.6.1.4.1.1248.1.1.3.1.1.5.0": OidValue("octets", mac_bytes("44:D2:44:99:BB:CC")),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.118.105.1.0.0": OidValue(
            "octets", bytes.fromhex("0076693a30303a4d45323348363b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.115.116.1.0.1": OidValue(
            "octets",
            bytes.fromhex(
                "0040424443205354320d0a58"
                "00010100020110060201000e010f0f0d030100"
                "69050369040269030169100301094e130101190c0000000000"
                "756e6b6e6f776e24020000370502020000003901003f0a01010000000000000000"
                # Tail ASCII serial (W2AP010552)
                "400a57324150303130353532"
            ),
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.7.0.133.5.65.190.160.24.0": OidValue(
            "octets", bytes.fromhex("00404244432050530d0a45453a3030313841443b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.7.0.133.5.65.190.160.25.0": OidValue(
            "octets", bytes.fromhex("00404244432050530d0a45453a3030313930463b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.7.0.133.5.65.190.160.30.0": OidValue(
            "octets", bytes.fromhex("00404244432050530d0a45453a3030314530303b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.7.0.133.5.65.190.160.26.0": OidValue(
            "octets", bytes.fromhex("00404244432050530d0a45453a3030314132433b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.7.0.133.5.65.190.160.27.0": OidValue(
            "octets", bytes.fromhex("00404244432050530d0a45453a3030314230413b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.7.0.133.5.65.190.160.34.0": OidValue(
            "octets", bytes.fromhex("00404244432050530d0a45453a3030323230303b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.133.5.66.189.33.24.0.120.81.112.109.122.121.102.111.98": OidValue(
            "octets", bytes.fromhex("007c7c3a34323a4f4b3b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.133.5.66.189.33.25.0.12.81.112.109.122.121.102.111.98": OidValue(
            "octets", bytes.fromhex("007c7c3a34323a4f4b3b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.133.5.66.189.33.26.0.44.81.112.109.122.121.102.111.98": OidValue(
            "octets", bytes.fromhex("007c7c3a34323a4f4b3b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.133.5.66.189.33.27.0.10.81.112.109.122.121.102.111.98": OidValue(
            "octets", bytes.fromhex("007c7c3a34323a4f4b3b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.133.5.66.189.33.28.0.0.81.112.109.122.121.102.111.98": OidValue(
            "octets", bytes.fromhex("007c7c3a34323a4f4b3b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.133.5.66.189.33.29.0.0.81.112.109.122.121.102.111.98": OidValue(
            "octets", bytes.fromhex("007c7c3a34323a4f4b3b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.133.5.66.189.33.30.0.0.81.112.109.122.121.102.111.98": OidValue(
            "octets", bytes.fromhex("007c7c3a34323a4f4b3b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.133.5.66.189.33.34.0.0.81.112.109.122.121.102.111.98": OidValue(
            "octets", bytes.fromhex("007c7c3a34323a4f4b3b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.133.5.66.189.33.46.0.94.81.112.109.122.121.102.111.98": OidValue(
            "octets", bytes.fromhex("007c7c3a34323a4f4b3b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.133.5.66.189.33.47.0.94.81.112.109.122.121.102.111.98": OidValue(
            "octets", bytes.fromhex("007c7c3a34323a4f4b3b0c")
        ),
        "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.133.5.66.189.33.49.0.0.81.112.109.122.121.102.111.98": OidValue(
            "octets", bytes.fromhex("007c7c3a34323a4f4b3b0c")
        ),
    }

    disc_payload = binascii.unhexlify(EPSON_DISCOVERY_PAYLOAD_HEX)

    loop = asyncio.get_running_loop()

    # SNMP responder
    snmp_transport, _snmp_proto = await loop.create_datagram_endpoint(
        lambda: SnmpV1Responder(oid_map, log_path),
        local_addr=(args.bind, args.snmp_port),
    )

    # Epson discovery responder
    disc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    disc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        disc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError:
        pass
    disc_sock.bind((args.bind, args.disc_port))

    disc_transport, _disc_proto = await loop.create_datagram_endpoint(
        lambda: EpsonDiscoveryResponder(disc_payload, log_path),
        sock=disc_sock,
    )

    try:
        print(f"SNMPv1 listening on udp://{args.bind}:{args.snmp_port}")
        print(f"Epson discovery listening on udp://{args.bind}:{args.disc_port}")
        print(f"Logging to {log_path}")
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
