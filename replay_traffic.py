from __future__ import annotations

import argparse
import re
import socket
import time

from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind  # type: ignore


EPSON_DISCOVERY_REQUEST = bytes.fromhex("4550534f4e510200000000000000")


def load_oids_from_learn(path: str) -> list[str]:
    oids: list[str] = []
    with open(path, "r", encoding="ascii") as f:
        for line in f:
            parts = line.strip().split()
            if not parts:
                continue
            if len(parts) >= 2 and parts[0].startswith("1.3.6."):
                oids.append(parts[0])
            elif len(parts) >= 3 and parts[1].startswith("1.3.6."):
                oids.append(parts[1])
    return oids


def load_oids_from_proxy_log(path: str) -> list[str]:
    oids: list[str] = []
    hex_re = re.compile(r"^\S+\s+SNMP\s+\S+\s+([0-9a-fA-F]+)$")
    with open(path, "r", encoding="ascii") as f:
        for line in f:
            m = hex_re.match(line.strip())
            if not m:
                continue
            payload = bytes.fromhex(m.group(1))
            try:
                msg = SNMP(payload)
            except Exception:
                continue
            pdu = getattr(msg, "PDU", None)
            if not isinstance(pdu, SNMPget):
                continue
            vbs = getattr(pdu, "varbindlist", [])
            if not vbs:
                continue
            vb0 = vbs[0]
            oid = vb0.oid.val if hasattr(vb0.oid, "val") else str(vb0.oid)
            oids.append(str(oid))
    return oids


def send_discovery(target_ip: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(EPSON_DISCOVERY_REQUEST, (target_ip, port))
    sock.close()


def send_snmp_get(target_ip: str, port: int, community: str, oid: str, req_id: int) -> None:
    vb = SNMPvarbind(oid=oid)
    pdu = SNMPget(id=req_id, varbindlist=[vb])
    msg = SNMP(version=0, community=community, PDU=pdu)
    data = bytes(msg)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data, (target_ip, port))
    sock.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay Epson discovery + SNMP GETs based on a learn map.")
    ap.add_argument("--target-ip", default="192.168.55.211", help="Printer IP")
    ap.add_argument("--snmp-port", type=int, default=161, help="SNMP UDP port")
    ap.add_argument("--disc-port", type=int, default=3289, help="Discovery UDP port")
    ap.add_argument("--community", default="public", help="SNMP community")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--learn-file", help="Learn map file (OID HEX)")
    src.add_argument("--proxy-log", help="Proxy log file (SNMP lines)")
    ap.add_argument("--sleep", type=float, default=0.05, help="Delay between SNMP GETs (seconds)")
    args = ap.parse_args()

    if args.learn_file:
        oids = load_oids_from_learn(args.learn_file)
    else:
        oids = load_oids_from_proxy_log(args.proxy_log)
    if not oids:
        print("No OIDs found in learn file.")
        return 1

    print(f"Replaying discovery to {args.target_ip}:{args.disc_port}")
    send_discovery(args.target_ip, args.disc_port)

    print(f"Replaying {len(oids)} SNMP GETs to {args.target_ip}:{args.snmp_port}")
    req_id = 1
    for oid in oids:
        send_snmp_get(args.target_ip, args.snmp_port, args.community, oid, req_id)
        req_id += 1
        time.sleep(args.sleep)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
