# AGENTS.md

## Project Knowledge

### Epson simulator ports
- SNMP default port is UDP `161` (the simulator now defaults to this).
- Epson discovery in this project uses UDP `3289` as observed in PCAPs; the simulator defaults to this.

### Windows discovery note
- SNMP + Epson discovery alone usually does not make the device appear as a printer in Windows.
- Windows typically expects WSD/WS-Discovery, mDNS/Bonjour + IPP, or related discovery protocols.

### Simulator coverage
- `epson_sim.py` simulates only a **subset** of SNMPv1 (a few OIDs in `oid_map`) and **one fixed Epson discovery payload**.
- It does **not** simulate all SNMP packets or all Epson discovery variants observed in PCAPs.

### PCAPs and exact-match simulator data
- PCAPs were removed from the repo.

### Simulator overrides (local only)
- SNMP OID MAC value was changed in the simulator to `44:D2:44:99:BB:CC` (does not match the pcap MAC).

### Epson proxy (pass-through to real printer)
- `epson_proxy.py` forwards UDP `161` and `3289` to a real Epson printer IP and logs all requests/responses.
- Default bind matches simulator (`0.0.0.0`), same ports.
- Usage example:
  - `python epson_proxy.py` (defaults to `--target-ip 192.168.55.211`)
- Log format matches simulator:
  - `YYYY-MM-DDTHH:MM:SS KIND IP:PORT HEX`
  - KIND: `SNMP`, `SNMP_RESP`, `SNMP_RESP_DROP`, `DISC`, `DISC_RESP`, `DISC_RESP_DROP`
- Learning mode:
  - Proxy writes `OID HEX` pairs from SNMP responses to `logs/epson_proxy-learn-YYYYMMDD-HHMMSS.log`.
  - Override path with `--learn-file <path>`.
  - Default is merge/dedup. Use `--no-learn-merge` to append with timestamps.

### Replay
- `replay_traffic.py` can replay discovery + SNMP GETs.
- Source options:
  - `--learn-file <path>` (learn map)
  - `--proxy-log <path>` (proxy log; SNMP lines are parsed for OIDs)
