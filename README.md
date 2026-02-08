# Epson Proxy/Simulator Notes

This repo contains a minimal Epson SNMP/discovery simulator and a UDP proxy that forwards to a real printer.

## Files
- `epson_sim.py` — SNMPv1 + Epson discovery simulator.
- `epson_proxy.py` — UDP proxy for SNMP (`161`) and Epson discovery (`3289`).
- `logs/` — runtime logs and learned OID maps (created at runtime).

## Simulator
Run:
```
py .\epson_sim.py
```

Defaults:
- SNMP: UDP `161`
- Discovery: UDP `3289`
- Logs: `logs/epson_sim-YYYYMMDD-HHMMSS.log`

## Proxy
Run (defaults to `--target-ip 192.168.55.211`):
```
py .\epson_proxy.py
```

Options:
- `--target-ip <ip>`: real printer IP.
- `--mac <AA:BB:CC:DD:EE:FF>`: override MAC in SNMP responses.
- `--learn-file <path>`: write OID→HEX mapping to a custom file.
- `--no-learn-merge`: append with timestamps instead of deduped map.

Logs (created at runtime):
- `logs/epson_proxy-YYYYMMDD-HHMMSS.log` — request/response log.
- `logs/epson_proxy-learn-YYYYMMDD-HHMMSS.log` — learned OID map (dedup by default).
