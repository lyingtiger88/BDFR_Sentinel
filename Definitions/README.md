# BDFR Sentinel Local Reputation Database

Place `reputation.jsonl` in this folder (or in ProgramData after install).

Each line is one JSON object:

```json
{"sha256":"<64 hex chars>","state":"Malicious","family":"Trojan.Example","source":"local"}
```

Supported states:
- `Trusted`
- `Malicious`
- `Unknown`

Trusted entries currently suppress reputation detections only; they do not override independent malware detections from YARA, hashes, AMSI, PE heuristics, or behavior analysis.
