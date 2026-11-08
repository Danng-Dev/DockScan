# Operations guide

## Standard scan

```bash
dockscan scan --output ./recovery-kit \
  --blueprint ./homelab.dsrcvr \
  --environment "Homelab" --ignore-secrets
```

Inspect, sign, trust, and plan before any recovery workflow:

```bash
dockscan blueprint inspect ./homelab.dsrcvr
dockscan blueprint sign ./homelab.dsrcvr --private-key ./signing.key --public-key ./signing.pub --signer "Primary key"
dockscan blueprint trust add --store ./trusted-signers.json --public-key ./signing.pub --signer "Primary key"
dockscan blueprint plan ./homelab.dsrcvr
dockscan blueprint run ./homelab.dsrcvr --mode audit --session-dir ./sessions
```

## OS mismatch flag

Audit compares source OS ID, version, architecture, hostname, and machine-ID hash with the target. A `FLAGGED OS` result means the target differs. Do not treat this as a compatible restore: review packages, paths, storage drivers, firewall backend, systemd unit names, and Docker storage before continuing.

## Evidence

```bash
dockscan evidence create --blueprint ./homelab.dsrcvr \
  --session ./sessions/session-<id>.json \
  --output ./evidence/session-<id>.zip \
  --private-key ./signing.key --signer "Primary key"
```

Store evidence next to backups, not inside them. It contains redacted operational history but still reveals infrastructure topology.
