# Quick start

## 1. Install

```bash
sudo bash install.sh
```

For hosted installation, use the pinned command in [HOSTED_INSTALL.md](HOSTED_INSTALL.md).

## 2. Scan and document one host

```bash
dockscan scan --output ./recovery-kit --services step-ca,tailscale --ignore-secrets
dockscan staticify --input ./recovery-kit/docs --output ./recovery-kit/site
```

Read `recovery-kit/docs/SYSTEM_OVERVIEW.md` and `recovery-kit/docs/RECOVERY.md` before considering any restore.

## 3. Make a portable blueprint

```bash
dockscan scan --output ./recovery-kit --blueprint ./homelab.dsrcvr \
  --environment "Home lab" --ignore-secrets
dockscan blueprint inspect ./homelab.dsrcvr
dockscan blueprint plan ./homelab.dsrcvr
```

## 4. Add a remote host

For SSH:

```bash
dockscan scan --output ./recovery-kit --remote nas=ops@nas.internal --ignore-secrets
```

For outbound mTLS enrollment, start `dockscan orchestrator enroll` on the controller and follow the printed agent command. See [CLI_REFERENCE.md](CLI_REFERENCE.md).

## 5. Perform an audit drill

```bash
dockscan blueprint run ./homelab.dsrcvr --mode audit --session-dir ./sessions
```

Resolve every `blocked`, `warning`, missing-backup, and `FLAGGED OS` finding before attempting a real restoration workflow.
