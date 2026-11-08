# DockScan CLI reference

Run `dockscan --help` for the installed version’s authoritative argument list. This guide documents every current command and its intended safety boundary.

## Global model

DockScan is audit-first. Discovery and documentation are read-only except for output files. Recovery mode is blocked until a capability-specific handler exists, even if a plan is signed and approved.

## `dockscan scan`

Scans the local Linux host, writes a recovery kit, and can package a `.dsrcvr` blueprint.

```bash
dockscan scan --output ./recovery-kit \
  --services step-ca,tailscale \
  --blueprint ./homelab.dsrcvr \
  --environment "Home lab" --ignore-secrets
```

| Option | Purpose |
|---|---|
| `--output PATH` | Required recovery-kit directory. Files are owner-private on Linux. |
| `--name NAME` | Display name for the local host. |
| `--remote NAME=SSH_TARGET` | Scan a remote host through SSH and `dockscan agent --json`. Repeat per host. |
| `--remote-command CMD` | Remote DockScan executable or wrapper. |
| `--services step-ca,tailscale` | Enable optional service discovery. |
| `--ignore-secrets` | Redact all suspected secret values without prompting; recommended for automation. |
| `--include-secrets` | Includes values in local artifacts. Use only in a protected location. |
| `--blueprint FILE.dsrcvr` | Also write a portable blueprint. |
| `--environment NAME` | Blueprint display name. |
| `--encrypted-secrets FILE.encsec` | Embed an age-encrypted secret envelope unchanged. |

Outputs include `inventory.json`, `manifests/`, `docs/`, `artifacts/`, and `ansible/`.

## `dockscan agent`

### Emit JSON through SSH

```bash
dockscan agent --json --ignore-secrets --services step-ca,tailscale
```

This is intended for `scan --remote`. It prints a single JSON inventory document.

### Serve a direct mTLS inventory request

```bash
dockscan agent --serve --bind 0.0.0.0 --port 45832 --token-file /secure/token \
  --tls-ca /etc/dockscan/ca.pem --tls-cert /etc/dockscan/agent.pem \
  --tls-key /etc/dockscan/agent-key.pem --allowed-client-name controller-1
```

The direct server requires a token and mTLS by default. It never allows the remote caller to request unredacted secret export. `--accept-insecure --i-understand-insecure` is break-glass only.

### Initiate outbound enrollment

```bash
dockscan agent --enroll --controller controller.internal:45833 \
  --token-file /etc/dockscan/enrollment-token \
  --tls-ca /etc/dockscan/ca.pem --tls-cert /etc/dockscan/agent.pem \
  --tls-key /etc/dockscan/agent-key.pem
```

The token file must be owner-only (`0600` on Linux). Enrollment is one-use and controller-approved.

## `dockscan orchestrator enroll`

Waits for one outbound agent and writes its approved inventory.

```bash
dockscan orchestrator enroll --output ./agent-inventory.json \
  --tls-ca /etc/dockscan/ca.pem --tls-cert /etc/dockscan/controller.pem \
  --tls-key /etc/dockscan/controller-key.pem
```

`--bind`, `--port`, and `--timeout` control the temporary controller listener. The command prints a short-lived token for out-of-band delivery to the agent.

## `dockscan interact`

Interactive direct-agent controller:

```bash
dockscan interact --output ./recovery-kit \
  --tls-ca /etc/dockscan/ca.pem --tls-cert /etc/dockscan/controller.pem \
  --tls-key /etc/dockscan/controller-key.pem --tls-server-name agent.internal
```

At the prompt, enter `scan 192.0.2.10`. DockScan provides the remote command, checks reachability, and receives inventory after agent-side approval.

## `dockscan step-ca enroll`

Bootstraps Step CA trust and asks the local Step CLI to issue a certificate/key pair.

```bash
dockscan step-ca enroll --ca-url https://ca.internal --fingerprint FINGERPRINT \
  --name controller-1 --san controller-1.internal
```

Defaults: `/etc/dockscan/<name>.pem` and `/etc/dockscan/<name>-key.pem`. Use `--cert`, `--key`, `--san`, and `--dry-run` as needed. Bearer tokens are intentionally unsupported because command-line token handling is unsafe.

## `dockscan encsec`

Encrypted secret envelopes use `age` and are suitable for recovery automation.

```bash
dockscan encsec encrypt --input ./secrets.json --output ./homelab.encsec \
  --recipient age1recipient...
dockscan encsec inspect ./homelab.encsec
dockscan encsec decrypt --input ./homelab.encsec --output ./decrypted.json \
  --identity ~/.config/age/keys.txt
```

Decryption never prints values. The output path is required and is private on Linux. Keep plaintext output only as long as necessary.

## `dockscan blueprint`

### Create and inspect

```bash
dockscan blueprint create --inventory ./recovery-kit/inventory.json \
  --output ./homelab.dsrcvr --environment "Home lab"
dockscan blueprint inspect ./homelab.dsrcvr
```

### Plan and run an audit

```bash
dockscan blueprint plan ./homelab.dsrcvr
dockscan blueprint run ./homelab.dsrcvr --mode audit --session-dir ./sessions
dockscan blueprint resume ./sessions/session-<id>.json --retry host-applications
```

Modes: `audit` runs read-only checks; `dry-run` records a proposed plan; `recovery` remains unavailable until a handler for each capability is implemented.

### Sign, verify, and trust

```bash
dockscan blueprint sign ./homelab.dsrcvr --private-key ./signing.key \
  --public-key ./signing.pub --signer "Primary recovery key"
dockscan blueprint verify ./homelab.dsrcvr --public-key ./signing.pub
dockscan blueprint trust add --store ./trusted-signers.json \
  --public-key ./signing.pub --signer "Primary recovery key"
dockscan blueprint trust list --store ./trusted-signers.json
dockscan blueprint trust revoke --store ./trusted-signers.json --fingerprint sha256:...
```

Trusted signer records support `--expires-at` and `--replaces` for key rotation. Recovery policy requires a trusted signer plus a second approval tied to the signed plan hash.

### Migrate without changing the source

```bash
dockscan blueprint migrate ./old.dsrcvr
dockscan blueprint migrate ./old.dsrcvr --output ./migrated.dsrcvr
```

The first command previews compatibility. The second writes a new unsigned copy; sign it again before relying on it.

## `dockscan backup verify`

Read-only availability checks:

```bash
dockscan backup verify --type restic --location /backups/restic
dockscan backup verify --type borg --location /backups/borg
dockscan backup verify --type age --location ./backup.tar.age
dockscan backup verify --type s3 --bucket homelab --key node/latest.age
```

Successful availability is not proof of a tested restore. Use a recovery drill for that.

## `dockscan evidence create`

Creates a redacted, signed evidence ZIP from a blueprint and session record.

```bash
dockscan evidence create --blueprint ./homelab.dsrcvr \
  --session ./sessions/session-<id>.json --output ./evidence.zip \
  --private-key ./signing.key --signer "Primary recovery key"
```

## `dockscan staticify`

Renders recovery-kit Markdown into a standalone static site.

```bash
dockscan staticify --input ./recovery-kit/docs --output ./recovery-kit/site \
  --title "Home lab recovery guide"
```

Open `site/index.html` locally or host the generated directory on a private static web server. Review the content before publishing: infrastructure topology is sensitive even after secret redaction.
