# DockScan

DockScan is a dependency-free Linux CLI for documenting a Docker homelab and producing a portable recovery kit. It discovers the current host, Docker containers, networks, volumes, and optionally Step CA and Tailscale. Remote hosts are scanned by starting the same lightweight agent over SSH.

## Documentation

- [Linux installation](docs/INSTALL_LINUX.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Operations and recovery workflow](docs/OPERATIONS.md)
- [Security model](docs/SECURITY.md)
- [Quick start](docs/QUICKSTART.md)
- [Complete CLI reference](docs/CLI_REFERENCE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Step CA setup and provisioners](docs/STEP_CA.md)
- [Updates](docs/UPDATES.md)
- [Remote agent setup](docs/AGENT_SETUP.md)

## Install

```bash
# From a reviewed source checkout on Linux:
sudo bash install.sh
```

The installer is intentionally local-source only: it does not download or execute remote code. See [Linux installation](docs/INSTALL_LINUX.md) for service and upgrade options.

For a hosted, pinned-release installer, see [hosted installation](docs/HOSTED_INSTALL.md). Do not install from a floating branch.

The scanner needs access to the Docker socket (usually run as a user in the `docker` group or with `sudo`). It only uses the Docker CLI; no Python Docker SDK is required.

## Create a recovery kit

```bash
dockscan scan --output ./homelab-recovery --services step-ca,tailscale
```

To include another machine, ensure `dockscan` is installed on it and SSH can authenticate non-interactively:

```bash
dockscan scan --output ./homelab-recovery \
  --remote nas=ops@nas.lan --remote pi=pi@192.168.1.12
```

Each remote is invoked as `ssh <target> dockscan agent --json`. Set a different program or wrapper with `--remote-command`.

Generated files include:

- `inventory.json`: machine-readable, redacted inventory.
- `docs/RECOVERY.md`: ordered recovery runbook and service notes.
- `docs/INVENTORY.md`: static infrastructure documentation.
- `ansible/`: inventory, a Docker recovery playbook, and per-host variables.
- `manifests/`: Docker inspect-derived manifests for audit and recovery reference.

## Portable `.dsrcvr` blueprint

Create a self-describing, portable recovery blueprint during a scan:

```bash
dockscan scan --output ./homelab-recovery \
  --blueprint ./archie-homelab.dsrcvr \
  --environment "Archie Homelab"
```

The `.dsrcvr` file is a ZIP archive containing a versioned manifest, per-machine definitions, infrastructure/service inventories, secret declarations (never values), dependency-aware recovery and verification plans, and SHA-256 checksums. Inspect it safely on another DockScan installation:

```bash
dockscan blueprint inspect ./archie-homelab.dsrcvr
```

Inspection validates archive paths and artifact hashes and is audit-only. Unsigned blueprints are never eligible for automated execution. You can also package an existing recovery kit with `dockscan blueprint create --inventory ./homelab-recovery/inventory.json --output ./homelab.dsrcvr`.

Sign a validated blueprint with a private key kept outside the archive, then verify it with a trusted public key:

```bash
dockscan blueprint sign ./homelab.dsrcvr \
  --private-key ./dockscan-signing-key.pem --signer "Home recovery key"
dockscan blueprint verify ./homelab.dsrcvr \
  --public-key ./dockscan-signing-public.pem
```

Signing uses the local OpenSSL CLI and signs a canonical manifest payload containing the artifact hash table. Modifying any covered artifact makes inspection fail before signature verification. The private key is never copied into the blueprint.

Preview the dependency-ordered plan without changing any machine:

```bash
dockscan blueprint plan ./homelab.dsrcvr
```

This validates task identifiers, missing dependencies, and dependency cycles, then prints the audit-only execution order. It never runs recovery commands.

Create a checkpointed audit session, then resume it later without repeating recorded checkpoints:

```bash
dockscan blueprint run ./homelab.dsrcvr --mode audit --session-dir ./sessions
dockscan blueprint resume ./sessions/session-<id>.json --retry raspi-services
```

Audit performs only read-only host checks (routing, mounts, Docker availability, and container inventory) and writes JSON and Markdown session records. `dry-run` records the approved execution order but executes nothing. Recovery execution remains deliberately blocked until an operation has a capability-scoped implementation.

### Flagged OS compatibility

Every recovery task records the source distribution, version, and CPU architecture. During audit, DockScan compares these fields to the target host and emits a **`FLAGGED OS`** result when they differ. A mismatched OS must be reviewed before attempting package, service, storage, or Docker restoration; it is never silently treated as a like-for-like recovery.

### Encrypted recovery secrets (`.encsec`)

For automated recovery, create an age-encrypted secret envelope. The input is a JSON object, for example `{"database-password":"...","cloudflare-api-token":"..."}`. It is encrypted to one or more recovery recipients and is never printed by DockScan:

```bash
dockscan encsec encrypt --input ./recovery-secrets.json \
  --output ./homelab.encsec \
  --recipient age1example...

dockscan scan --output ./homelab-recovery \
  --blueprint ./homelab.dsrcvr \
  --encrypted-secrets ./homelab.encsec
```

The blueprint stores it as `requirements/secrets.encsec`, still encrypted. Use `dockscan encsec inspect` to view only envelope metadata. Decryption always requires an explicit protected output file and one or more age identity files; DockScan never prints decrypted values. Keep the identity file separate from the blueprint and encrypted backups.

### Outbound agent enrollment

Avoid exposing a port on the recovering machine by having the agent initiate a single-use outbound enrollment:

```bash
# Controller: displays a token and waits for one approved agent
dockscan orchestrator enroll --output ./agent-inventory.json \
  --tls-ca /etc/dockscan/ca.pem --tls-cert /etc/dockscan/controller.pem \
  --tls-key /etc/dockscan/controller-key.pem

# Agent: use the displayed token and controller address
dockscan agent --enroll --controller controller.lan:45833 --token '<token>' \
  --tls-ca /etc/dockscan/ca.pem --tls-cert /etc/dockscan/agent.pem \
  --tls-key /etc/dockscan/agent-key.pem
```

The controller token expires after ten minutes, may be used once, and requires interactive controller-side approval of the agent identity. Mutual TLS is required unless `--accept-insecure` is explicitly selected.

### Backup availability

Read-only availability checks support Restic, Borg, age archives, and S3-compatible access through the AWS CLI:

```bash
dockscan backup verify --type restic --location /backups/restic
dockscan backup verify --type borg --location /backups/borg
dockscan backup verify --type age --location ./backup.tar.age
dockscan backup verify --type s3 --bucket homelab-backups --key raspi/latest.age
```

## Restore

Review generated `ansible/host_vars/*.yml`, provide sensitive environment values from a secret manager, then run:

```bash
cd homelab-recovery/ansible
ansible-galaxy collection install community.docker
ansible-playbook -i inventory.ini recover.yml
```

Docker bind mounts are documented but their contents cannot be backed up by inspecting Docker. Back up bind paths and named volumes separately before relying on a recovery kit.

## Interactive remote agent

On the controller, start an interactive session:

```bash
dockscan interact --output ./homelab-recovery
```

Say `scan 172.0.8.7`. DockScan generates a one-time token and prints the exact command to run on that host. After you start it, the controller verifies TCP port `45832` is reachable and retrieves the inventory.

### Step CA mutual TLS

For encrypted, mutually authenticated traffic, use PEM certificates issued by your Step CA. The agent verifies the controller certificate, displays its certificate common name (for example `John-PC-1`), and asks its local operator for approval before serving inventory:

```bash
dockscan interact --output ./homelab-recovery \
  --tls-ca /etc/dockscan/ca.pem \
  --tls-cert /etc/dockscan/controller.pem \
  --tls-key /etc/dockscan/controller-key.pem \
  --tls-server-name agent.homelab.internal
```

The controller prints the matching remote `dockscan agent serve` command. DockScan consumes standard PEM files; its CA-provider layer currently supports Step CA enrollment guidance and can be extended for other internal CAs.

### Enroll identities with Step CA

You can have DockScan invoke the installed `step` CLI, rather than manually obtaining PEM files. Run this separately on the controller and on every machine that will run an agent, changing the identity and SANs for each host:

```bash
dockscan step-ca enroll \
  --ca-url https://ca.homelab.internal \
  --fingerprint '<step-ca-fingerprint>' \
  --name John-PC-1 \
  --san john-pc-1.homelab.internal
```

This runs `step ca bootstrap` followed by `step ca certificate`; the certificate and key are outputs created by Step. By default they are written as `/etc/dockscan/<name>.pem` and `/etc/dockscan/<name>-key.pem`, and the private key is set to mode `0600` on Linux. Override the output locations with `--cert` and `--key` if needed. DockScan deliberately does not accept bearer tokens because the Step CLI would expose them as process arguments; use a Step provisioner/authentication flow that does not require a command-line token. Use `--dry-run` to validate the local inputs without contacting the CA.

`--accept-insecure` is a break-glass mode. It permits unsigned or unverified peers; when certificate/key files are still supplied, traffic remains encrypted but identity is not verified. Without TLS files, it is plaintext and suitable only for isolated troubleshooting.

## Security

Environment values whose keys resemble passwords, tokens, keys, or secrets are redacted by default. Pass `--include-secrets` only to a protected output location; it writes those values to local recovery files. Do not commit recovery kits with secrets.

By default, an interactive scan asks about each suspected value. Answering `Y` (or pressing Enter) means it is a secret and it is excluded; answer `n` to retain it. Use `--ignore-secrets` to redact all suspected secrets non-interactively.
