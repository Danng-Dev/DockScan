# Install DockScan on Linux

## Supported baseline

DockScan requires Linux, Python 3.10 or newer, and Docker CLI access for Docker discovery. Run scanning as a dedicated operator account in the `docker` group where possible; avoid running ordinary scans as root.

The installer uses the reviewed local checkout only. It does not fetch code, install an agent, create credentials, expose network ports, or enable a service.

```bash
git clone <reviewed-repository-url> dockscan
cd dockscan
sudo ./scripts/install-linux.sh
dockscan --help
```

The default installation is an isolated virtualenv at `/opt/dockscan`, a launcher at `/usr/local/bin/dockscan`, and private directories at `/etc/dockscan` and `/var/lib/dockscan`.

## Optional outbound agent service

The agent initiates a short-lived, mTLS-protected enrollment to the controller. It does not listen on an exposed port.

```bash
sudo ./scripts/install-linux.sh --service
sudo install -d -m 0700 /etc/dockscan/agents
sudoedit /etc/dockscan/agents/recovery.env
sudo chmod 600 /etc/dockscan/agents/recovery.env
```

Example environment file:

```ini
DOCKSCAN_CONTROLLER=controller.example.internal:45833
DOCKSCAN_TOKEN_FILE=/etc/dockscan/enrollment-token
DOCKSCAN_TLS_CA=/etc/dockscan/ca.pem
DOCKSCAN_TLS_CERT=/etc/dockscan/agent.pem
DOCKSCAN_TLS_KEY=/etc/dockscan/agent-key.pem
```

Review the file, token lifetime, certificate identity, and firewall policy before enabling it:

```bash
sudo systemctl enable --now dockscan-agent@recovery.service
```

For one-time recovery enrollment, prefer running the equivalent command interactively; do not leave an enrollment token on disk after use.

## Dependencies

Optional integrations require their own reviewed CLI:

| Integration | Command |
|---|---|
| Docker discovery | `docker` |
| Step CA enrollment | `step` |
| Encrypted secret envelopes | `age` |
| Blueprint/evidence signing | `openssl` |
| Restic/Borg checks | `restic`, `borg` |
| S3 checks | `aws` |

## Upgrade and uninstall

Upgrade from a new reviewed checkout by rerunning the installer with the same `--prefix`. Back up `/etc/dockscan` first.

To uninstall, stop any enabled agent units, remove `/usr/local/bin/dockscan`, then remove `/opt/dockscan`. Remove `/etc/dockscan` and `/var/lib/dockscan` only after confirming no keys, tokens, session records, or evidence bundles remain.
