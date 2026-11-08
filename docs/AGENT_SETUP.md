# Set up a DockScan recovery agent on another Linux machine

This guide configures an agent machine to connect **outbound** to a DockScan controller. The recommended path uses mutual TLS, a short-lived enrollment token, and controller-side approval. It does not require an inbound port on the agent.

## Before you start

You need:

- Controller DNS name and reachable port, normally `45833`.
- The CA root bundle (`ca.pem`).
- A controller certificate/key and an agent certificate/key issued by the same internal CA.
- A short-lived one-use enrollment token from the controller.
- `sudo` access on the agent.
- Python 3.10+ and, when issuing a local Step certificate, the Smallstep `step` CLI.

Never copy CA root/intermediate private keys, a reusable JWK provisioner password, `.encsec` identities, or backup decryption identities to the agent.

An outbound enrollment is a **one-shot inventory collection**, not a permanently connected daemon. Repeat sections 3–5 with a new token whenever you need a new collection. The optional systemd template is only suitable for an operator-managed, short-lived enrollment window; it must not be enabled with an already-consumed token.

## 1. Install DockScan

Run on the agent machine:

```bash
curl -fsSL https://raw.githubusercontent.com/Danng-Dev/DockScan/v0.1.3/scripts/bootstrap-install.sh | bash -s -- \
  --repository https://github.com/Danng-Dev/DockScan.git \
  --ref v0.1.3
```

Confirm installation:

```bash
dockscan --help
```

If Docker is installed, run the collection command with enough local privilege to read the Docker socket. For a non-root operator, this normally means membership of the `docker` group; membership is effectively root-equivalent on typical Docker installations, so keep it limited to trusted administrators.

## 2. Prepare the controller identity

Do this once on the controller. It assumes Step CA issuance has already been configured; see [STEP_CA.md](STEP_CA.md) for creating the dedicated provisioner and protecting its password.

```bash
sudo dockscan step-ca enroll \
  --ca-url https://ca.internal \
  --fingerprint '<step-ca-fingerprint>' \
  --name controller-1 --san controller.internal \
  --cert /etc/dockscan/controller.pem \
  --key /etc/dockscan/controller-key.pem
sudo chmod 600 /etc/dockscan/controller-key.pem
```

Install the CA root certificate at `/etc/dockscan/ca.pem` on both controller and agent. The controller certificate must contain the exact DNS name that agents use in `--controller`; otherwise normal TLS hostname verification will reject it.

## 3. Install CA trust and agent identity

Create a private directory for agent material:

```bash
sudo install -d -m 0700 /etc/dockscan
sudo install -m 0644 ./ca.pem /etc/dockscan/ca.pem
```

### Recommended: issue the key on the agent

Have the CA operator create a **short-lived, single-use** enrollment token for this agent identity. Do not copy the reusable provisioner password to the agent.

Install the Step CLI using your distribution's reviewed package or the [official Smallstep installation instructions](https://smallstep.com/docs/step-cli/installation/). On the agent, use the token once to create the key locally. Entering it through `read` avoids shell history; the token is still briefly present in the `step` process arguments, so keep it short-lived and single-use:

```bash
read -rsp 'One-use Step token: ' STEP_TOKEN; echo
sudo step ca certificate agent-1.internal \
  /etc/dockscan/agent.pem /etc/dockscan/agent-key.pem \
  --ca-url https://ca.internal \
  --root /etc/dockscan/ca.pem \
  --token "$STEP_TOKEN"
unset STEP_TOKEN
sudo chmod 600 /etc/dockscan/agent-key.pem
```

Use an identity authorized by your CA policy. Issue a stable DNS or URI SAN such as `agent-1.internal`, and enforce the machine/role/environment allowlist in Step CA policy. This release displays the peer certificate common name at the controller approval prompt; use CA-side policy for SAN and revocation enforcement rather than treating the prompt as a complete authorization system.

## 4. Start the controller enrollment window

Run on the controller:

```bash
sudo dockscan orchestrator enroll \
  --output ./agent-1-inventory.json \
  --tls-ca /etc/dockscan/ca.pem \
  --tls-cert /etc/dockscan/controller.pem \
  --tls-key /etc/dockscan/controller-key.pem \
  --port 45833 --timeout 600
```

DockScan prints a single-use token. Deliver it over a secure out-of-band channel; do not put it in a shell command or shell history.

## 5. Create a private enrollment-token file

On the agent:

```bash
sudo install -m 600 /dev/null /etc/dockscan/enrollment-token
sudoedit /etc/dockscan/enrollment-token
```

Paste only the one-time token, save, then check:

```bash
sudo stat -c '%a %U %G %n' /etc/dockscan/enrollment-token
```

Expected mode is `600`.

## 6. Enroll outbound from the agent

```bash
sudo dockscan agent --enroll \
  --controller controller.internal:45833 \
  --token-file /etc/dockscan/enrollment-token \
  --name agent-1 \
  --services step-ca,tailscale \
  --tls-ca /etc/dockscan/ca.pem \
  --tls-cert /etc/dockscan/agent.pem \
  --tls-key /etc/dockscan/agent-key.pem
```

The controller displays the certificate identity and source address for approval. After approval, it writes the redacted agent inventory to the controller output path.

Immediately remove the consumed token:

```bash
sudo rm -f /etc/dockscan/enrollment-token
```

## 7. Verify the result

On the controller:

```bash
python3 -m json.tool ./agent-1-inventory.json | less
```

Check the hostname, Docker version, expected containers, storage paths, and warnings. Create a recovery kit or blueprint only after you confirm the agent identity and inventory are correct.

## Optional: direct mTLS inventory server

Use only when an inbound port to the agent is acceptable. Create a temporary `0600` token file and start:

```bash
sudo dockscan agent --serve --bind 0.0.0.0 --port 45832 \
  --token-file /etc/dockscan/direct-token \
  --tls-ca /etc/dockscan/ca.pem \
  --tls-cert /etc/dockscan/agent.pem \
  --tls-key /etc/dockscan/agent-key.pem \
  --allowed-client-name controller-1
```

The agent requires mTLS and operator approval by default. Stop it with Ctrl+C and delete the temporary token file after collection.

`--allowed-client-name` currently matches the controller certificate **common name**. Give the controller certificate a controlled, unique CN and continue to enforce SAN restrictions in CA policy.

## Troubleshooting

| Symptom | Check |
|---|---|
| `connection refused` | Controller address, port, outbound firewall, and listener timeout. |
| TLS verification fails | CA bundle, certificate chain, system time, certificate SAN, and key permissions. |
| enrollment rejected | Token may be expired/used, controller operator may have rejected it, or the client identity is not accepted. |
| Docker unavailable | Run `docker info`; verify the agent user has Docker-socket access. |
| `FLAGGED OS` later | The recovery target differs from the scanned source; review it before restore. |

## Security checklist

- [ ] Agent private key and enrollment token are mode `0600`.
- [ ] Reusable CA provisioner passwords never leave the CA administrator host.
- [ ] Enrollment token is deleted after one use.
- [ ] Agent certificate has a stable, authorized SAN identity.
- [ ] Controller and agent clocks are synchronized.
- [ ] `--accept-insecure` is not used.
