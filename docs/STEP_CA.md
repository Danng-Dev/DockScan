# Step CA and DockScan

DockScan uses Step CA-issued certificates for mTLS agent identity. Keep CA root/intermediate keys, database, provisioner credentials, and renewal configuration outside recovery kits; the kit records locations and requirements, not private contents.

## Enroll a controller or agent identity

```bash
dockscan step-ca enroll --ca-url https://ca.internal --fingerprint '<fingerprint>' \
  --name controller-1 --san controller-1.internal
```

The command bootstraps the root of trust and creates `/etc/dockscan/controller-1.pem` plus an owner-private key. Use the paths with the controller or agent mTLS options.

## Create a dedicated DockScan JWK provisioner

Run this **on the CA host** as an administrator. It uses `step ca provisioner add --type JWK --create --password-file` rather than hand-editing `ca.json`, which Step recommends for correct encoding and compatibility. It creates a timestamped `ca.json` backup, generates a 48-byte OpenSSL password into a new `0600` file, adds the provisioner, and restarts the requested service.

Preview first:

```bash
sudo dockscan step-ca provisioner create --name dockscan-agents --dry-run
```

Apply only after reviewing the CA backup location, password-file location, service name, and resulting issuance policy:

```bash
sudo dockscan step-ca provisioner create --name dockscan-agents \
  --password-file /etc/step-ca/secrets/dockscan-agents.password \
  --service step-ca --apply --confirm dockscan-agents
```

Do not expose the generated password file, commit it, or copy it into a `.dsrcvr` blueprint. Restrict its directory to the CA administrator and back it up according to your CA key-management policy.

## Renewal

Prefer short-lived client certificates plus a systemd timer that runs `step ca renew` and reloads the dependent service. Renewal uses the existing key and certificate for mTLS authentication, so restrict key read access and monitor expiry/renewal failures. See the official [Step CA renewal guide](https://smallstep.com/docs/step-ca/renewal/).

## CA recovery order

1. Restore CA storage/database and root/intermediate key material from protected backup.
2. Restore `ca.json`, provisioner password files, and systemd service configuration.
3. Start `step-ca`; validate the trust chain and health endpoint.
4. Restore/renew agent and controller certificates.
5. Restore reverse proxies and dependent applications.
