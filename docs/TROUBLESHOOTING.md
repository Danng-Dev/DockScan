# Troubleshooting

## Installer reports permission denied

Use the current `install.sh` through Bash:

```bash
sudo bash install.sh
```

For hosted installation, use a pinned release tag. Do not use a floating branch.

## Docker is unavailable

Confirm the Docker daemon is running and the scan user can access its socket:

```bash
docker info
id
```

Add the operator to the `docker` group only if that level of Docker-root-equivalent access is appropriate.

## Agent cannot enroll

- Confirm controller hostname and port are reachable from the agent.
- Confirm agent/client certificates chain to the configured CA.
- Confirm the certificate identity is allowed by the agent policy.
- Check token-file ownership and `0600` permissions.
- Make sure the enrollment token has not expired or been used.

## `FLAGGED OS` appears

The recovery target is not equivalent to the scanned source. Review package managers, architecture, storage, firewall backend, systemd unit naming, and Docker storage before proceeding. This is a warning by design, not an error to suppress.

## Blueprint fails inspection

Do not extract or modify it. Check the reported checksum, archive-path, duplicate-entry, or signature failure. Obtain a known-good copy from protected backup, then re-run inspection.

## Static site is blank or missing pages

Pass the recovery kit’s `docs` directory, not the recovery-kit root:

```bash
dockscan staticify --input ./recovery-kit/docs --output ./recovery-kit/site
```
