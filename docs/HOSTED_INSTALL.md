# Hosted installation

Host `scripts/bootstrap-install.sh` at a TLS-protected URL after reviewing and releasing it. It clones a specific repository ref into a temporary directory and runs that checkout’s `install.sh`.

Recommended user command:

```bash
curl -fsSL https://downloads.example.com/dockscan/bootstrap-install.sh | bash -s -- \
  --repository https://github.com/ORG/DockScan.git \
  --ref v0.1.0 --verify-tag
```

Before users run this, publish the repository’s signing-key fingerprint and release-tag verification instructions through an independent channel. Users must import the trusted Git signing key before `--verify-tag` can succeed.

## Hosting rules

- Serve over HTTPS with HSTS.
- Release immutable, signed tags; never document installation from `main`.
- Publish source tarball checksums and SBOMs per release.
- Keep bootstrap script changes small and reviewable.
- Do not embed tokens, private keys, analytics, or remote shell payloads.
- Offer the script as a downloadable file as well as a `curl | bash` convenience option.

The bootstrap script accepts only HTTPS Git URLs, requires an explicit tag or commit, and deletes its temporary checkout after installation.
