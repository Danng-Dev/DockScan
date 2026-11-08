# Security model

- Never use `--accept-insecure` except for isolated troubleshooting; it requires a second acknowledgement.
- Prefer outbound enrollment and mTLS with a CA-issued client identity.
- Pin permitted client identities with `--allowed-client-name`.
- Keep `.encsec` identities separate from blueprints and backups.
- Protect recovery kits, session records, token files, private keys, and agent environment files with owner-only permissions.
- Sign blueprints and evidence; trust only known, non-revoked signer fingerprints.
- Treat a blueprint as executable infrastructure configuration even though current recovery is audit-first.

If a secret may have been included or displayed, rotate it. Redaction is defense-in-depth, not proof that a secret never reached an artifact.
