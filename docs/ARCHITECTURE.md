# Architecture

DockScan has five trust boundaries:

1. **Collector** — gathers host/Docker facts and redacts suspected secrets.
2. **Blueprint** — a checksummed, optionally signed `.dsrcvr` ZIP archive.
3. **Controller** — validates blueprints, plan policy, signatures, and recovery approvals.
4. **Agent** — exposes only declared capabilities through mTLS and short-lived enrollment.
5. **Evidence** — a redacted, signed record of the plan and outcome.

The recovery engine is audit-first. It generates declarative tasks and capability requirements; it does not accept arbitrary shell commands from blueprints.

## Data flow

```text
scan → inventory → .dsrcvr → signature/trust check → audit/preflight
                                              └→ approved agent capability → recovery handler → verification → evidence
```

Secrets are declared by ID. Values remain in an age-encrypted `.encsec` envelope or an external secret manager and must never appear in the blueprint, logs, generated documentation, or evidence bundle.
