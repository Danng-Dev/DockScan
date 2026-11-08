"""Versioned, capability-scoped integration registry for recovery plans.

Adapters intentionally describe preflight/verification requirements separately from
execution. Unknown mandatory adapters block a plan; unknown optional adapters warn.
"""
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Integration:
    identifier: str
    version: str
    capabilities: tuple[str, ...]
    required_secrets: tuple[str, ...]
    operations: tuple[str, ...]
    verification: tuple[str, ...]
    optional: bool = True


REGISTRY = {
    item.identifier: item for item in (
        Integration("docker-compose", "1", ("docker", "file.restore"), (), ("compose.restore", "image.pull"), ("docker.health", "container.running"), False),
        Integration("systemd", "1", ("systemd",), (), ("unit.restore", "unit.enable"), ("unit.active",), False),
        Integration("restic", "1", ("backup.restore",), ("backup-identity",), ("snapshot.verify", "files.restore"), ("repository.check",)),
        Integration("borg", "1", ("backup.restore",), ("backup-passphrase",), ("archive.verify", "files.restore"), ("repository.check",)),
        Integration("age", "1", ("backup.decrypt",), ("age-identity",), ("archive.decrypt",), ("archive.header",)),
        Integration("s3", "1", ("object-storage",), ("s3-credentials",), ("object.download",), ("object.head",)),
        Integration("caddy", "1", ("file.restore", "systemd"), (), ("caddy.restore", "caddy.reload"), ("caddy.validate", "https.route")),
        Integration("step-ca", "1", ("pki", "systemd"), ("ca-recovery-key",), ("ca.restore", "trust.distribute"), ("certificate.chain", "ca.health")),
        Integration("tailscale", "1", ("vpn",), ("tailscale-auth-key",), ("node.enroll", "routes.restore"), ("tailnet.status",)),
        Integration("postgresql", "1", ("database.restore",), ("database-password",), ("postgres.restore",), ("postgres.query",)),
        Integration("mariadb", "1", ("database.restore",), ("database-password",), ("mariadb.restore",), ("mariadb.query",)),
        Integration("sqlite", "1", ("file.restore",), (), ("sqlite.restore",), ("sqlite.integrity",)),
        Integration("cloudflare", "1", ("dns",), ("cloudflare-api-token",), ("dns.restore",), ("dns.resolve",)),
    )
}


def declarations(identifiers: set[str]) -> list[dict]:
    return [asdict(REGISTRY[item]) for item in sorted(identifiers) if item in REGISTRY]


def validate(required: list[dict]) -> dict:
    unknown_mandatory = [item["identifier"] for item in required if item["identifier"] not in REGISTRY and not item.get("optional", False)]
    unknown_optional = [item["identifier"] for item in required if item["identifier"] not in REGISTRY and item.get("optional", False)]
    return {"valid": not unknown_mandatory, "unknown_mandatory": unknown_mandatory, "unknown_optional": unknown_optional}
