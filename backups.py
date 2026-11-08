"""Read-only backup availability checks; credentials remain in the caller environment."""
import shutil
import subprocess
from pathlib import Path
from .security import redacted_text


def verify_backup(kind: str, location: str | None = None, bucket: str | None = None, key: str | None = None) -> dict:
    if kind == "age":
        if not location:
            raise ValueError("--location is required for age archives")
        data = Path(location).read_bytes()
        return {"type": "age", "available": data.startswith(b"age-encryption.org/"), "verification": "age header present; decryption identity not tested"}
    commands = {"restic": ["restic", "snapshots", "--json"], "borg": ["borg", "list", "--json"]}
    if kind == "s3":
        if not bucket or not key:
            raise ValueError("S3 verification requires --bucket and --key")
        command = ["aws", "s3api", "head-object", "--bucket", bucket, "--key", key]
    else:
        if not location:
            raise ValueError(f"--location is required for {kind}")
        command = commands[kind] + ([location] if kind == "borg" else ["--repo", location])
    if not shutil.which(command[0]):
        return {"type": kind, "available": False, "reason": f"{command[0]} CLI not installed"}
    result = subprocess.run(command, capture_output=True, check=False)
    return {"type": kind, "available": result.returncode == 0, "verification": "repository/object reachable" if result.returncode == 0 else "verification failed", "reason": redacted_text(result.stderr.decode(errors="replace").strip()[:300]) if result.returncode else None}
