"""Non-mutating local verification checks used by audit and dry-run sessions."""
import shutil
import subprocess
import hashlib
import platform
from pathlib import Path


def _check(command: list[str], label: str) -> dict:
    if not shutil.which(command[0]):
        return {"status": "unknown", "method": label, "reason": f"{command[0]} not installed"}
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    return {"status": "passed" if result.returncode == 0 else "failed", "method": label, "reason": (result.stderr or result.stdout).strip()[:300] or None}


def verify_task(task: dict) -> dict:
    expected = task.get("target_identity", {})
    machine_id = Path("/etc/machine-id")
    actual_id = hashlib.sha256(machine_id.read_bytes()).hexdigest() if machine_id.exists() else None
    if expected and (expected.get("hostname") != platform.node() or (expected.get("machine_id_sha256") and expected.get("machine_id_sha256") != actual_id)):
        return {"status": "blocked", "method": "machine identity check", "reason": "local host does not match blueprint target"}
    compatibility = os_compatibility(task.get("target_platform", {}))
    if compatibility["mismatch"]:
        return {"status": "warning", "method": "OS compatibility check", "reason": compatibility["message"], "flagged_os": True}
    kind = task.get("type")
    if kind == "preflight":
        return _check(["uname", "-a"], "host responds")
    if kind == "network":
        return _check(["ip", "route"], "routing table available")
    if kind == "storage":
        return _check(["findmnt"], "mount table available")
    if kind == "docker":
        return _check(["docker", "info"], "Docker daemon responds")
    if kind == "services":
        return _check(["docker", "ps"], "Docker service inventory available")
    return {"status": "unknown", "method": "no verifier", "reason": "unsupported task type"}


def os_compatibility(expected: dict) -> dict:
    """Flag—not silently ignore—restores attempted on a different OS release/CPU."""
    if not expected:
        return {"mismatch": False, "message": None}
    current = {"os": "unknown", "version": "unknown", "architecture": platform.machine()}
    release = Path("/etc/os-release")
    if release.exists():
        values = dict(line.split("=", 1) for line in release.read_text().splitlines() if "=" in line)
        current["os"] = values.get("ID", "unknown").strip('"')
        current["version"] = values.get("VERSION_ID", "unknown").strip('"')
    differences = [key for key in ("os", "version", "architecture") if expected.get(key, "unknown") != "unknown" and expected.get(key) != current[key]]
    return {"mismatch": bool(differences), "message": f"FLAGGED OS: source {expected}, target {current}; differences: {', '.join(differences)}" if differences else None}
