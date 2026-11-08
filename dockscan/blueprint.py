"""Portable, integrity-checked .dsrcvr disaster-recovery blueprints."""
import hashlib
import json
import base64
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile

from . import __version__
from .models import HostInventory
from .recovery import safe_name
from .security import private_file
from .integrations import declarations
from .trust import fingerprint

FORMAT = "dsrcvr"
FORMAT_VERSION = "1.0.0"
MAX_ARCHIVE_FILES = 1_000
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def signing_payload(manifest: dict) -> bytes:
    """The manifest without mutable signature metadata, canonically serialized."""
    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    return canonical(unsigned)


def plan_hash(path: Path) -> str:
    with _validated_archive(path) as archive:
        return hashlib.sha256(archive.read("recovery/plan.json")).hexdigest()


def _openssl() -> str:
    executable = shutil.which("openssl")
    if not executable:
        raise RuntimeError("OpenSSL CLI not found. Install openssl to sign or verify blueprints.")
    return executable


def _read_archive(path: Path) -> tuple[dict[str, bytes], dict]:
    with _validated_archive(path) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    if "manifest.json" not in files:
        raise ValueError("manifest.json is missing")
    return files, json.loads(files["manifest.json"])


def _validated_archive(path: Path) -> ZipFile:
    archive = ZipFile(path)
    try:
        info = archive.infolist()
        names = [entry.filename for entry in info]
        if len(info) > MAX_ARCHIVE_FILES or len(set(names)) != len(names):
            raise ValueError("archive has too many or duplicate entries")
        size = sum(entry.file_size for entry in info)
        if size > MAX_ARCHIVE_BYTES:
            raise ValueError("archive exceeds the 128 MiB uncompressed safety limit")
        for entry in info:
            if entry.filename.startswith("/") or ".." in Path(entry.filename).parts:
                raise ValueError("unsafe archive path")
            if entry.file_size and entry.compress_size and entry.file_size / entry.compress_size > MAX_COMPRESSION_RATIO:
                raise ValueError("archive entry exceeds compression-ratio safety limit")
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("archive symlinks are not allowed")
        return archive
    except Exception:
        archive.close()
        raise


def _write_archive(path: Path, files: dict[str, bytes]) -> None:
    temporary = path.with_name(path.name + ".partial")
    if temporary.exists():
        temporary.unlink()
    try:
        with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
            for name, content in sorted(files.items()):
                archive.writestr(name, content)
        temporary.replace(path)
        private_file(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def secret_declarations(hosts: list[HostInventory]) -> list[dict]:
    declarations: list[dict] = []
    for host in hosts:
        for container in host.containers:
            container_name = container.get("Name", "unknown").lstrip("/")
            for item in container.get("Config", {}).get("Env") or []:
                key, _, value = item.partition("=")
                if value == "__REDACTED__":
                    declarations.append({"id": f"{safe_name(host.name)}-{safe_name(container_name)}-{safe_name(key)}", "name": key, "description": f"Environment value required by container {container_name} on {host.name}.", "type": "password", "required": True, "scope": host.name})
    return declarations


def machine_definition(host: HostInventory, priority: int) -> dict:
    operating = host.system.get("operating_system", {})
    return {"id": safe_name(host.name), "name": host.name, "role": "discovered-host", "platform": {"os": host.os_release.get("ID", "unknown"), "version": host.os_release.get("VERSION_ID", "unknown"), "architecture": operating.get("architecture", "unknown")}, "connection": {"type": "local" if host.hostname == host.name else "agent", "hostname": host.hostname, "authentication": "prompt"}, "agent": {"required": host.hostname != host.name, "status": "not-connected", "capabilities": ["inspection", "docker", "systemd", "verification"]}, "recovery": {"priority": priority, "requires_backup": bool(host.system.get("storage", {}).get("persistent_data"))}}


def plan_for(hosts: list[HostInventory], secrets: list[dict] | None = None) -> tuple[list[dict], list[dict]]:
    tasks: list[dict] = []
    verification: list[dict] = []
    for priority, host in enumerate(hosts, 1):
        machine = safe_name(host.name)
        prefix = f"{machine}-"
        groups = host.system.get("docker", {}).get("dependency_groups", {})
        task_specs = [
            ("preflight", "preflight", "inspection", [], "target validation and capacity check"),
            ("network", "network", "network", [prefix + "preflight"], "network and DNS reachable"),
            ("storage", "storage", "file.restore", [prefix + "network"], "required mounts exist"),
            ("docker", "docker.container.restore", "docker", [prefix + "storage"], "Docker daemon responds"),
            ("databases", "database.restore", "database.restore", [prefix + "docker"], "database connection and test query"),
            ("migrations", "docker.container.restore", "docker", [prefix + "databases"], "migration containers complete"),
            ("applications", "docker.compose.apply", "docker", [prefix + "migrations"], "expected application containers healthy"),
            ("proxy", "docker.compose.apply", "docker", [prefix + "applications"], "reverse proxy routes healthy"),
        ]
        for suffix, task_type, capability, depends, check in task_specs:
            task_id = prefix + suffix
            needed = [secret["id"] for secret in (secrets or []) if secret.get("scope") == host.name] if suffix in {"databases", "applications", "proxy"} else []
            phase = "preparation" if suffix == "preflight" else ("infrastructure" if suffix in {"network", "storage"} else "services")
            tasks.append({"id": task_id, "machine": machine, "capability": capability, "targets": groups.get({"databases": "databases", "migrations": "migrations", "applications": "applications", "proxy": "proxies"}.get(suffix, ""), []), "target_identity": host.system.get("identity", {"hostname": host.hostname}), "target_platform": {"os": host.os_release.get("ID", "unknown"), "version": host.os_release.get("VERSION_ID", "unknown"), "architecture": host.system.get("operating_system", {}).get("architecture", "unknown")}, "phase": phase, "type": task_type, "depends_on": depends, "verification": prefix + "verify-" + suffix, "required_secrets": needed, "status": "pending", "requires_approval": suffix != "preflight", "rollback": "partial" if suffix in {"storage", "databases"} else "not-possible"})
            verification.append({"id": prefix + "verify-" + suffix, "task": task_id, "method": check, "status": "not-run"})
    return tasks, verification


def create_blueprint(output: Path, hosts: list[HostInventory], environment: str = "DockScan environment", encrypted_secrets: Path | None = None) -> Path:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    secrets = secret_declarations(hosts)
    tasks, verification = plan_for(hosts, secrets)
    files: dict[str, bytes] = {}
    files["environment.json"] = canonical({"name": environment, "created_at": now, "last_scan_at": now, "source": "DockScan Linux discovery"})
    files["requirements/secrets.json"] = canonical({"secrets": secrets})
    if encrypted_secrets:
        from .encsec import inspect as inspect_encsec
        inspect_encsec(encrypted_secrets)
        files["requirements/secrets.encsec"] = encrypted_secrets.read_bytes()
    files["requirements/credentials.json"] = canonical({"credentials": [{"type": "agent-or-ssh", "required_for": safe_name(host.name), "status": "required"} for host in hosts]})
    integration_ids = {"docker-compose", "systemd"}
    for host in hosts:
        if host.services.get("step-ca", {}).get("service_installed"):
            integration_ids.add("step-ca")
        if host.services.get("tailscale", {}).get("available"):
            integration_ids.add("tailscale")
        if host.system.get("reverse_proxy", {}).get("caddy", {}).get("present"):
            integration_ids.add("caddy")
        integration_ids.update(host.system.get("backups", {}).get("detected_tools", []))
    files["requirements/integrations.json"] = canonical({"integrations": declarations(integration_ids)})
    files["requirements/dependencies.json"] = canonical({"capabilities": ["docker", "systemd", "network", "storage"], "integrations": sorted(integration_ids)})
    files["recovery/plan.json"] = canonical({"execution_mode": "audit", "tasks": tasks})
    files["recovery/verification.json"] = canonical({"checks": verification})
    files["recovery/rollback.json"] = canonical({"policy": "no automatic rollback", "note": "Destructive operations require an approved implementation and backup."})
    files["infrastructure/networking.json"] = canonical({safe_name(h.name): h.system.get("networking", {}) for h in hosts})
    files["infrastructure/storage.json"] = canonical({safe_name(h.name): h.system.get("storage", {}) for h in hosts})
    files["infrastructure/reverse-proxy.json"] = canonical({safe_name(h.name): h.system.get("reverse_proxy", {}) for h in hosts})
    files["services/docker.json"] = canonical({safe_name(h.name): {"version": h.docker_version, "containers": h.containers, "networks": h.networks, "volumes": h.volumes} for h in hosts})
    files["services/systemd.json"] = canonical({safe_name(h.name): h.system.get("services", {}) for h in hosts})
    for priority, host in enumerate(hosts, 1):
        files[f"machines/{safe_name(host.name)}.json"] = canonical(machine_definition(host, priority))
    checksums = {name: hashlib.sha256(content).hexdigest() for name, content in sorted(files.items())}
    manifest = {"format": FORMAT, "format_version": FORMAT_VERSION, "blueprint_id": "env-" + uuid4().hex[:12], "environment": environment, "created_at": now, "last_scan_at": now, "generated_by": {"application": "DockScan", "version": __version__}, "machines": len(hosts), "services": sum(len(h.containers) for h in hosts), "recovery": {"requires_remote_agents": len(hosts) > 1, "requires_secrets": bool(secrets), "supports_resume": True, "default_execution_mode": "audit"}, "policy": {"allowed_integrations": sorted(integration_ids), "allowed_agents": [safe_name(host.name) for host in hosts], "allowed_destinations": [host.hostname for host in hosts], "privileged_task_types": ["package.install", "file.restore", "docker.compose.apply", "docker.container.restore", "systemd.unit.enable", "database.restore", "firewall.apply", "dns.apply"], "custom_scripts": "signed-and-separately-approved"}, "checksums": checksums, "signature": {"status": "unsigned", "algorithm": None}}
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", canonical(manifest))
        for name, content in files.items():
            archive.writestr(name, content)
    private_file(output)
    return output


def inspect_blueprint(path: Path) -> dict:
    try:
        with _validated_archive(path) as archive:
            names = archive.namelist()
            if "manifest.json" not in names:
                raise ValueError("manifest.json is missing")
            manifest = json.loads(archive.read("manifest.json"))
            if manifest.get("format") != FORMAT or not str(manifest.get("format_version", "")).startswith("1."):
                raise ValueError("unsupported blueprint format/version")
            checksums = manifest.get("checksums", {})
            signature_file = manifest.get("signature", {}).get("file") if manifest.get("signature", {}).get("status") == "signed" else None
            allowed = {"manifest.json", *checksums}
            if signature_file:
                allowed.add(signature_file)
            unexpected = sorted(set(names) - allowed)
            if unexpected:
                raise ValueError("archive contains unmanifested artifacts: " + ", ".join(unexpected[:5]))
            failures = [name for name, digest in checksums.items() if name not in names or hashlib.sha256(archive.read(name)).hexdigest() != digest]
            return {"valid": not failures, "manifest": manifest, "checksum_failures": failures, "signature": manifest.get("signature", {}), "execution_allowed": False, "notice": "Blueprint inspection is audit-only. Unsigned blueprints require explicit trust before recovery execution."}
    except BadZipFile as exc:
        raise ValueError("invalid .dsrcvr archive") from exc


def sign_blueprint(path: Path, private_key: Path, signer: str, public_key: Path | None = None) -> None:
    """Add an OpenSSL signature while retaining artifact checksums and archive portability."""
    report = inspect_blueprint(path)
    if not report["valid"]:
        raise ValueError("refusing to sign a blueprint with invalid checksums")
    if not private_key.is_file():
        raise ValueError(f"private key not found: {private_key}")
    files, manifest = _read_archive(path)
    result = subprocess.run([_openssl(), "dgst", "-sha256", "-sign", str(private_key)], input=signing_payload(manifest), capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError("blueprint signing failed: " + result.stderr.decode(errors="replace").strip())
    manifest["signature"] = {"status": "signed", "algorithm": "openssl-dgst-sha256", "signer": signer, "public_key_fingerprint": fingerprint(public_key) if public_key else None, "plan_hash": hashlib.sha256(files["recovery/plan.json"]).hexdigest(), "file": "signatures/manifest.sig"}
    files["manifest.json"] = canonical(manifest)
    files["signatures/manifest.sig"] = base64.b64encode(result.stdout) + b"\n"
    _write_archive(path, files)


def verify_signature(path: Path, public_key: Path) -> dict:
    report = inspect_blueprint(path)
    if not report["valid"]:
        return {"valid": False, "reason": "artifact checksums failed"}
    files, manifest = _read_archive(path)
    signature = manifest.get("signature", {})
    location = signature.get("file")
    if signature.get("status") != "signed" or not location or location not in files:
        return {"valid": False, "reason": "blueprint is unsigned"}
    if not public_key.is_file():
        raise ValueError(f"public key not found: {public_key}")
    try:
        signature_bytes = base64.b64decode(files[location].strip(), validate=True)
    except ValueError as exc:
        return {"valid": False, "reason": "invalid signature encoding"}
    # OpenSSL cannot consume both the detached signature and payload through stdin.
    # Use short-lived local files instead, never storing them in the blueprint.
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        payload = Path(directory, "manifest.payload")
        detached = Path(directory, "manifest.sig")
        payload.write_bytes(signing_payload(manifest))
        detached.write_bytes(signature_bytes)
        result = subprocess.run([_openssl(), "dgst", "-sha256", "-verify", str(public_key), "-signature", str(detached), str(payload)], capture_output=True, check=False)
    actual = fingerprint(public_key)
    bound = signature.get("public_key_fingerprint")
    bound_valid = bound is None or bound == actual
    return {"valid": result.returncode == 0 and bound_valid, "signer": signature.get("signer"), "fingerprint": actual, "algorithm": signature.get("algorithm"), "reason": "public key does not match signed fingerprint" if not bound_valid else (result.stderr.decode(errors="replace").strip() if result.returncode else None)}


def recovery_plan(path: Path) -> dict:
    """Validate and topologically order recovery tasks; never executes them."""
    report = inspect_blueprint(path)
    if not report["valid"]:
        return {"valid": False, "reason": "artifact checksums failed", "tasks": []}
    with _validated_archive(path) as archive:
        if "recovery/plan.json" not in archive.namelist():
            raise ValueError("recovery plan is missing")
        tasks = json.loads(archive.read("recovery/plan.json")).get("tasks", [])
    by_id = {task.get("id"): task for task in tasks}
    if len(by_id) != len(tasks) or None in by_id:
        return {"valid": False, "reason": "task identifiers must be unique", "tasks": []}
    missing = {task["id"]: [dep for dep in task.get("depends_on", []) if dep not in by_id] for task in tasks}
    missing = {task: deps for task, deps in missing.items() if deps}
    if missing:
        return {"valid": False, "reason": "missing dependencies", "missing": missing, "tasks": []}
    remaining = {task_id: set(task.get("depends_on", [])) for task_id, task in by_id.items()}
    ordered: list[str] = []
    while remaining:
        ready = sorted(task_id for task_id, deps in remaining.items() if not deps)
        if not ready:
            return {"valid": False, "reason": "circular dependencies", "cycles": sorted(remaining), "tasks": []}
        ordered.extend(ready)
        for task_id in ready:
            remaining.pop(task_id)
        completed = set(ready)
        for dependencies in remaining.values():
            dependencies.difference_update(completed)
    return {"valid": True, "execution_mode": "audit", "ordered_task_ids": ordered, "tasks": [by_id[task_id] for task_id in ordered], "notice": "Plan validated only; no recovery commands were executed."}
