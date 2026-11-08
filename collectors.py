import json
import os
import platform
import re
import shutil
import subprocess
try:  # POSIX-only modules; keeping importable elsewhere helps test/package tooling.
    import pwd
    import grp
except ModuleNotFoundError:  # pragma: no cover - DockScan targets Linux
    pwd = None
    grp = None
from pathlib import Path
from typing import Any

from .models import HostInventory

SENSITIVE = re.compile(r"(?:pass(?:word)?|secret|token|api[_-]?key|private[_-]?key|credential)", re.I)


def run(command: list[str]) -> tuple[str, str, int]:
    try:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        return result.stdout, result.stderr.strip(), result.returncode
    except FileNotFoundError:
        return "", f"command not found: {command[0]}", 127


def os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values


def secret_value(key: str, value: str, include_secrets: bool, secret_mode: str) -> str:
    if include_secrets or not SENSITIVE.search(key):
        return value
    if secret_mode == "ignore":
        return "__REDACTED__"
    try:
        answer = input(f"Suspected secret in {key} (value hidden). Is this a secret? [Y/n] ").strip().lower()
    except EOFError:
        answer = ""
    return "__REDACTED__" if answer in ("", "y", "yes") else value


def redact_environment(env: list[str], include_secrets: bool, secret_mode: str = "ignore") -> list[str]:
    result = []
    for item in env:
        key, _, value = item.partition("=")
        result.append(f"{key}={secret_value(key, value, include_secrets, secret_mode)}")
    return result


def redact_mapping(values: dict[str, Any], include_secrets: bool, secret_mode: str = "ignore") -> dict[str, Any]:
    return {key: secret_value(key, str(value), include_secrets, secret_mode) for key, value in values.items()}


def docker_json(args: list[str]) -> Any:
    stdout, stderr, code = run(["docker", *args])
    if code:
        raise RuntimeError(stderr or "docker command failed")
    return json.loads(stdout or "[]")


def docker_inventory(include_secrets: bool, secret_mode: str = "ignore") -> tuple[list[dict], list[dict], list[dict], list[str]]:
    warnings: list[str] = []
    if not shutil.which("docker"):
        return [], [], [], ["Docker CLI is not installed or not on PATH."]
    stdout, stderr, code = run(["docker", "version", "--format", "{{json .Server}}"])
    if code:
        return [], [], [], [f"Docker is unavailable: {stderr or 'cannot reach daemon'}"]
    ids, _, _ = run(["docker", "ps", "-aq"])
    containers: list[dict] = []
    for container_id in ids.split():
        try:
            raw = docker_json(["inspect", container_id])[0]
            config = raw.get("Config", {})
            config["Env"] = redact_environment(config.get("Env") or [], include_secrets, secret_mode)
            config["Labels"] = redact_mapping(config.get("Labels") or {}, include_secrets, secret_mode)
            raw["Config"] = config
            containers.append(raw)
        except (RuntimeError, IndexError, json.JSONDecodeError) as exc:
            warnings.append(f"Could not inspect container {container_id}: {exc}")
    try:
        networks = docker_json(["network", "ls", "--format", "{{json .}}"])
        if isinstance(networks, dict):
            networks = [networks]
    except (RuntimeError, json.JSONDecodeError) as exc:
        networks = []
        warnings.append(f"Could not list networks: {exc}")
    try:
        volumes = docker_json(["volume", "ls", "--format", "{{json .}}"])
        if isinstance(volumes, dict):
            volumes = [volumes]
    except (RuntimeError, json.JSONDecodeError) as exc:
        volumes = []
        warnings.append(f"Could not list volumes: {exc}")
    return containers, networks, volumes, warnings


def service_inventory(services: set[str]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    if "tailscale" in services:
        stdout, stderr, code = run(["tailscale", "status", "--json"])
        found["tailscale"] = json.loads(stdout) if code == 0 else {"available": False, "reason": stderr or "tailscale not installed"}
    if "step-ca" in services:
        config = Path("/etc/step-ca/config/ca.json")
        found["step-ca"] = {
            "config_exists": config.exists(),
            "config_path": str(config),
            "service_installed": shutil.which("step-ca") is not None,
        }
    return found


def json_command(command: list[str]) -> Any:
    stdout, _, code = run(command)
    if code != 0 or not stdout.strip():
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def lines_if_available(command: list[str], limit: int = 200) -> list[str]:
    stdout, _, code = run(command)
    return stdout.splitlines()[:limit] if code == 0 else []


def docker_summary(containers: list[dict]) -> dict[str, Any]:
    images = sorted({c.get("Config", {}).get("Image", "unknown") for c in containers})
    projects: dict[str, list[str]] = {}
    compose_files: dict[str, list[str]] = {}
    image_digests: dict[str, list[str]] = {}
    dependency_groups: dict[str, list[str]] = {"databases": [], "migrations": [], "applications": [], "proxies": []}
    persistent_paths: list[dict[str, str]] = []
    for container in containers:
        name = container.get("Name", "").lstrip("/")
        labels = container.get("Config", {}).get("Labels") or {}
        project = labels.get("com.docker.compose.project")
        if project:
            projects.setdefault(project, []).append(name)
            files = labels.get("com.docker.compose.project.config_files") or labels.get("com.docker.compose.project.config_files") or labels.get("com.docker.compose.project.working_dir")
            if files:
                compose_files[project] = [item for item in files.split(",") if item]
        image = container.get("Config", {}).get("Image", "")
        if image and image not in image_digests:
            try:
                inspected = docker_json(["image", "inspect", image])[0]
                image_digests[image] = inspected.get("RepoDigests") or []
            except (RuntimeError, IndexError, json.JSONDecodeError):
                image_digests[image] = []
        description = (name + " " + image).lower()
        group = "applications"
        if any(word in description for word in ("postgres", "mariadb", "mysql", "redis", "mongo", "sqlite")):
            group = "databases"
        elif any(word in description for word in ("migrate", "migration", "schema")):
            group = "migrations"
        elif any(word in description for word in ("caddy", "nginx", "traefik", "haproxy")):
            group = "proxies"
        dependency_groups[group].append(name)
        for mount in container.get("Mounts") or []:
            if mount.get("Source"):
                persistent_paths.append({"container": name, "type": mount.get("Type", "unknown"), "path": mount["Source"]})
    return {"images": images, "image_digests": image_digests, "compose_projects": projects, "compose_files": compose_files, "persistent_paths": persistent_paths, "dependency_groups": dependency_groups}


def caddy_inventory() -> dict[str, Any]:
    paths = [Path("/etc/caddy/Caddyfile"), Path("/etc/caddy/caddy.json")]
    config = next((path for path in paths if path.exists()), None)
    if not config:
        return {"present": False}
    # A hostname-only summary documents routing without exposing config values.
    text = config.read_text(errors="replace")
    domains = sorted(set(re.findall(r"(?m)^\s*([A-Za-z0-9*][A-Za-z0-9*.-]+\.[A-Za-z]{2,})\s*(?:\{|$)", text)))
    return {"present": True, "config_path": str(config), "domains": domains, "routing_directives": text.count("reverse_proxy")}


def backup_inventory() -> dict[str, Any]:
    candidates = [Path("/etc/borgmatic/config.yaml"), Path("/etc/restic"), Path("/etc/backup"), Path("/etc/cron.d")]
    found = [str(path) for path in candidates if path.exists()]
    timer_lines = [line for line in lines_if_available(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"]) if any(x in line.lower() for x in ("backup", "borg", "restic"))]
    tools = [tool for tool in ("restic", "borg", "rsync") if command_exists(tool)]
    commands = []
    if "restic" in tools:
        commands.append("restic snapshots  # requires RESTIC_REPOSITORY and credentials from secret manager")
    if "borg" in tools:
        commands.append("borg list <repository>  # obtain repository and passphrase from secret manager")
    return {"configuration_locations": found, "backup_timers": timer_lines, "detected_tools": tools, "restore_commands": commands, "manual_investigation": not bool(found or timer_lines)}


def system_inventory(containers: list[dict]) -> dict[str, Any]:
    packages = lines_if_available(["dpkg-query", "-W", "-f=${binary:Package} ${Version}\\n"], 5000)
    users = [{"name": item.pw_name, "uid": item.pw_uid, "gid": item.pw_gid, "home": item.pw_dir, "shell": item.pw_shell} for item in pwd.getpwall()] if pwd else []
    groups = [{"name": item.gr_name, "gid": item.gr_gid, "members": item.gr_mem} for item in grp.getgrall()] if grp else []
    firewall = "unknown"
    firewall_rules: list[str] = []
    if command_exists("ufw"):
        firewall = "ufw"
        firewall_rules = lines_if_available(["ufw", "status", "numbered"])
    elif command_exists("nft"):
        firewall = "nftables"
        firewall_rules = lines_if_available(["nft", "list", "ruleset"], 1000)
    elif command_exists("iptables-save"):
        firewall = "iptables"
        firewall_rules = lines_if_available(["iptables-save"], 1000)
    sshd = Path("/etc/ssh/sshd_config")
    security = {"ssh_config": str(sshd) if sshd.exists() else None, "fail2ban": command_exists("fail2ban-client"), "apparmor": command_exists("aa-status"), "firewall": firewall, "firewall_rules": firewall_rules}
    backup = backup_inventory()
    persistent = docker_summary(containers)["persistent_paths"]
    # Coverage cannot be proven without reading credential-bearing backup configuration.
    backup["unverified_persistent_paths"] = [item["path"] for item in persistent]
    machine_id = Path("/etc/machine-id")
    identity = {"hostname": platform.node(), "machine_id_sha256": __import__("hashlib").sha256(machine_id.read_bytes()).hexdigest() if machine_id.exists() else None}
    return {
        "identity": identity,
        "operating_system": {"architecture": platform.machine(), "packages": packages, "users": users, "groups": groups},
        "networking": {"interfaces": json_command(["ip", "-json", "address"]), "routes": json_command(["ip", "-json", "route"]), "dns_config": Path("/etc/resolv.conf").read_text(errors="replace").splitlines() if Path("/etc/resolv.conf").exists() else []},
        "security": security,
        "storage": {"block_devices": json_command(["lsblk", "--json", "--output", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS"]), "mounts": json_command(["findmnt", "--json"]), "persistent_data": persistent},
        "docker": docker_summary(containers),
        "reverse_proxy": {"caddy": caddy_inventory()},
        "backups": backup,
        "services": {"enabled_units": lines_if_available(["systemctl", "list-unit-files", "--state=enabled", "--no-pager", "--no-legend"], 1000), "timers": lines_if_available(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"], 1000)},
    }


def collect(name: str | None = None, include_secrets: bool = False, services: set[str] | None = None, secret_mode: str = "ignore") -> HostInventory:
    containers, networks, volumes, warnings = docker_inventory(include_secrets, secret_mode)
    version, _, code = run(["docker", "version", "--format", "{{.Server.Version}}"])
    return HostInventory(
        name=name or platform.node(), hostname=platform.node(), os_release=os_release(),
        kernel=platform.release(), docker_version=version.strip() if code == 0 else None,
        containers=containers, networks=networks, volumes=volumes,
        services=service_inventory(services or set()), system=system_inventory(containers), warnings=warnings,
    )
