import json
import re
import hashlib
import os
from pathlib import Path
from typing import Any

from .models import HostInventory
from .security import private_directory, private_file


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", value).strip("_") or "host"


def yaml_scalar(value: Any) -> str:
    return json.dumps(value)


def container_task(container: dict[str, Any]) -> str:
    cfg, host = container.get("Config", {}), container.get("HostConfig", {})
    name = container.get("Name", "").lstrip("/")
    lines = ["    - name: Restore " + name, "      community.docker.docker_container:", f"        name: {yaml_scalar(name)}",
             f"        image: {yaml_scalar(cfg.get('Image', ''))}", "        state: started", "        restart_policy: " + yaml_scalar(host.get("RestartPolicy", {}).get("Name") or "no")]
    if cfg.get("Env"):
        lines.extend(["        env:"] + [f"          {yaml_scalar(item.split('=', 1)[0])}: {yaml_scalar(item.split('=', 1)[1] if '=' in item else '')}" for item in cfg["Env"]])
    mounts = container.get("Mounts") or []
    if mounts:
        lines.append("        mounts:")
        for mount in mounts:
            source, target = mount.get("Source"), mount.get("Destination")
            if source and target:
                lines.extend([f"          - source: {yaml_scalar(source)}", f"            target: {yaml_scalar(target)}", f"            type: {yaml_scalar(mount.get('Type', 'bind'))}", f"            read_only: {str(not mount.get('RW', True)).lower()}"])
    if cfg.get("Entrypoint"):
        lines.append("        entrypoint: " + yaml_scalar(cfg["Entrypoint"]))
    if cfg.get("Cmd"):
        lines.append("        command: " + yaml_scalar(cfg["Cmd"]))
    if host.get("NetworkMode"):
        lines.append("        network_mode: " + yaml_scalar(host["NetworkMode"]))
    ports = host.get("PortBindings") or {}
    if ports:
        lines.append("        published_ports:")
        for private, bindings in ports.items():
            for bind in bindings or []:
                address = bind.get("HostIp") or "0.0.0.0"
                lines.append("          - " + yaml_scalar(f"{address}:{bind.get('HostPort')}:{private}"))
    return "\n".join(lines)


def write_recovery_kit(output: Path, hosts: list[HostInventory]) -> None:
    private_directory(output)
    private_directory(output / "manifests")
    ansible = output / "ansible"
    private_directory(ansible / "host_vars")
    private_directory(ansible / "generated")
    private_directory(output / "docs")
    data = {"schema_version": 1, "hosts": [host.to_dict() for host in hosts]}
    (output / "inventory.json").write_text(json.dumps(data, indent=2) + "\n")
    private_file(output / "inventory.json")
    inv_lines = ["[homelab]"]
    play_hosts = []
    for host in hosts:
        ident = safe_name(host.name)
        play_hosts.append(ident)
        inv_lines.append(f"{ident} ansible_host={host.hostname}")
        (output / "manifests" / f"{ident}.json").write_text(json.dumps(host.to_dict(), indent=2) + "\n")
        private_file(output / "manifests" / f"{ident}.json")
        tasks = "\n\n".join(container_task(c) for c in host.containers) or "    # No containers discovered.\n"
        (ansible / "generated" / f"{ident}.yml").write_text("---\n" + tasks + "\n")
        private_file(ansible / "generated" / f"{ident}.yml")
        (ansible / "host_vars" / f"{ident}.yml").write_text("recovery_container_tasks: |\n" + "\n".join("  " + line for line in tasks.splitlines()) + "\n")
        private_file(ansible / "host_vars" / f"{ident}.yml")
    (ansible / "inventory.ini").write_text("\n".join(inv_lines) + "\n")
    private_file(ansible / "inventory.ini")
    play = '''---
- name: Recover Docker homelab
  hosts: homelab
  become: true
  gather_facts: true
  tasks:
    - name: Install Docker engine on Debian-family hosts
      ansible.builtin.apt:
        name: docker.io
        state: present
        update_cache: true
      when: ansible_facts.os_family == "Debian"
    - name: Install Docker engine on RedHat-family hosts
      ansible.builtin.dnf:
        name: docker
        state: present
      when: ansible_facts.os_family == "RedHat"
    - name: Start Docker
      ansible.builtin.service:
        name: docker
        state: started
        enabled: true
    - name: Restore discovered containers
      ansible.builtin.include_tasks: "{{ playbook_dir }}/restore-containers.yml"
'''
    (ansible / "recover.yml").write_text(play)
    private_file(ansible / "recover.yml")
    (ansible / "restore-containers.yml").write_text("---\n- name: Restore this host's discovered containers\n  ansible.builtin.include_tasks: '{{ playbook_dir }}/generated/{{ inventory_hostname }}.yml'\n")
    private_file(ansible / "restore-containers.yml")
    write_docs(output, hosts)
    write_artifacts(output, hosts)


def write_artifacts(output: Path, hosts: list[HostInventory]) -> None:
    """Capture only local, allowlisted configuration files and redact before writing."""
    root = output / "artifacts" / "compose"
    private_directory(root)
    metadata: list[dict] = []
    sensitive_line = re.compile(r"(?i)(password|secret|token|api[_-]?key|private[_-]?key|credential)(\s*[:=]\s*)([^\s#]+)")
    for host in hosts:
        files = host.system.get("docker", {}).get("compose_files", {})
        for project, paths in files.items():
            for source in paths:
                candidate = Path(source)
                if not candidate.is_file() or candidate.stat().st_size > 1_048_576:
                    metadata.append({"source": source, "project": project, "status": "not-captured", "reason": "unavailable, remote, or exceeds 1 MiB allowlist"})
                    continue
                try:
                    original = candidate.read_text(errors="replace")
                    redacted = sensitive_line.sub(r"\1\2__REDACTED__", original)
                    target_dir = root / safe_name(host.name) / safe_name(project)
                    private_directory(target_dir)
                    target = target_dir / safe_name(candidate.name)
                    target.write_text(redacted)
                    private_file(target)
                    metadata.append({"source": source, "artifact": str(target.relative_to(output)), "project": project, "sha256": hashlib.sha256(redacted.encode()).hexdigest(), "mode": oct(candidate.stat().st_mode & 0o777), "owner_uid": candidate.stat().st_uid if hasattr(candidate.stat(), "st_uid") else None, "status": "captured-redacted"})
                except OSError as exc:
                    metadata.append({"source": source, "project": project, "status": "not-captured", "reason": str(exc)})
    manifest = output / "artifacts" / "manifest.json"
    private_directory(manifest.parent)
    manifest.write_text(json.dumps({"artifacts": metadata}, indent=2) + "\n")
    private_file(manifest)


def write_docs(output: Path, hosts: list[HostInventory]) -> None:
    rows = []
    details = []
    for host in hosts:
        system = host.system
        docker = system.get("docker", {})
        backup = system.get("backups", {})
        security = system.get("security", {})
        caddy = system.get("reverse_proxy", {}).get("caddy", {})
        rows.append(f"| {host.name} | {host.hostname} | {host.docker_version or 'unavailable'} | {len(host.containers)} |")
        persistent = docker.get("persistent_paths", [])
        backup_paths = "\n".join(f"- {x['path']} ({x['type']}, used by {x['container']})" for x in persistent) or "- None detected"
        dependencies = dependency_notes(host)
        details.append(f'''## {host.name}

### Operating system — verified

- OS: {host.os_release.get('PRETTY_NAME', 'unknown')}; kernel: {host.kernel or 'unknown'}; architecture: {system.get('operating_system', {}).get('architecture', 'unknown')}
- Installed package list, users, and groups are in `manifests/{safe_name(host.name)}.json`.

### Networking and security — verified where available

- Interfaces, addresses, DNS configuration, routes, and firewall rules are in the host manifest.
- SSH configuration: {security.get('ssh_config') or 'not found'}; fail2ban: {security.get('fail2ban')}; AppArmor: {security.get('apparmor')}; firewall: {security.get('firewall', 'unknown')}.

### Docker and reverse proxy — verified

- Images: {', '.join(docker.get('images', [])) or 'none'}
- Networks: {', '.join(n.get('Name', '?') for n in host.networks) or 'none'}; volumes: {', '.join(v.get('Name', '?') for v in host.volumes) or 'none'}
- Compose projects: {', '.join(docker.get('compose_projects', {}).keys()) or 'none detected'}
- Caddy: {'configured at ' + caddy.get('config_path', '') if caddy.get('present') else 'not detected'}; domains: {', '.join(caddy.get('domains', [])) or 'none discovered'}.

### Storage and backup coverage — inferred

Persistent Docker paths:
{backup_paths}

- Backup configuration locations: {', '.join(backup.get('configuration_locations', [])) or 'none discovered'}
- Detected backup tools: {', '.join(backup.get('detected_tools', [])) or 'none'}; scheduled jobs: {len(backup.get('backup_timers', []))}.
- **Missing-backup candidates:** {', '.join(backup.get('unverified_persistent_paths', [])) or 'none'}. These are deliberately marked unverified because coverage cannot be proven without reading credential-bearing backup configuration.
- **Manual investigation:** confirm every path above is included in backups, record backup destination/encryption recipients in the secret manager, and test the listed restore command. DockScan intentionally does not read credentials or private keys.

### Recovery dependencies — inferred

{dependencies}
''')
    inventory = "# Homelab inventory\n\n| Host | Address | Docker | Containers |\n|---|---|---|---:|\n" + "\n".join(rows) + "\n\n" + "\n".join(details)
    recovery = '''# Recovery runbook

1. Restore this directory from protected backup. Inventory values may include sensitive configuration.
2. Restore Docker named volumes and every bind-mount path shown in `manifests/*.json` from backups. Docker inspection does **not** contain bind-mount data.
3. Review each `ansible/generated/*.yml`; replace `__REDACTED__` environment values from a secret manager.
4. Install the Ansible Docker collection: `ansible-galaxy collection install community.docker`.
5. Review container ports, mounts, images, and capabilities before applying. Start services in dependency order (databases, identity/PKI, applications).
6. Run `ansible-playbook -i ansible/inventory.ini ansible/recover.yml`.

## Optional services

- **Step CA:** protect `/etc/step-ca`, the CA database, root/intermediate keys, and provisioner secrets. Restore its storage before starting `step-ca`; rotate/revoke credentials if the recovery kit was exposed.
- **Tailscale:** reinstall the client, authenticate using an ephemeral/pre-auth key or interactive login, then confirm ACLs and subnet routes in the tailnet admin console. Do not treat a node state file as a portable credential.
'''
    (output / "docs" / "INVENTORY.md").write_text(inventory)
    private_file(output / "docs" / "INVENTORY.md")
    (output / "docs" / "RECOVERY.md").write_text(recovery)
    private_file(output / "docs" / "RECOVERY.md")
    commands = "# Generated restore commands\n\nCommands are guidance only; DockScan never executes them. Supply secrets from your secret manager.\n\n"
    for host in hosts:
        commands += f"## {host.name}\n\n```bash\nansible-galaxy collection install community.docker\nansible-playbook -i ansible/inventory.ini ansible/recover.yml --limit {safe_name(host.name)}\n"
        for command in host.system.get("backups", {}).get("restore_commands", []):
            commands += command + "\n"
        commands += "```\n\n"
    (output / "docs" / "RESTORE_COMMANDS.md").write_text(commands)
    private_file(output / "docs" / "RESTORE_COMMANDS.md")
    confidence = '''# Confidence indicators

- **Verified:** directly returned by a local command or Docker API during this scan. It can still be stale immediately after collection.
- **Inferred:** derived from labels, paths, service names, or conventional configuration locations; review before acting.
- **Manual investigation:** intentionally not proven by DockScan, usually because proving it would require reading secrets, remote backup repositories, or private keys.

All generated restore commands are proposals for review and are never executed by DockScan.
'''
    (output / "docs" / "CONFIDENCE.md").write_text(confidence)
    private_file(output / "docs" / "CONFIDENCE.md")
    write_operational_docs(output, hosts)


def write_operational_docs(output: Path, hosts: list[HostInventory]) -> None:
    """Write navigable runbooks from the same structured inventory as the manifest."""
    docs = output / "docs"
    overview = ["# System documentation", "", "Generated from the scan inventory. Start with the recovery runbook, then use the per-machine documents for implementation details.", "", "## Documents", "", "- [Inventory](INVENTORY.md) — scan summary and confidence levels", "- [Recovery runbook](RECOVERY.md) — ordered recovery process", "- [Backup coverage](BACKUP_COVERAGE.md) — persistent-data and coverage gaps", "- [Service catalog](SERVICE_CATALOG.md) — Docker services, images, and ordering", "- [Network map](NETWORK.md) — addressing, routes, DNS, and exposure", "- [Generated artifacts](../artifacts/manifest.json) — redacted configuration capture status", "", "## Machines", "", "| Machine | Role | Recovery document |", "|---|---|---|"]
    backup_rows = ["# Backup coverage", "", "A path is **unverified** until a backup adapter or a restore drill proves that it is recoverable.", "", "| Machine | Persistent path | Type | Consumer | Coverage |", "|---|---|---|---|---|"]
    service_rows = ["# Service catalog", "", "Image digests are preferred over tags for reproducible recovery. `none recorded` means the registry/digest must be checked before restore.", "", "| Machine | Service | Image | Digest | Group | Restart |", "|---|---|---|---|---|---|"]
    network_sections = ["# Network map", "", "This document is a scan-time description, not a firewall change plan. Validate addresses and routes before restoration."]
    for host in hosts:
        ident = safe_name(host.name)
        overview.append(f"| {host.name} | discovered host | [Open](MACHINE_{ident}.md) |")
        docker = host.system.get("docker", {})
        backup = host.system.get("backups", {})
        unverified = set(backup.get("unverified_persistent_paths", []))
        for item in docker.get("persistent_paths", []):
            coverage = "unverified — restore drill required" if item["path"] in unverified else "not applicable"
            backup_rows.append(f"| {host.name} | `{item['path']}` | {item['type']} | {item['container']} | {coverage} |")
        if not docker.get("persistent_paths"):
            backup_rows.append(f"| {host.name} | — | — | — | no persistent Docker mounts discovered |")
        groups = docker.get("dependency_groups", {})
        group_for = {name: group for group, names in groups.items() for name in names}
        digests = docker.get("image_digests", {})
        for container in host.containers:
            cfg, hc = container.get("Config", {}), container.get("HostConfig", {})
            name, image = container.get("Name", "?").lstrip("/"), cfg.get("Image", "?")
            digest = ", ".join(digests.get(image, [])) or "none recorded"
            restart = hc.get("RestartPolicy", {}).get("Name") or "no"
            service_rows.append(f"| {host.name} | {name} | `{image}` | `{digest}` | {group_for.get(name, 'applications')} | {restart} |")
        network = host.system.get("networking", {})
        network_sections.extend([f"\n## {host.name}", "", f"- DNS configuration: `{'; '.join(network.get('dns_config', [])) or 'not discovered'}`", f"- Docker networks: {', '.join(item.get('Name', '?') for item in host.networks) or 'none'}", f"- Firewall: {host.system.get('security', {}).get('firewall', 'unknown')}", "- Full interface and route data: `../manifests/" + ident + ".json`."])
        write_machine_doc(docs / f"MACHINE_{ident}.md", host)
    for target, content in ((docs / "SYSTEM_OVERVIEW.md", "\n".join(overview) + "\n"), (docs / "BACKUP_COVERAGE.md", "\n".join(backup_rows) + "\n"), (docs / "SERVICE_CATALOG.md", "\n".join(service_rows) + "\n"), (docs / "NETWORK.md", "\n".join(network_sections) + "\n")):
        target.write_text(content)
        private_file(target)


def write_machine_doc(target: Path, host: HostInventory) -> None:
    system = host.system
    docker = system.get("docker", {})
    caddy = system.get("reverse_proxy", {}).get("caddy", {})
    lines = [f"# Machine runbook: {host.name}", "", "## Identity and platform", "", f"- Address: `{host.hostname}`", f"- OS: {host.os_release.get('PRETTY_NAME', 'unknown')}", f"- Kernel: `{host.kernel or 'unknown'}`", f"- Architecture: `{system.get('operating_system', {}).get('architecture', 'unknown')}`", f"- Docker: `{host.docker_version or 'unavailable'}`", "", "## Restore checklist", "", "1. Confirm this target matches the expected machine identity and OS compatibility warning status.", "2. Restore all persistent paths listed in `BACKUP_COVERAGE.md` before starting containers.", "3. Restore databases, then migrations, applications, and reverse proxy services.", "4. Replace every `__REDACTED__` value from the approved secret source.", "5. Run the generated verification/audit workflow and record an evidence bundle.", "", "## Compose and service topology", ""]
    for project, paths in docker.get("compose_files", {}).items():
        lines.append(f"- **{project}:** " + ", ".join(f"`{path}`" for path in paths))
    if not docker.get("compose_files"):
        lines.append("- No Compose configuration file location was discovered; inspect Docker labels and generated artifacts.")
    lines.extend(["", "## Reverse proxy and certificates", "", f"- Caddy configuration: `{caddy.get('config_path', 'not discovered')}`", f"- Domains: {', '.join(caddy.get('domains', [])) or 'none discovered'}", f"- Step CA detected: {host.services.get('step-ca', {}).get('service_installed', False)}", f"- Tailscale detected: {host.services.get('tailscale', {}).get('available', False)}", "", "## Source of truth", "", f"- Full machine inventory: `../manifests/{safe_name(host.name)}.json`", "- Generated Ansible task file: `../ansible/generated/" + safe_name(host.name) + ".yml`", "- Redacted artifacts: `../artifacts/manifest.json`", ""])
    target.write_text("\n".join(lines))
    private_file(target)


def dependency_notes(host: HostInventory) -> str:
    names = " ".join(c.get("Name", "") + " " + c.get("Config", {}).get("Image", "") for c in host.containers).lower()
    notes = ["1. Network connectivity, DNS, firewall policy, and storage mounts."]
    if "step-ca" in names or host.services.get("step-ca", {}).get("service_installed"):
        notes.append("2. Step CA and its restored key/database storage, then trust-chain distribution.")
    if "caddy" in names or host.system.get("reverse_proxy", {}).get("caddy", {}).get("present"):
        notes.append("3. Caddy after DNS and certificate infrastructure are reachable.")
    notes.append("4. Databases and stateful services, then dependent applications and reverse proxies.")
    return "\n".join(notes)
