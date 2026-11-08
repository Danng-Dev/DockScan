import json
import subprocess

from .models import HostInventory


def collect_remote(name: str, target: str, command: str, services: set[str], include_secrets: bool) -> HostInventory:
    args = ["ssh", target, command, "agent", "--json", "--name", name]
    if services:
        args.extend(["--services", ",".join(sorted(services))])
    if include_secrets:
        args.append("--include-secrets")
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if result.returncode:
        return HostInventory(name=name, hostname=target, os_release={}, kernel="", docker_version=None,
                             warnings=[f"Remote agent failed: {result.stderr.strip() or result.stdout.strip()}"])
    try:
        return HostInventory(**json.loads(result.stdout))
    except (json.JSONDecodeError, TypeError) as exc:
        return HostInventory(name=name, hostname=target, os_release={}, kernel="", docker_version=None,
                             warnings=[f"Remote agent returned invalid JSON: {exc}"])
