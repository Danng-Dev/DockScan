"""CA-provider abstractions. TLS consumes standard PEM files, so new CAs plug in here."""
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
from datetime import datetime, timezone
import re


@dataclass(frozen=True)
class StepCAProvider:
    """Step CA enrollment guidance; certificates are deliberately issued outside DockScan."""
    ca_url: str
    fingerprint: str

    def bootstrap_command(self) -> str:
        return f"step ca bootstrap --ca-url {self.ca_url} --fingerprint {self.fingerprint}"

    def certificate_command(self, name: str, cert_path: str, key_path: str) -> str:
        return f"step ca certificate {name} {cert_path} {key_path}"


def subject_common_name(certificate: dict | None) -> str | None:
    for rdn in (certificate or {}).get("subject", []):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def enroll_step_ca(ca_url: str, fingerprint: str, name: str, cert: Path, key: Path, sans: list[str], token_file: Path | None = None, dry_run: bool = False) -> list[list[str]]:
    """Bootstrap Step trust and issue a local TLS identity certificate.

    The Step CLI is responsible for the CA's chosen provisioner/auth flow.
    """
    if not shutil.which("step"):
        raise RuntimeError("Step CLI not found. Install smallstep-cli before enrolling.")
    commands = [["step", "ca", "bootstrap", "--ca-url", ca_url, "--fingerprint", fingerprint]]
    issue = ["step", "ca", "certificate", name, str(cert), str(key)]
    for san in sans:
        issue.extend(["--san", san])
    if token_file:
        raise ValueError("--token-file is not supported because Step CLI tokens would be exposed in process arguments; use a provisioner credential flow instead")
    commands.append(issue)
    if dry_run:
        return commands
    cert.parent.mkdir(parents=True, exist_ok=True)
    key.parent.mkdir(parents=True, exist_ok=True)
    for command in commands:
        subprocess.run(command, check=True)
    if os.name != "nt":
        key.chmod(0o600)
    return commands


def create_jwk_provisioner(name: str, ca_config: Path, password_file: Path, service: str, apply: bool, confirm: str | None, dry_run: bool = False) -> dict:
    """Create a password-protected JWK provisioner through the supported Step CLI.

    This intentionally does not hand-edit ca.json. `--apply` and a matching
    confirmation are required because the operation changes CA issuance policy.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}", name):
        raise ValueError("provisioner name may contain only letters, digits, '.', '_', '@', and '-'")
    command = ["step", "ca", "provisioner", "add", name, "--type", "JWK", "--create", "--password-file", str(password_file), "--ca-config", str(ca_config)]
    preview = {"command": ["step", "ca", "provisioner", "add", name, "--type", "JWK", "--create", "--password-file", "__GENERATED_PRIVATE_FILE__", "--ca-config", str(ca_config)], "service": service, "ca_config": str(ca_config), "password_file": str(password_file), "will_restart": True}
    if dry_run:
        return {"applied": False, "dry_run": True, **preview}
    if not ca_config.is_file():
        raise ValueError(f"CA configuration not found: {ca_config}")
    if not shutil.which("step") or not shutil.which("openssl"):
        raise RuntimeError("both step and openssl CLIs are required")
    if not apply or confirm != name:
        raise PermissionError("CA changes require --apply and --confirm matching the provisioner name")
    password_file.parent.mkdir(parents=True, exist_ok=True)
    if password_file.exists():
        raise FileExistsError("refusing to overwrite existing provisioner password file")
    backup = ca_config.with_name(ca_config.name + ".dockscan-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".bak")
    shutil.copy2(ca_config, backup)
    try:
        secret = subprocess.run(["openssl", "rand", "-base64", "48"], capture_output=True, text=True, check=True).stdout.strip()
        password_file.write_text(secret + "\n")
        if os.name != "nt":
            password_file.chmod(0o600)
        subprocess.run(command, check=True)
        subprocess.run(["systemctl", "restart", service], check=True)
    except Exception:
        if password_file.exists():
            password_file.unlink()
        shutil.copy2(backup, ca_config)
        # Best effort: restore the previous CA configuration to service after a failed restart.
        subprocess.run(["systemctl", "restart", service], check=False, capture_output=True)
        raise
    return {"applied": True, "backup": str(backup), **preview}
