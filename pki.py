"""CA-provider abstractions. TLS consumes standard PEM files, so new CAs plug in here."""
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess


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
