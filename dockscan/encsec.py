"""`.encsec`: an age-encrypted JSON secret envelope for recovery automation."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import shutil
import subprocess

MAGIC = "encsec"
VERSION = "1.0.0"


def _age() -> str:
    executable = shutil.which("age")
    if not executable:
        raise RuntimeError("age CLI not found. Install age before creating or opening .encsec files.")
    return executable


def validate_plaintext(path: Path) -> bytes:
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("secret input must be a valid JSON document") from exc
    if not isinstance(payload, dict):
        raise ValueError("secret input must be a JSON object")
    # Format marker is inside the encryption boundary, so no secret metadata leaks.
    return json.dumps({"format": MAGIC, "version": VERSION, "secrets": payload}, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def encrypt(source: Path, output: Path, recipients: list[str]) -> None:
    if not recipients:
        raise ValueError("at least one age recipient is required")
    payload = validate_plaintext(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ValueError("refusing to write encrypted output through a symlink")
    handle = tempfile.NamedTemporaryFile(dir=output.parent, prefix=".encsec-", delete=False)
    temporary = Path(handle.name)
    handle.close()
    command = [_age(), "--encrypt", "--output", str(temporary)]
    for recipient in recipients:
        command.extend(["--recipient", recipient])
    try:
        result = subprocess.run(command, input=payload, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError("age encryption failed: " + result.stderr.decode(errors="replace").strip())
        if os.name != "nt":
            temporary.chmod(0o600)
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()


def decrypt(source: Path, output: Path, identities: list[Path]) -> None:
    if not identities:
        raise ValueError("at least one age identity file is required")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ValueError("refusing to write decrypted output through a symlink")
    temporary = output.with_name(output.name + ".partial")
    if temporary.exists():
        temporary.unlink()
    command = [_age(), "--decrypt", "--output", str(temporary)]
    for identity in identities:
        command.extend(["--identity", str(identity)])
    command.append(str(source))
    result = subprocess.run(command, capture_output=True, check=False)
    try:
        if result.returncode:
            raise RuntimeError("age decryption failed: " + result.stderr.decode(errors="replace").strip())
        # Verify the decrypted payload is our format without emitting it.
        try:
            payload = json.loads(temporary.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("decrypted file is not a valid encsec payload") from exc
        if payload.get("format") != MAGIC or payload.get("version") != VERSION:
            raise RuntimeError("decrypted file is not an encsec payload")
        if os.name != "nt":
            temporary.chmod(0o600)
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()


def inspect(path: Path) -> dict:
    data = path.read_bytes()
    # Age files always begin with this marker; do not attempt decryption for inspection.
    if not data.startswith(b"age-encryption.org/"):
        raise ValueError("not an age-encrypted .encsec file")
    return {"format": MAGIC, "version": VERSION, "encrypted": True, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
