"""Redacted recovery evidence bundles for audits and future recovery runs."""
import hashlib
import json
import base64
import shutil
import subprocess
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from .blueprint import inspect_blueprint, plan_hash, canonical
from .security import private_file, redacted_text


def _redact(value):
    if isinstance(value, dict):
        return {key: "__REDACTED__" if any(x in key.lower() for x in ("secret", "token", "password", "credential", "key")) else _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return redacted_text(value) if isinstance(value, str) else value


def create(blueprint: Path, session: Path, output: Path, private_key: Path | None = None, signer: str | None = None) -> Path:
    manifest = inspect_blueprint(blueprint)["manifest"]
    session_data = _redact(json.loads(session.read_text()))
    evidence = {"blueprint_id": manifest["blueprint_id"], "blueprint_sha256": hashlib.sha256(blueprint.read_bytes()).hexdigest(), "plan_hash": plan_hash(blueprint), "signature": manifest.get("signature"), "session": session_data, "approvals": {"plan_hash": manifest.get("signature", {}).get("plan_hash"), "recovery_approved": False}, "redacted": True}
    markdown = "# DockScan recovery evidence\n\n" + f"- Blueprint: `{evidence['blueprint_id']}`\n- Plan hash: `{evidence['plan_hash']}`\n- Session: `{session_data.get('session_id')}`\n- Mode: `{session_data.get('mode')}`\n- Status: `{session_data.get('status')}`\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    evidence_bytes = canonical(evidence)
    signature = None
    if private_key:
        openssl = shutil.which("openssl")
        if not openssl:
            raise RuntimeError("OpenSSL CLI is required to sign evidence")
        result = subprocess.run([openssl, "dgst", "-sha256", "-sign", str(private_key)], input=evidence_bytes, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError("evidence signing failed")
        signature = {"algorithm": "openssl-dgst-sha256", "signer": signer, "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(), "signature_base64": base64.b64encode(result.stdout).decode()}
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("evidence.json", evidence_bytes)
        archive.writestr("evidence.md", markdown)
        if signature:
            archive.writestr("signature.json", canonical(signature))
    private_file(output)
    return output
