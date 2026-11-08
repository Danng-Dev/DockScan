"""Local trusted-signer store; private keys never enter DockScan state."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .security import private_directory, private_file


def fingerprint(public_key: Path) -> str:
    if not public_key.is_file():
        raise ValueError(f"public key not found: {public_key}")
    return "sha256:" + hashlib.sha256(public_key.read_bytes()).hexdigest()


def load(store: Path) -> dict:
    if not store.exists():
        return {"version": 1, "signers": []}
    return json.loads(store.read_text())


def save(store: Path, value: dict) -> None:
    private_directory(store.parent)
    store.write_text(json.dumps(value, indent=2) + "\n")
    private_file(store)


def add(store: Path, public_key: Path, signer: str, expires_at: str | None = None, replaces: str | None = None) -> dict:
    data = load(store)
    item = {"fingerprint": fingerprint(public_key), "signer": signer, "public_key": str(public_key.resolve()), "expires_at": expires_at, "revoked_at": None, "replaces": replaces, "added_at": datetime.now(timezone.utc).isoformat()}
    data["signers"] = [x for x in data["signers"] if x["fingerprint"] != item["fingerprint"]] + [item]
    save(store, data)
    return item


def revoke(store: Path, key_fingerprint: str) -> None:
    data = load(store)
    for item in data["signers"]:
        if item["fingerprint"] == key_fingerprint:
            item["revoked_at"] = datetime.now(timezone.utc).isoformat()
            save(store, data)
            return
    raise ValueError("trusted signer not found")


def trusted(store: Path, key_fingerprint: str) -> bool:
    for item in load(store)["signers"]:
        if item["fingerprint"] == key_fingerprint and not item.get("revoked_at"):
            expiry = item.get("expires_at")
            if not expiry or datetime.fromisoformat(expiry.replace("Z", "+00:00")) > datetime.now(timezone.utc):
                return True
    return False
