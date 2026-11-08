"""Copy-on-write .dsrcvr migrations; the source archive is never modified."""
import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from .blueprint import FORMAT, FORMAT_VERSION, _validated_archive, canonical
from .security import private_file


def compatibility(version: str) -> dict:
    major = version.split(".", 1)[0]
    return {"supported": major == "1" or version == "0.1.0", "migration_available": version == "0.1.0", "current": FORMAT_VERSION}


def preview(path: Path) -> dict:
    with _validated_archive(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    status = compatibility(manifest.get("format_version", ""))
    return {"source": str(path), "source_version": manifest.get("format_version"), "target_version": FORMAT_VERSION, "would_modify_original": False, "changes": ["add recovery policy" if "policy" not in manifest else "normalize current schema", "recompute checksums", "remove stale signature; re-sign migrated copy"], **status}


def migrate(source: Path, output: Path) -> Path:
    details = preview(source)
    if not details["supported"]:
        raise ValueError("unsupported blueprint version")
    if output.resolve() == source.resolve():
        raise ValueError("migration requires a new output path; original blueprints are immutable")
    with _validated_archive(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist() if name != "manifest.json" and not name.startswith("signatures/")}
        manifest = json.loads(archive.read("manifest.json"))
    manifest["format"] = FORMAT
    manifest["format_version"] = FORMAT_VERSION
    manifest.setdefault("policy", {"allowed_integrations": [], "allowed_agents": [], "allowed_destinations": [], "privileged_task_types": [], "custom_scripts": "signed-and-separately-approved"})
    manifest["checksums"] = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}
    manifest["signature"] = {"status": "unsigned", "algorithm": None, "migration_notice": "Re-sign this migrated copy before recovery."}
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", canonical(manifest))
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    private_file(output)
    return output
