"""Audit-first recovery session records and resumable plan checkpoints."""
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .blueprint import recovery_plan, inspect_blueprint, plan_hash
from .verification import verify_task
from .security import private_directory, private_file
from .trust import trusted


def run_session(blueprint: Path, session_dir: Path, mode: str = "audit", approve: bool = False, trusted_fingerprint: str | None = None, trust_store: Path | None = None, approve_plan_hash: str | None = None) -> dict:
    plan = recovery_plan(blueprint)
    if not plan["valid"]:
        raise ValueError("cannot start a session from an invalid plan")
    if mode == "recovery" and not approve:
        raise PermissionError("recovery mode requires --approve; use audit or dry-run to preview")
    if mode == "recovery" and (not trust_store or not trusted_fingerprint or not trusted(trust_store, trusted_fingerprint)):
        raise PermissionError("recovery mode requires a currently trusted signer fingerprint")
    signature = inspect_blueprint(blueprint)["manifest"].get("signature", {})
    current_plan_hash = plan_hash(blueprint)
    if mode == "recovery" and (signature.get("plan_hash") != current_plan_hash or approve_plan_hash != current_plan_hash):
        raise PermissionError("recovery mode requires a second approval for the current signed plan hash")
    if mode == "recovery":
        raise NotImplementedError("recovery execution is not enabled until each task has an approved agent capability implementation")
    manifest = inspect_blueprint(blueprint)["manifest"]
    tasks = []
    for task in plan["tasks"]:
        check = verify_task(task) if mode == "audit" else {"status": "not-run", "method": "dry-run"}
        tasks.append({"id": task["id"], "status": "audited" if mode == "audit" else "planned", "verification": task["verification"], "verification_result": check, "checkpoint": check["status"] in {"passed", "unknown"}, "flagged_os": bool(check.get("flagged_os"))})
    session = {"session_id": "session-" + uuid4().hex, "blueprint_id": manifest["blueprint_id"], "blueprint": str(blueprint), "started_at": datetime.now(timezone.utc).isoformat(), "mode": mode, "status": "completed", "tasks": tasks, "secrets_required": [item.get("id") for item in _secrets(blueprint)], "warnings": ["No commands were executed."]}
    private_directory(session_dir)
    path = session_dir / f"{session['session_id']}.json"
    path.write_text(json.dumps(session, indent=2) + "\n")
    private_file(path)
    markdown = session_dir / f"{session['session_id']}.md"
    markdown.write_text("# DockScan recovery session\n\n" + f"- Session: `{session['session_id']}`\n- Mode: `{mode}`\n- Tasks: {len(session['tasks'])}\n- Status: {session['status']}\n- Commands executed: no\n")
    private_file(markdown)
    return session


def resume_session(session_file: Path, retry: list[str] | None = None) -> dict:
    """Reopen a session without rerunning completed checkpoints; retry is metadata-only in audit mode."""
    session = json.loads(session_file.read_text())
    retry = set(retry or [])
    for task in session.get("tasks", []):
        if task["id"] in retry:
            task["status"] = "planned"
            task["checkpoint"] = False
            task["retry_requested_at"] = datetime.now(timezone.utc).isoformat()
    session["resumed_at"] = datetime.now(timezone.utc).isoformat()
    session["status"] = "resumed-audit"
    session_file.write_text(json.dumps(session, indent=2) + "\n")
    private_file(session_file)
    return session


def _secrets(blueprint: Path) -> list[dict]:
    from zipfile import ZipFile
    with ZipFile(blueprint) as archive:
        return json.loads(archive.read("requirements/secrets.json")).get("secrets", [])
