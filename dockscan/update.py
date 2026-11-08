"""Explicit, pinned self-update workflow. Never updates automatically."""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def _git() -> str:
    executable = shutil.which("git")
    if not executable:
        raise RuntimeError("git is required for updates")
    return executable


def check(repository: str) -> list[str]:
    if not repository.startswith("https://"):
        raise ValueError("only HTTPS repository URLs are accepted")
    result = subprocess.run([_git(), "ls-remote", "--tags", "--refs", repository], text=True, capture_output=True, check=True)
    tags = []
    for line in result.stdout.splitlines():
        ref = line.split()[-1] if line.split() else ""
        if ref.startswith("refs/tags/v") and re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", ref.removeprefix("refs/tags/")):
            tags.append(ref.removeprefix("refs/tags/"))
    return sorted(tags, key=lambda item: tuple(int(part) for part in re.match(r"v(\d+)\.(\d+)\.(\d+)", item).groups()))


def apply(repository: str, ref: str, verify_tag: bool = False, installer_args: list[str] | None = None) -> str:
    if not repository.startswith("https://"):
        raise ValueError("only HTTPS repository URLs are accepted")
    if not ref or ref in {"main", "master", "HEAD"}:
        raise ValueError("updates require an immutable release tag or commit, not a floating branch")
    args = installer_args or []
    with tempfile.TemporaryDirectory(prefix="dockscan-update-") as directory:
        root = Path(directory)
        subprocess.run([_git(), "-C", str(root), "init", "-q"], check=True)
        subprocess.run([_git(), "-C", str(root), "remote", "add", "origin", repository], check=True)
        subprocess.run([_git(), "-C", str(root), "fetch", "-q", "--depth=1", "origin", ref], check=True)
        subprocess.run([_git(), "-C", str(root), "checkout", "-q", "--detach", "FETCH_HEAD"], check=True)
        if verify_tag:
            subprocess.run([_git(), "-C", str(root), "fetch", "-q", "--tags", "--depth=1", "origin", f"refs/tags/{ref}:refs/tags/{ref}"], check=True)
            subprocess.run([_git(), "-C", str(root), "verify-tag", ref], check=True)
        commit = subprocess.run([_git(), "-C", str(root), "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
        subprocess.run(["bash", str(root / "install.sh"), *args], check=True)
        return commit
