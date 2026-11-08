"""Small security primitives shared by local files and line-based protocols."""
import os
from pathlib import Path

MAX_PROTOCOL_BYTES = 1_048_576


def read_json_line(reader):
    import json
    line = reader.readline(MAX_PROTOCOL_BYTES + 1)
    if not line or len(line) > MAX_PROTOCOL_BYTES:
        raise ValueError("request is empty or exceeds the 1 MiB protocol limit")
    value = json.loads(line.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("request must be a JSON object")
    return value


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)


def private_file(path: Path) -> None:
    if os.name != "nt" and path.exists():
        path.chmod(0o600)


def redacted_text(value: str) -> str:
    """Keep diagnostics useful without returning URLs with userinfo or obvious tokens."""
    import re
    value = re.sub(r"(://)[^\s/@:]+:[^\s/@]+@", r"\1__REDACTED__@", value)
    return re.sub(r"(?i)(token|password|secret|api[_-]?key)=([^\s&]+)", r"\1=__REDACTED__", value)
