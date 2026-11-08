from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class HostInventory:
    name: str
    hostname: str
    os_release: dict[str, str]
    kernel: str
    docker_version: str | None
    containers: list[dict[str, Any]] = field(default_factory=list)
    networks: list[dict[str, Any]] = field(default_factory=list)
    volumes: list[dict[str, Any]] = field(default_factory=list)
    services: dict[str, Any] = field(default_factory=dict)
    system: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
