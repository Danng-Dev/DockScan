"""Stable v1 plugin contract. Plugins describe work; the core enforces policy."""
from dataclasses import dataclass, field
from typing import Protocol, Any

PLUGIN_API_VERSION = "1.0"


@dataclass(frozen=True)
class PluginManifest:
    identifier: str
    version: str
    api_version: str
    capabilities: tuple[str, ...]
    optional: bool = True


class RecoveryPlugin(Protocol):
    manifest: PluginManifest
    def discover(self, context: dict[str, Any]) -> dict[str, Any]: ...
    def collect_artifacts(self, context: dict[str, Any]) -> list[dict[str, Any]]: ...
    def preflight(self, task: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]: ...
    def tasks(self, context: dict[str, Any]) -> list[dict[str, Any]]: ...
    def execute(self, task: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]: ...
    def verify(self, task: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]: ...
    def rollback(self, task: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]: ...
    def required_secrets(self, context: dict[str, Any]) -> list[dict[str, Any]]: ...
    def migrate(self, artifact: dict[str, Any], from_version: str) -> dict[str, Any]: ...


def validate_manifest(value: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in ("identifier", "version", "api_version", "capabilities") if field not in value]
    compatible = value.get("api_version") == PLUGIN_API_VERSION
    return {"valid": not missing and compatible, "missing": missing, "compatible": compatible, "warning": None if compatible else f"requires plugin API {PLUGIN_API_VERSION}"}
