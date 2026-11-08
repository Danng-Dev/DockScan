#!/usr/bin/env bash
# One-command installer for a reviewed DockScan source checkout.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec bash "$ROOT_DIR/scripts/install-linux.sh" --source "$ROOT_DIR" "$@"
