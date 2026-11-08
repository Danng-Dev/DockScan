#!/usr/bin/env bash
# DockScan Linux installer. Run from a reviewed source checkout; it never curls code.
set -euo pipefail

PREFIX=/opt/dockscan
BIN_DIR=/usr/local/bin
SERVICE_USER=dockscan
INSTALL_SERVICE=0
SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: sudo ./scripts/install-linux.sh [options]

  --prefix PATH       Install virtualenv under PATH (default: /opt/dockscan)
  --bin-dir PATH      Install dockscan launcher in PATH (default: /usr/local/bin)
  --source PATH       Reviewed DockScan source directory (default: script parent)
  --service            Install the dockscan-agent@.service systemd template
  --user NAME          Service account name (default: dockscan)
  --help               Show this help

This installer uses only the checked-out local source. It does not download code,
create agents, open firewall ports, or enable a service.
EOF
}

while (($#)); do
  case "$1" in
    --prefix) PREFIX=$2; shift 2 ;;
    --bin-dir) BIN_DIR=$2; shift 2 ;;
    --source) SOURCE_DIR=$(realpath "$2"); shift 2 ;;
    --service) INSTALL_SERVICE=1; shift ;;
    --user) SERVICE_USER=$2; shift 2 ;;
    --help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Run as root (for example: sudo $0)." >&2; exit 1; }
[[ -f "$SOURCE_DIR/pyproject.toml" && -d "$SOURCE_DIR/dockscan" ]] || { echo "--source is not a DockScan source directory." >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required. Install python3 and python3-venv first." >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ is required"'

install -d -m 0755 "$PREFIX" "$BIN_DIR"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/python" -m pip install --no-deps --upgrade "$SOURCE_DIR"
install -m 0755 "$PREFIX/venv/bin/dockscan" "$BIN_DIR/dockscan"
install -d -m 0700 /etc/dockscan /var/lib/dockscan /var/log/dockscan

if (( INSTALL_SERVICE )); then
  id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home /var/lib/dockscan --shell /usr/sbin/nologin "$SERVICE_USER"
  install -o "$SERVICE_USER" -g "$SERVICE_USER" -d -m 0700 /var/lib/dockscan /var/log/dockscan
  install -m 0644 "$SOURCE_DIR/scripts/dockscan-agent@.service" /etc/systemd/system/dockscan-agent@.service
  systemctl daemon-reload
  echo "Installed systemd template. Create /etc/dockscan/agents/<name>.env (mode 0600), then review and enable it manually."
fi

cat <<EOF
DockScan installed successfully.

  Version:  $($BIN_DIR/dockscan --help >/dev/null && "$PREFIX/venv/bin/python" -c 'from dockscan import __version__; print(__version__)')
  Command:  $BIN_DIR/dockscan
  Config:   /etc/dockscan (mode 0700)

Next: read docs/INSTALL_LINUX.md and run 'dockscan --help'.
EOF
