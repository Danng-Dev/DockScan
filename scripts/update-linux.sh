#!/usr/bin/env bash
# Manual updater for installations that cannot use `dockscan update`.
set -euo pipefail

REPOSITORY="${DOCKSCAN_REPOSITORY:-https://github.com/Danng-Dev/DockScan.git}"
REF="${DOCKSCAN_REF:-}"
VERIFY_TAG=0

usage() {
  cat <<'EOF'
Usage: sudo bash update-linux.sh --ref vX.Y.Z [--repository HTTPS_URL] [--verify-tag]

Updates from an immutable release tag/commit using a temporary Git checkout.
Never use main, master, or HEAD as an update ref.
EOF
}

while (($#)); do
  case "$1" in
    --repository) REPOSITORY=${2:?}; shift 2 ;;
    --ref) REF=${2:?}; shift 2 ;;
    --verify-tag) VERIFY_TAG=1; shift ;;
    --help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$REF" && "$REF" != main && "$REF" != master && "$REF" != HEAD ]] || { echo "An immutable --ref is required." >&2; exit 2; }
[[ "$REPOSITORY" =~ ^https:// ]] || { echo "Only HTTPS repositories are allowed." >&2; exit 2; }
command -v git >/dev/null || { echo "git is required." >&2; exit 1; }
WORK_DIR=$(mktemp -d -t dockscan-update.XXXXXXXX)
trap 'rm -rf -- "$WORK_DIR"' EXIT INT TERM
git -C "$WORK_DIR" init -q
git -C "$WORK_DIR" remote add origin "$REPOSITORY"
git -C "$WORK_DIR" fetch -q --depth=1 origin "$REF"
git -C "$WORK_DIR" checkout -q --detach FETCH_HEAD
if (( VERIFY_TAG )); then
  git -C "$WORK_DIR" fetch -q --tags --depth=1 origin "refs/tags/$REF:refs/tags/$REF"
  git -C "$WORK_DIR" verify-tag "$REF"
fi
echo "Updating to $(git -C "$WORK_DIR" rev-parse HEAD)"
exec bash "$WORK_DIR/install.sh"
